/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * This file is part of PRoot.
 *
 * Copyright (C) 2010, 2011 STMicroelectronics
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA.
 *
 * Author: Cedric VINCENT (cedric.vincent@st.com)
 *         Christophe Guillon (christophe.guillon@st.com)
 */

/**
 * Generates list of exec'd gcc commands
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h> /* strtok (3p) */
#include <unistd.h> /* readlink (3p) */
#include <regex.h> /* regcomp, regexec, regfree (3p) */
#include <libgen.h> /* basename (3p) */
#include <errno.h> /* ENOMEM */
#include <assert.h>

#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "syscall/syscall.h"
#include "tracee/array.h"
#include "tracee/abi.h"
#include "execve/ldso.h"
#include "addons/syscall_addons.h"
#include "extension/extension.h"

/**
 * Defines OUTPUT macro for all addon outputs.
 */
#define OUTPUT(...) fprintf(output_file, __VA_ARGS__);
#define VERBOSE(...) do { if (verbose) OUTPUT(__VA_ARGS__); } while (0)

/**
 * Local variables, self describing.
 */
static int active;
static int verbose;
static const char *driver_regexp;
static const char *output;
static FILE *output_file;
static regex_t driver_re;
static char **opt_args;
static char *opts;
static char *driver_cmd;

/** 
 * Format args.
 */
static void format_args(Array *argv)
{
	const char *sep;
	char *arg;
	int status;
	int i;

	if (argv != NULL) {
		sep = "";
		for (i = 0; i < argv->length; i++) {
			status = read_item_string(argv, i, &arg);
			if (status < 0 || arg == NULL)
				return;

			OUTPUT("%s\"%s\"", sep, arg);
			sep = ", ";
		}
	}
}

/**
 * Format execve.
 */
static void format_execve(const char *path, Array *argv, Array *envp, const char *cwd)
{
	if (path != NULL) {
		OUTPUT("\"%s\"", path);
	}
	OUTPUT(": ");
	format_args(argv);
	OUTPUT(": ");
	format_args(envp);
	OUTPUT(": ");
	if (cwd != NULL) {
		OUTPUT("\"%s\"", cwd);
	}
	OUTPUT("\n");
}


/**
 * Modify execve by injecting options last in arguments list.
 */
static int modify_execve(Tracee *tracee, const char *path, Array *argv)
{
	int opts_size = 0;
	int status = 0;
	int i = 0;
	int index;

	if (opt_args != NULL) {
		for (opts_size = 0; opt_args[opts_size] != NULL; opts_size++)
			;
		opts_size++;
	}

	if (opts_size <= 1) {
		status = 0;
		goto end;
	}

	if (driver_cmd && !tracee->forced_elf_interpreter) {
		status = set_sysarg_path(tracee, driver_cmd, SYSARG_1);
		if (status < 0) goto end;

		/* Prepend the driver command.  */
		status = resize_array(argv, 0, 1);
		if (status < 0)
			goto end;

		status = write_item(argv, 0, driver_cmd);
		if (status < 0)
			goto end;
	}

	/* Write the new entries at the end of argv[],
	 * rigth before the NULL terminator.  */
	index = argv->length - 1;
	status = resize_array(argv, index, opts_size - 1);
	if (status < 0)
		goto end;

	for (i = 0; i < opts_size - 1; i++) {
		status = write_item(argv, index + i, opt_args[i]);
		if (status < 0)
			goto end;
	}
	status = 0;

end:
	if (status < 0)
		return status;

	return 0;
}


/**
 * Process execve.
 */
static int process_execve(Tracee *tracee)
{
	char u_path[PATH_MAX];
	Array *argv = NULL;
	char *argv0;
	int status = 0;
	int size = 0;
	int index;

	status = get_sysarg_path(tracee, u_path, SYSARG_1);
	if (status < 0)
		goto end;

	status = fetch_array(tracee, &argv, SYSARG_2, 0);
	if (status < 0)
		goto  end;

	if (verbose) {
		OUTPUT("VERB: execve: ");
		format_execve(u_path, argv, NULL, tracee->fs->cwd);
	}
	/* Check whether we are executing the compiler driver.
	   Compares with argv0 (not the actual path, as some driver installation may be symlinks)
	   and check if basename argv0 matches driver_re.
	*/
	if (tracee->forced_elf_interpreter) {
		index = 1;
	} else {
		index = 0;
	}

	status = read_item_string(argv, index, &argv0);
	if (status < 0 || argv0 == NULL)
		goto end;

	if (regexec(&driver_re, basename(argv0), 0, NULL, 0) == 0) {
		Array *envp = NULL;

		status = fetch_array(tracee, &envp, SYSARG_3, 0);
		if (status < 0)
			goto end;

		/* Environment variables should be compared with the "name"
		 * part in the "name=value" string format.  */
		envp->compare_item = (compare_item_t)compare_item_env;

		index = find_item(envp, "PROOT_ADDON_CC_OPTS_ACTIVE");
		if (index < 0) {
			status = index;
			goto end;
		}

		/* PROOT_ADDON_CC_OPTS_ACTIVE not found.  */
		if (index == envp->length) {
			size = modify_execve(tracee, u_path, argv);
			if (size < 0) {
				status = size;
				goto end;
			}

			/* Allocate a new entry at the end of envp[].  */
			index = envp->length - 1;
			resize_array(envp, envp->length - 1, 1);

			status = write_item(envp, index, "PROOT_ADDON_CC_OPTS_ACTIVE=1");
			if (status < 0)
				goto end;
		}

		status = push_array(envp, SYSARG_3);
		if (status < 0)
			return status;
	}

	status = push_array(argv, SYSARG_2);
	if (status < 0)
		return status;

#if 0 // FIXME
	if (verbose) {
		OUTPUT("VERB: changed: ");
		status = get_sysarg_path(tracee, u_path, SYSARG_1);
		if (status < 0)
			goto end;
		status = get_args(tracee, &argv, SYSARG_2);
		if (status < 0)
			goto  end;
		format_execve(u_path, argv, NULL, tracee->fs->cwd);
	}
#endif

 end:
	if (status < 0)
		return status;

	return 0;
}


/**
 * Process syscall entries.
 */
static int addon_enter(Tracee *tracee)
{
	if (!active) return 0;
	int status = 0;

	switch (get_abi(tracee)) {
	case ABI_DEFAULT: {
#include SYSNUM_HEADER
		switch(peek_reg(tracee, CURRENT, SYSARG_NUM)) {
		case PR_execve:
			status = process_execve(tracee);
		}
		break;
	}
#ifdef SYSNUM_HEADER2
	case ABI_2: {
#include SYSNUM_HEADER2
		switch(peek_reg(tracee, CURRENT, SYSARG_NUM)) {
		case PR_execve:
			status = process_execve(tracee);
		}
		break;
	}
#endif
	default:
		assert(0);
	}

	return status;
}

/**
 * Parse options string into an options array.
 * The generated array must be freed with free_opts().
 */
static char **parse_opts(const char *opts)
{
	char *args = strdup(opts);
	char **opt_args = NULL;
	char *arg;
	int opt_num = 0;
	/* First count the number of args. */
	arg = strtok(args, " ");
	while(arg != NULL) {
		opt_num++;
		arg = strtok(NULL, " ");
	}
	/* The opt_args pointer will point to the args, but the
	   element opt_args[-1] contains the dupped
	   string to be freed in free_opts.
	   Thus we allocate the space for opt_num args plus the
	   dupped string element, plus the terminating NULL element.
	*/
	opt_args = (char **)calloc(opt_num+2, sizeof(*opt_args));
	if (opt_args == NULL)
		return NULL;
	opt_args[0] = args;
	opt_args++;
	if (opt_num > 0) {
		/* Fill the opt array. */
		opt_num = 0;
		strcpy(args, opts);
		arg = strtok(args, " ");
		while(arg != NULL) {
			opt_args[opt_num] = arg;
			opt_num++;
			arg = strtok(NULL, " ");
		}
	}
	opt_args[opt_num] = NULL;
	return opt_args;
}

/**
 * Free an option array allocated by parse_opts().
 */
static void free_opts(char **opts)
{
	opts--;
	free(opts[0]);
	free(opts);
}

/**
 * Register the current addon through a constructor function.
 */
static int cc_opts_callback(Extension *extension, ExtensionEvent event,
			intptr_t data1, intptr_t data2);

static struct addon_info addon = { "cc_opts", cc_opts_callback };

static void __attribute__((constructor)) init(void)
{
	syscall_addons_register(&addon);
}

static int cc_opts_init(void)
{
	active = getenv("PROOT_ADDON_CC_OPTS") != NULL;
	verbose = getenv("PROOT_ADDON_CC_OPTS_VERBOSE") != NULL;
	output = getenv("PROOT_ADDON_CC_OPTS_OUTPUT");
	if (output == NULL || *output == '\0')
		output = ":stderr";
	driver_regexp = getenv("PROOT_ADDON_CC_OPTS_CCRE");
	if (driver_regexp == NULL)
		driver_regexp = "^\\(gcc\\|g++\\|cc\\|c++\\)$";
	if (regcomp(&driver_re, driver_regexp, REG_NOSUB|REG_NEWLINE) != 0) {
		fprintf(stderr, "error: cc_opts addon: error in driver path regexp: %s\n",
			driver_regexp);
		return -1;
	}
	opts = getenv("PROOT_ADDON_CC_OPTS_ARGS");
	if (opts != NULL) {
		opt_args = parse_opts(opts);
	}
	driver_cmd = getenv("PROOT_ADDON_CC_OPTS_DRIVER");
	if (driver_cmd) driver_cmd = realpath(driver_cmd, NULL);

	/* Open output file.  */
	if (strcmp(output, ":stdout") == 0)
		output_file = stdout;
	else if (strcmp(output, ":stderr") == 0)
		output_file = stderr;
	else {
		const char *mode = "w";
		if (*output == '+') {
			mode = "a";
			output++;
		}
		output_file = fopen(output, mode);
		if (output_file == NULL) {
			perror("error: cc_opts addon output file");
			return -1;
		}
		setlinebuf(output_file);
	}
	if (verbose) {
		OUTPUT("cc_opts: output file: %s\n", output);
		OUTPUT("cc_opts: driver regexp: %s\n", driver_regexp);
		// FIXME: OUTPUT("cc_opts: options: "); format_args(opt_args); OUTPUT("\n");
	}

	return 0;
}


static int cc_opts_callback(Extension *extension, ExtensionEvent event,
			intptr_t data1, intptr_t data2)
{
	Tracee *tracee = TRACEE(extension);

	switch (event) {
	case INITIALIZATION:
		return cc_opts_init();

	case SYSCALL_ENTER_END:
		return addon_enter(tracee);

	default:
		break;
	}

	return 0;
}

static void __attribute__((destructor)) fini(void)
{
	regfree(&driver_re);
	if (opt_args != NULL)
		free_opts(opt_args);
}
