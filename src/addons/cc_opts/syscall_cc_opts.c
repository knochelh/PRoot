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
#include "tracee/info.h"
#include "tracee/ureg.h"
#include "syscall/syscall.h"
#include "execve/args.h"
#include "addons/syscall_addons.h"

#include SYSNUM_HEADER

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

/**
 * Get current dir for the specified process.
 */
static int get_pid_cwd(int pid, char path[PATH_MAX])
{
	char buffer[256];
	int n;
	snprintf(buffer, sizeof(buffer), "/proc/%d/cwd", pid);
	if ((n = readlink(buffer, path, PATH_MAX-1)) == -1) {
		return -1;
	}
	path[n] = '\0';
	return 0;
}


/** 
 * Format args.
 */
static void format_args(char * const argv[])
{
	const char *sep;
	const char *arg;
	if (argv != NULL) {
		sep = "";
		while ((arg = *argv++) != NULL) {
			OUTPUT("%s\"%s\"", sep, arg);
			sep = ", ";
		}
	}
}

/**
 * Format execve.
 */
static void format_execve(const char *path, char * const argv[], char * const envp[], const char *cwd)
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
static int modify_execve(struct tracee_info *tracee, const char *path, char * const argv[], char * const envp[], const char *cwd)
{
	int argv_size = 0;
	int opts_size = 0;
	int new_argv_size = 0;
	char **new_argv = NULL;
	int status = 0;
	int size = 0;
	int i;

	if (opt_args != NULL) {
		for (opts_size = 0; opt_args[opts_size] != NULL; opts_size++)
			;
		opts_size++;
	}

	if (opts_size <= 1) {
		size = 0;
		status = 0;
		goto end;
	}

	for (argv_size = 0; argv[argv_size] != NULL; argv_size++)
		;
	argv_size++;

	new_argv_size = argv_size + opts_size - 1;
	new_argv = (char **)calloc(new_argv_size, sizeof(*new_argv));
	if (new_argv == NULL) {
		status = -ENOMEM;
		goto end;
	}
	
	for (i = 0; i < new_argv_size; i++) {
		if (i < argv_size - 1) {
			new_argv[i] = argv[i];
		} else {
			new_argv[i] = opt_args[i - (argv_size - 1)];
		}
	}
	size = set_args(tracee, new_argv, SYSARG_2);
	if (size < 0) {
		status = size;
		goto end;
	}
end:
	if (new_argv != NULL)
		free(new_argv);

	if (status < 0)
		return status;

	return size;
}


/**
 * Process execve.
 */
static int process_execve(struct tracee_info *tracee)
{
	char u_path[PATH_MAX];
	char cwd_path[PATH_MAX];
	char **argv = NULL;
	char **envp = NULL;
	int status = 0;
	int size = 0;
	int index;

	status = get_sysarg_path(tracee, u_path, SYSARG_1);
	if (status < 0)
		goto end;
  
	status = get_args(tracee, &argv, SYSARG_2);
	if (status < 0)
		goto  end;

	status = get_args(tracee, &envp, SYSARG_3);
	if (status < 0)
		goto end;

	status = get_pid_cwd(tracee->pid, cwd_path);
	if (status < 0)
		goto end;
  
	if (verbose) {
		OUTPUT("VERB: execve: ");
		format_execve(u_path, argv, NULL, cwd_path);
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

	if (regexec(&driver_re, basename(argv[index]), 0, NULL, 0) == 0) {
		size = modify_execve(tracee, u_path, argv, envp, cwd_path);
		if (size < 0) {
			status = size;
			goto end;
		}
	}
	if (verbose) {
		OUTPUT("VERB: changed: ");
		status = get_args(tracee, &argv, SYSARG_2);
		if (status < 0)
			goto  end;
		format_execve(u_path, argv, NULL, cwd_path);
	}
 end:
	if (status < 0)
		return status;
	return size;
}


/**
 * Process syscall entries.
 */
static int addon_enter(struct tracee_info *tracee)
{
	if (!active) return 0;
	int status = 0;
	switch(tracee->sysnum) {
	case PR_execve:
		status = process_execve(tracee);
	}
	return status;
}


/**
 * Process syscall exits.
 */
static int addon_exit(struct tracee_info *tracee)
{
	if (!active) return 0;
  
	return 0;
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
static struct addon_info addon = { &addon_enter, &addon_exit };

static void __attribute__((constructor)) init(void)
{
	syscall_addons_register(&addon);
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
		exit(1);
	}
	opts = getenv("PROOT_ADDON_CC_OPTS_ARGS");
	if (opts != NULL) {
		opt_args = parse_opts(opts);
	}

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
			exit(1);
		}
		setlinebuf(output_file);
	}
	if (verbose) {
		OUTPUT("cc_opts: output file: %s\n", output);
		OUTPUT("cc_opts: driver regexp: %s\n", driver_regexp);
		OUTPUT("cc_opts: options: "); format_args(opt_args); OUTPUT("\n");
	}
}

static void __attribute__((destructor)) fini(void)
{
	regfree(&driver_re);
	if (opt_args != NULL)
		free_opts(opt_args);
}
