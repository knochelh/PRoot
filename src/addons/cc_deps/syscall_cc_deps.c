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
#include <string.h>
#include <unistd.h> /* readlink (3p) */
#include <regex.h> /* regcomp, regexec, regfree (3p) */
#include <libgen.h> /* basename (3p) */
#include <limits.h> /* PATH_MAX */
#include <assert.h> /* assert(3), */

#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "tracee/array.h"
#include "tracee/abi.h"
#include "syscall/syscall.h"
#include "execve/ldso.h"
#include "addons/syscall_addons.h"
#include "extension/extension.h"

#warning "cc_deps ADDON is deprecated. Pleasde remove from build."

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


/**
 * Format execve.
 */
static void format_execve(const char *path, Array *argv, Array *envp, const char *cwd, int index)
{
	char *arg;
	const char *sep;
	int status;
	int i;

	if (path != NULL) {
		OUTPUT("\"%s\"", path);
	}
	OUTPUT(": ");
	if (argv != NULL) {
		sep = "";

		for (i = index; i < argv->length; i++) {
			status = read_item_string(argv, i, &arg);
			if (status < 0 || arg == NULL)
				return;

			OUTPUT("%s\"%s\"", sep, arg);
			sep = ", ";
		}
	}
	OUTPUT(": ");
	if (envp != NULL) {
		sep = "";

		for (i = 0; i < envp->length; i++) {
			status = read_item_string(envp, i, &arg);
			if (status < 0 || arg == NULL)
				return;

			OUTPUT("%s\"%s\"", sep, arg);
			sep = ", ";
		}
		sep = ": ";
	}
	OUTPUT(": ");
	if (cwd != NULL) {
		OUTPUT("\"%s\"", cwd);
	}
	OUTPUT("\n");
}


/**
 * Process execve.
 */
static int process_execve(Tracee *tracee)
{
	char u_path[PATH_MAX];
	char *prog_path, *argv0;
	Array *argv = NULL;
	int status;
	int index = 0;

	status = get_sysarg_path(tracee, u_path, SYSARG_1);
	if (status < 0)
		goto end;

	status = fetch_array(tracee, &argv, SYSARG_2, 0);
	if (status < 0)
		goto end;

	if (verbose) {
		OUTPUT("VERB: execve: ");
		format_execve(u_path, argv, NULL, tracee->fs->cwd, 0);
	}
	/* Check whether we are executing the compiler driver.
	   Compares with argv0 (not the actual path, as some driver installation may be symlinks)
	   and check if basename argv0 matches driver_re.
	*/
	if (tracee->forced_elf_interpreter) {
		index= 1;
		status = read_item_string(argv, index, &prog_path);
		if (status < 0 || prog_path == NULL)
			goto end;
	} else {
		prog_path = u_path;
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

		int index2 = find_item(envp, "PROOT_ADDON_CC_DEPS_ACTIVE");
		if (index2 < 0) {
			status = index2;
			goto end;
		}

		/* PROOT_ADDON_CC_DEPS_ACTIVE not found.  */
		if (index2 == envp->length) {
			OUTPUT("CC_DEPS: ");
			format_execve(prog_path, argv, NULL, tracee->fs->cwd, index);

			/* Allocate a new entry at the end of envp[],
			 * rigth before the NULL terminator.  */
			index2 = envp->length - 1;
			status = resize_array(envp, index2, 1);
			if (status < 0)
				goto end;

			status = write_item(envp, index2, "PROOT_ADDON_CC_DEPS_ACTIVE=1");
			if (status < 0)
				goto end;
		}

		status = push_array(envp, SYSARG_3);
		if (status < 0)
			return status;
	}

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
	int status = 0;

	if (!active) return 0;

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
 * Register the current addon through a constructor function.
 */
static int cc_deps_callback(Extension *extension, ExtensionEvent event,
			intptr_t data1, intptr_t data2);

static struct addon_info addon = { "cc_deps", &cc_deps_callback };

static void __attribute__((constructor)) init(void)
{
	syscall_addons_register(&addon);
}


static int cc_deps_init(void)
{
	active = getenv("PROOT_ADDON_CC_DEPS") != NULL;
	verbose = getenv("PROOT_ADDON_CC_DEPS_VERBOSE") != NULL;
	output = getenv("PROOT_ADDON_CC_DEPS_OUTPUT");
	if (output == NULL || *output == '\0')
		output = ":stderr";
	driver_regexp = getenv("PROOT_ADDON_CC_DEPS_CCRE");
	if (driver_regexp == NULL)
		driver_regexp = "^\\(gcc\\|g++\\|cc\\|c++\\)$";
	if (regcomp(&driver_re, driver_regexp, REG_NOSUB|REG_NEWLINE) != 0) {
		fprintf(stderr, "error: cc_deps addon: error in driver path regexp: %s\n",
			driver_regexp);
		return -1;
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
			perror("error: cc_deps addon output file");
			exit(1);
		}
		setlinebuf(output_file);
	}
	if (verbose) {
		OUTPUT("cc_deps: output file: %s\n", output);
		OUTPUT("cc_deps: driver regexp: %s\n", driver_regexp);
	}

	return 0;
}


static int cc_deps_callback(Extension *extension, ExtensionEvent event,
			intptr_t data1, intptr_t data2)
{
	Tracee *tracee = TRACEE(extension);

	switch (event) {
	case INITIALIZATION:
		return cc_deps_init();

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
}