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
#include "tracee/info.h"
#include "tracee/ureg.h"
#include "syscall/syscall.h"
#include "execve/args.h"
#include "addons/syscall_addons.h"

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
 * Format execve.
 */
static void format_execve(const char *path, char * const argv[], char * const envp[], const char *cwd, int index)
{
	const char *arg;
	const char *sep;
	if (path != NULL) {
		OUTPUT("\"%s\"", path);
	}
	OUTPUT(": ");
	if (argv != NULL) {
		sep = "";
		while (index--)
			argv++;
		while ((arg = *argv++) != NULL) {
			OUTPUT("%s\"%s\"", sep, arg);
			sep = ", ";
		}
	}
	OUTPUT(": ");
	if (envp != NULL) {
		sep = "";
		while ((arg = *envp++) != NULL) {
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
static int process_execve(struct tracee_info *tracee)
{
	char u_path[PATH_MAX];
	char cwd_path[PATH_MAX];
	char *prog_path;
	char **argv = NULL;
	char **envp = NULL;
	int status;
	int size = 0;
	int index = 0;
	int envp_changed = 0;
	
	status = get_sysarg_path(tracee, u_path, SYSARG_1);
	if (status < 0)
		goto end;
  
	status = get_args(tracee, &argv, SYSARG_2);
	if (status < 0)
		goto end;

	status = get_args(tracee, &envp, SYSARG_3);
	if (status < 0)
		goto end;

	status = get_pid_cwd(tracee->pid, cwd_path);
	if (status < 0)
		goto end;
  
	if (verbose) {
		OUTPUT("VERB: execve: ");
		format_execve(u_path, argv, NULL, cwd_path, 0);
	}
	/* Check whether we are executing the compiler driver.
	   Compares with argv0 (not the actual path, as some driver installation may be symlinks)
	   and check if basename argv0 matches driver_re.
	*/
	if (tracee->forced_elf_interpreter) {
		index= 1;
		prog_path = argv[index];
	} else {
		prog_path = u_path;
	}

	if (regexec(&driver_re, basename(argv[index]), 0, NULL, 0) == 0) {
		if (get_env_entry(envp, "PROOT_ADDON_CC_DEPS_ACTIVE") == NULL) {
			OUTPUT("CC_DEPS: ");
			format_execve(prog_path, argv, NULL, cwd_path, index);
			status = new_env_entry(&envp, "PROOT_ADDON_CC_DEPS_ACTIVE", "1");
			if (status < 0)
				goto end;
			envp_changed = 1;
		}
	}
	if (envp_changed) {
		size = set_args(tracee, envp, SYSARG_3);
		if (size < 0) {
			status = size;
			goto end;
		}
	}

 end:
	free_args(argv);
	free_args(envp);
	
	if (status < 0)
		return status;

	return size;
}


/**
 * Process syscall entries.
 */
static int addon_enter(struct tracee_info *tracee)
{
	int status = 0;

	if (!active) return 0;

	if (tracee->uregs == uregs) {
#include SYSNUM_HEADER
		switch(tracee->sysnum) {
		case PR_execve:
			status = process_execve(tracee);
		}
	}
#ifdef SYSNUM_HEADER2
	else if (tracee->uregs == uregs2) {
#include SYSNUM_HEADER2
		switch(tracee->sysnum) {
		case PR_execve:
			status = process_execve(tracee);
		}
	}
#endif
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
 * Register the current addon through a constructor function.
 */
static struct addon_info addon = { &addon_enter, &addon_exit };

static void __attribute__((constructor)) init(void)
{
	syscall_addons_register(&addon);
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
		exit(1);
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
}

static void __attribute__((destructor)) fini(void)
{
	regfree(&driver_re);
}
