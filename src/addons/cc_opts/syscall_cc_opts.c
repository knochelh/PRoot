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
#define OUTPUT(...) fprintf(config->output_file, __VA_ARGS__);
#define VERBOSE(...) do { if (config->verbose) OUTPUT(__VA_ARGS__); } while (0)

/*
 * Configuration local to extension.
 */
typedef struct cc_opts_config {
	struct cc_opts_config *parent;
	int active;
	int setup;
	int verbose;
	const char *driver_regexp;
	const char *output;
	FILE *output_file;
	regex_t driver_re;
	const char * const *opt_args;
	const char *opts;
	const char *driver_cmd;
	const char *driver_opts;
} cc_opts_config_t;


/*
 * Forward declarations.
 */
static int modify_execve(cc_opts_config_t *config, Tracee *tracee, const char *path, Array *argv);
static int process_execve(Extension *extension, cc_opts_config_t *config, Tracee *tracee);
static int cc_opts_setup(Extension *extension, cc_opts_config_t *config, Array *envp);
static int cc_opts_enter(Extension *extension);
static int cc_opts_init(Extension *extension);
static int cc_opts_fini(Extension *extension);

static char **parse_opts(Extension *extension, const char *opts);
static int envp_getenv(Array *envp, const char *key, char **value);

static int cc_opts_callback(Extension *extension, ExtensionEvent event,
			    intptr_t data1, intptr_t data2);

/** 
 * Format args.
 */
static void format_args(cc_opts_config_t *config, Array *argv)
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
static void format_execve(cc_opts_config_t *config, const char *path, Array *argv, Array *envp, const char *cwd)
{
	if (path != NULL) {
		OUTPUT("\"%s\"", path);
	}
	OUTPUT(": ");
	format_args(config, argv);
	OUTPUT(": ");
	format_args(config, envp);
	OUTPUT(": ");
	if (cwd != NULL) {
		OUTPUT("\"%s\"", cwd);
	}
	OUTPUT("\n");
}


/**
 * Modify execve by injecting options last in arguments list.
 */
static int modify_execve(cc_opts_config_t *config, Tracee *tracee, const char *path, Array *argv)
{
	int opts_size = 0;
	int status = 0;
	int i = 0;
	int index;

	if (config->opt_args != NULL) {
		for (opts_size = 0; config->opt_args[opts_size] != NULL; opts_size++)
			;
		opts_size++;
	}

	if (opts_size <= 1) {
		status = 0;
		goto end;
	}

	if (config->driver_cmd) {
		status = set_sysarg_path(tracee, (char *)config->driver_cmd, SYSARG_1);
		if (status < 0) goto end;

		/* Prepend the driver command.  */
		status = resize_array(argv, 0, 1);
		if (status < 0)
			goto end;

		status = write_item(argv, 0, config->driver_cmd);
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
		status = write_item(argv, index + i, config->opt_args[i]);
		if (status < 0)
			goto end;
	}
	status = 0;

end:
	if (status < 0)
		return status;

	return 0;
}

extern int translate_n_check(Tracee *, char *, const char *);

/**
 * Process execve.
 */
static int process_execve(Extension *extension, cc_opts_config_t *config, Tracee *tracee)
{
	char u_path[PATH_MAX];
	Array *argv = NULL;
	Array *envp = NULL;
	char *argv0;
	int status = 0;
	int size = 0;
	int changed = 0;

	status = get_sysarg_path(tracee, u_path, SYSARG_1);
	if (status < 0)
		goto end;

	status = fetch_array(tracee, &argv, SYSARG_2, 0);
	if (status < 0)
		goto  end;

	status = fetch_array(tracee, &envp, SYSARG_3, 0);
	if (status < 0)
		goto  end;
	/* Environment variables should be compared with the "name"
	 * part in the "name=value" string format.  */
	envp->compare_item = (compare_item_t)compare_item_env;

	status = cc_opts_setup(extension, config, envp);
	if (status < 0)
		goto end;

	if (!config->active)
		goto end;

	if (config->verbose) {
		OUTPUT("VERB: execve: ");
		format_execve(config, u_path, argv, NULL, tracee->fs->cwd);
	}
	/* Check whether we are executing the compiler driver.
	   Compares with argv0 (not the actual path, as some driver installation may be symlinks)
	   and check if basename argv0 matches driver_re.
	*/

	status = read_item_string(argv, 0, &argv0);
	if (status < 0 || argv0 == NULL)
		goto end;

	if (regexec(&config->driver_re, basename(argv0), 0, NULL, 0) == 0) {
		char path[PATH_MAX];
		status = translate_n_check(tracee, path, u_path);
		if (status < 0) {
			goto end;
		}

		int index = find_item(envp, "PROOT_ADDON_CC_OPTS_ACTIVE");
		if (index < 0) {
			status = index;
			goto end;
		}

		if (index == envp->length) {
			/* PROOT_ADDON_CC_OPTS_ACTIVE not found.  */
			size = modify_execve(config, tracee, u_path, argv);
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
			changed = 1;
		}

		status = push_array(envp, SYSARG_3);
		if (status < 0)
			return status;
	}

	status = push_array(argv, SYSARG_2);
	if (status < 0)
		return status;

	if (config->verbose && changed) {
		OUTPUT("VERB: changed: ");
		format_execve(config, u_path, argv, NULL, tracee->fs->cwd);
	}

 end:
	if (status < 0)
		return status;

	return 0;
}


/**
 * Process syscall entries.
 */
static int cc_opts_enter(Extension *extension)
{
	Tracee *tracee = TRACEE(extension);
	cc_opts_config_t *config = extension->config;
	int status = 0;

	if (get_sysnum(tracee, CURRENT) == PR_execve)
		status = process_execve(extension, config, tracee);

	return status;
}

/**
 * Parse options string into an options array.
 * The generated array is talloc-ed into extension.
 */
static char **parse_opts(Extension *extension, const char *opts)
{
	char *args = talloc_strdup(extension->config, opts);
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
	   element opt_args[-1] contains the dupped string.
	   Thus we allocate the space for opt_num args plus the
	   dupped string element, plus the terminating NULL element.
	*/
	opt_args = talloc_zero_array(extension->config, char *, opt_num + 2);
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


static int envp_getenv(Array *envp, const char *key, char **value)
{
	int index, status;
	char *str_value;

	index = find_item(envp, key);
	if (index < 0)
		return index;
	if (index == envp->length) {
		*value = NULL;
		return 0;
	}
	status = read_item_string(envp, index, &str_value);
	if (status < 0)
		return status;
	*value = &str_value[strlen(key) + 1];
	return 0;
}

static int cc_opts_setup(Extension *extension, cc_opts_config_t *config, Array *envp)
{
	char *env_value;
	int status;

	assert(config != NULL);
	assert(envp != NULL);

	if (config->setup)
		return 0;
	config->setup = 1;

	status = envp_getenv(envp, "PROOT_ADDON_CC_OPTS", &env_value);
	if (status < 0) return status;

	config->active = (env_value != NULL);

	if (!config->active)
		return 0;

	status = envp_getenv(envp, "PROOT_ADDON_CC_OPTS_ACTIVE", &env_value);
	if (status < 0) return status;
	if (env_value != NULL) {
		config->active = 0;
		return 0;
	}

	status = envp_getenv(envp, "PROOT_ADDON_CC_OPTS_VERBOSE", &env_value);
	if (status < 0) return status;
	config->verbose = env_value != NULL;

	status = envp_getenv(envp, "PROOT_ADDON_CC_OPTS_OUTPUT", &env_value);
	if (status < 0) return status;
	config->output = env_value;
	if (config->output == NULL || *config->output == '\0')
		config->output = ":stderr";

	status = envp_getenv(envp, "PROOT_ADDON_CC_OPTS_CCRE", &env_value);
	if (status < 0) return status;
	config->driver_regexp = env_value;
	if (config->driver_regexp == NULL)
		config->driver_regexp = "^\\(gcc\\|g++\\|cc\\|c++\\)$";
	if (regcomp(&config->driver_re, config->driver_regexp, REG_NOSUB|REG_NEWLINE) != 0) {
		fprintf(stderr, "error: cc_opts addon: error in driver path regexp: %s\n",
			config->driver_regexp);
		return -1;
	}

	status = envp_getenv(envp, "PROOT_ADDON_CC_OPTS_ARGS", &env_value);
	if (status < 0) return status;
	config->opts = env_value;
	if (config->opts != NULL) {
		config->opt_args = (const char * const *)parse_opts(extension, config->opts);
	}

	status = envp_getenv(envp, "PROOT_ADDON_CC_OPTS_DRIVER", &env_value);
	if (status < 0) return status;
	config->driver_cmd = env_value;
	if (config->driver_cmd) config->driver_cmd = realpath(config->driver_cmd, NULL);

	/* Open output file.  */
	if (strcmp(config->output, ":stdout") == 0)
		config->output_file = stdout;
	else if (strcmp(config->output, ":stderr") == 0)
		config->output_file = stderr;
	else {
		const char *mode = "w";
		const char *output = config->output;
		if (*output == '+') {
			mode = "a";
			output++;
		}
		config->output_file = fopen(output, mode);
		if (config->output_file == NULL) {
			perror("error: cc_opts addon output file");
			return -1;
		}
		setlinebuf(config->output_file);
	}
	if (config->verbose &&
	    (config->parent == NULL || config->parent->active == 0)) {
		OUTPUT("cc_opts: output file: %s\n", config->output);
		OUTPUT("cc_opts: driver regexp: %s\n", config->driver_regexp);
		OUTPUT("cc_opts: options: %s\n", config->opts?:"<none>");
	}

	return 0;
}


static int cc_opts_init(Extension *extension)
{
	assert(extension->config == NULL);
	extension->config = talloc_zero(extension, cc_opts_config_t);
	if (extension->config == NULL)
		return -1;
	return 0;

}

static int cc_opts_fini(Extension *extension)
{
	cc_opts_config_t *config;

	assert(extension->config != NULL);
	config = extension->config;
	regfree(&config->driver_re);
	talloc_free(extension->config);
	extension->config = NULL;
	return 0;
}

static int cc_opts_inherit(Extension *extension, Extension *parent_extension)
{
	int status;
	cc_opts_config_t *config, *parent_config;

	assert(parent_extension->config != NULL);
	status = cc_opts_init(extension);
	if (status < 0) return status;
	config = extension->config;
	parent_config = parent_extension->config;
	config->parent = parent_config;
	return 0;
}

static int cc_opts_callback(Extension *extension, ExtensionEvent event,
			intptr_t data1, intptr_t data2)
{

	switch (event) {
	case INITIALIZATION:
		return cc_opts_init(extension);

	case INHERIT_PARENT:
		return 1; /* Handle inheritance specifically. */

	case INHERIT_CHILD: {
		Extension *parent_extension = (Extension *)data1;
		return cc_opts_inherit(extension, parent_extension);
	}

	case SYSCALL_ENTER_START:
		return cc_opts_enter(extension);

	case REMOVED:
		return cc_opts_fini(extension);

	default:
		break;
	}

	return 0;
}


/**
 * Register the current addon through a constructor function.
 */
static void __attribute__((constructor)) init(void)
{
	static struct addon_info addon = { "cc_opts", cc_opts_callback };

	syscall_addons_register(&addon);
}
