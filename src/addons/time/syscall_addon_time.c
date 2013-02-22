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

/*
 * Output timing information for a process.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h> /* open, close (3p) */
#include <unistd.h> /* read, readlink, sysconf (3p) */
#include <stdint.h> /* uint32_t */
#include <inttypes.h> /* SCNu32, PRNu32 */
#include <limits.h> /* PATH_MAX */
#include <time.h> /* CLOCKS_PER_SEC */
#include <signal.h> /* SIGTRAP, */
#include <sys/ptrace.h> /* PTRACE_EVENT_EXIT, */

#include "addons/syscall_addons.h"
#include "tracee/tracee.h"
#include "extension/extension.h"

/**
 * Defines OUTPUT macro for all addon outputs.
 */
#define OUTPUT(...) fprintf(output_file, __VA_ARGS__);
#define VERBOSE(...) do { if (verbose) OUTPUT(__VA_ARGS__); } while (0)

static int active;
static int verbose;
static const char *output;
FILE *output_file;


/**
 * Get executable path for the current process.
 */
static int get_pid_exe(int pid, char path[PATH_MAX])
{
	char buffer[256];
	int n;
	snprintf(buffer, sizeof(buffer), "/proc/%d/exe", pid);
	
	if ((n = readlink(buffer, path, PATH_MAX-1)) < 0) {
		return -1;
	}
	path[n] = '\0';
	return 0;
}

static int
read_stat(int pid, char stat_buffer[PATH_MAX])
{
	char buffer[256];
	int n;
	int status = 0;
	int fd;
	snprintf(buffer, sizeof(buffer), "/proc/%d/stat", pid);
	fd = open(buffer, O_RDONLY);
	if (fd < 0) {
		status = -1;
		goto end;
	}
	n = read(fd, stat_buffer, PATH_MAX-1);
	if (n < 0) {
		status = -1;
		goto end;
	}
	stat_buffer[n] = '\0';
 end:
	if (fd != -1)
		close(fd);
	return status;
}

static int
parse_stat(const char stat_buffer[PATH_MAX], uint32_t *ut, uint32_t *st, uint32_t *cut, uint32_t *cst)
{
	sscanf(stat_buffer, "%*d (%*[^)]) %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %"SCNu32" %"SCNu32" %"SCNu32" %"SCNu32,
	       ut, st, cut, cst);
	return 0;
}

/**
 * Outputs timing information for the exited process.
 */
static int
addon_procexit(const Tracee *tracee)
{
	char buffer[PATH_MAX];
	uint32_t ut, st, cut, cst;
	if (!active)
		return 0;
	
	if (read_stat(tracee->pid, buffer) == -1)
		goto end;
	VERBOSE("%s", buffer);
	if (parse_stat(buffer, &ut, &st, &cut, &cst) == -1)
		goto end;
	if (get_pid_exe(tracee->pid, buffer) == -1)
		goto end;
	
	OUTPUT("TIME: \"%s\": %"PRIu32" %"PRIu32" %"PRIu32" %"PRIu32" %"PRIu32"\n", buffer, (uint32_t)sysconf(_SC_CLK_TCK), ut, st, cut, cst);
 end:
	return 0;
}

/**
 * Register the current addon through a constructor function.
 */
static int time_callback(Extension *extension, ExtensionEvent event,
			intptr_t data1, intptr_t data2);

static struct addon_info addon = { "time", time_callback };

static void __attribute__((constructor)) init(void)
{
	syscall_addons_register(&addon);
}

static int time_init(void)
{
	active = getenv("PROOT_ADDON_TIME") != NULL;
	verbose = getenv("PROOT_ADDON_TIME_VERBOSE") != NULL;
	output = getenv("PROOT_ADDON_TIME_OUTPUT");
	if (output == NULL || *output == '\0')
		output = ":stderr";

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
			perror("error: time addon output file");
			return -1;
		}
		setlinebuf(output_file);
	}
	
	if (verbose) {
		OUTPUT("time: output file: %s\n", output);
	}

	return 0;
}


static int time_callback(Extension *extension, ExtensionEvent event,
			intptr_t data1, intptr_t data2)
{
	const Tracee *tracee = TRACEE(extension);

	switch (event) {
	case INITIALIZATION:
		return time_init();

	case NEW_STATUS: {
		int signal;
		int tracee_status;

		tracee_status = (int) data1;
		signal = (tracee_status & 0xfff00) >> 8;

		if (!WIFSTOPPED(tracee_status) || signal != (SIGTRAP | PTRACE_EVENT_EXIT  << 8))
			break;

		return addon_procexit(tracee);
	}

	default:
		break;
	}

	return 0;
}
