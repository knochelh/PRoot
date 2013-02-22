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
 * Simple trace addon for tracing syscall parameters and exit values.
 */

#include <stdlib.h>
#include <stdio.h>

#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "syscall/syscall.h"
#include "addons/syscall_addons.h"
#include "extension/extension.h"


/**
 * Defines OUTPUT macro for all addon outputs.
 */
#define OUTPUT(...) fprintf(stderr, __VA_ARGS__);
#define VERBOSE(...) do { if (verbose) OUTPUT(__VA_ARGS__); } while (0)


static int verbose;

/**
 * Simple output of syscall number and name with arguments.
 */
static int addon_enter(Tracee *tracee)
{
	VERBOSE("pid %d: syscall(%ld, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx) [0x%lx]\n",
		tracee->pid, peek_reg(tracee, CURRENT, SYSARG_NUM),
		peek_reg(tracee, CURRENT, SYSARG_1), peek_reg(tracee, CURRENT, SYSARG_2),
		peek_reg(tracee, CURRENT, SYSARG_3), peek_reg(tracee, CURRENT, SYSARG_4),
		peek_reg(tracee, CURRENT, SYSARG_5), peek_reg(tracee, CURRENT, SYSARG_6),
		peek_reg(tracee, CURRENT, STACK_POINTER));
	return 0;
}


/**
 * Simple output of syscall result.
 */
static int addon_exit(Tracee *tracee)
{
	VERBOSE("pid %d:        -> 0x%lx [0x%lx]\n", tracee->pid, 
		peek_reg(tracee, CURRENT, SYSARG_RESULT),
		peek_reg(tracee, CURRENT, STACK_POINTER));
	return 0;
}


/**
 * Register the current addon through a constructor function.
 */
static int trace_callback(Extension *extension, ExtensionEvent event,
			intptr_t data1, intptr_t data2);

static struct addon_info addon = { "trace", trace_callback };

static void __attribute__((constructor)) register_addon(void)
{
	syscall_addons_register(&addon);
}

static int trace_callback(Extension *extension, ExtensionEvent event,
			intptr_t data1, intptr_t data2)
{
	Tracee *tracee = TRACEE(extension);

	switch (event) {
	case INITIALIZATION:
		verbose = getenv("PROOT_ADDON_TRACE") != NULL;
		break;

	case SYSCALL_ENTER_END:
		return addon_enter(tracee);

	case SYSCALL_EXIT_START:
		return addon_exit(tracee);

	default:
		break;
	}

	return 0;
}
