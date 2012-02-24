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
#include "tracee/info.h"
#include "tracee/ureg.h"
#include "syscall/syscall.h"
#include "addons/syscall_addons.h"


/**
 * Defines OUTPUT macro for all addon outputs.
 */
#define OUTPUT(...) fprintf(stderr, __VA_ARGS__);
#define VERBOSE(...) do { if (verbose) OUTPUT(__VA_ARGS__); } while (0)


static int verbose;

/**
 * Simple output of syscall number and name with arguments.
 */
static int addon_enter(struct tracee_info *tracee)
{
	VERBOSE("pid %d: syscall(%ld, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx) [0x%lx]\n",
		tracee->pid, tracee->sysnum,
		peek_ureg(tracee, SYSARG_1), peek_ureg(tracee, SYSARG_2),
		peek_ureg(tracee, SYSARG_3), peek_ureg(tracee, SYSARG_4),
		peek_ureg(tracee, SYSARG_5), peek_ureg(tracee, SYSARG_6),
		peek_ureg(tracee, STACK_POINTER));
	return 0;
}


/**
 * Simple output of syscall result.
 */
static int addon_exit(struct tracee_info *tracee)
{
	VERBOSE("pid %d:        -> 0x%lx [0x%lx]\n", tracee->pid, 
		peek_ureg(tracee, SYSARG_RESULT), peek_ureg(tracee, STACK_POINTER));
	return 0;
}


/**
 * Register the current addon through a constructor function.
 */
static struct addon_info addon = { &addon_enter, &addon_exit };

static void __attribute__((constructor)) register_addon(void)
{
	syscall_addons_register(&addon);
	verbose = getenv("PROOT_ADDON_TRACE") != NULL;
}
