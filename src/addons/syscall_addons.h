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

#ifndef SYSCALL_ADDONS_H
#define SYSCALL_ADDONS_H

#ifdef ENABLE_ADDONS

#include "tracee/tracee.h"

/**
 * Records addon information.
 * Actually the callbacks to enter and exit
 * syscall processing functions for the addon.
 * A next field is for internal usage by register/unregister functions.
 */
struct addon_info {
	int (*enter)(Tracee *tracee);
	int (*exit)(Tracee *tracee);
	int (*procexit)(Tracee *tracee);
	int (*canon_host_enter)(Tracee *tracee, char *real_path);
	struct addon_info *next;
};


/**
 * Process the syscall before execution and after default proot processing.
 * All registered addon enter functions are executed until one returns a negative status.
 */
int syscall_addons_enter(Tracee *tracee);

/**
 * Process the syscall after execution and before default proot processing.
 * All registered addon exit functions are executed in reverse order until one returns
 * a negative status.
 */
int syscall_addons_exit(Tracee *tracee);

/**
 * Called on exit of tracee process.
 * Each registered addon procexit function is executed in order or registration.
 * A return value < 0 indicates failure of one of the addons.
 */
int syscall_addons_procexit(Tracee *tracee);

/**
 * Called on exit of tracee process.
 * Each registered addon procexit function is executed in order or registration.
 * A return value < 0 indicates failure of one of the addons.
 */
int syscall_addons_procexit(Tracee *tracee);

/**
 * Called on canonicalization entry.
 * Each registered addon is called.
 */
int syscall_addons_canon_host_enter(Tracee *tracee, char *real_path);

/**
 * Register a new addon to the processing list.
 * First in, first executed on syscall entry, last executed on syscall exit.
 */
void syscall_addons_register(struct addon_info *addon);

/**
 * Unregister an addon from the processign list.
 */
void syscall_addons_unregister(struct addon_info *addon);

#endif /* ENABLE_ADDONS */

#endif /* SYSCALL_ADDONS_H */
