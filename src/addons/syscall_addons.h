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

#include "extension/extension.h"

#ifdef ENABLE_ADDONS

/**
 * Records addon information.
 * A next field is for internal usage by register/unregister functions.
 */
struct addon_info {
	const char *name;
	extension_callback_t callback;
	struct addon_info *next;
};

/**
 * Initialize all registered addons.
 */
int syscall_addons_init(Tracee *tracee);

/**
 * Register a new addon to the processing list.
 * First in, first executed on syscall entry, first executed on syscall exit.
 */
void syscall_addons_register(struct addon_info *addon);

#endif /* ENABLE_ADDONS */

#endif /* SYSCALL_ADDONS_H */
