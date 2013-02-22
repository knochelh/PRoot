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

#include <stdlib.h>
#include "addons/syscall_addons.h"
#include "tracee/tracee.h"
#include "notice.h"
#include "extension/extension.h"

/**
 * Current list of active addons.
 */
struct addon_info *addons_list;


/**
 * Initialize all registered addons.
 */
int syscall_addons_init(Tracee *tracee)
{
	int status = 0;
	struct addon_info *current = addons_list;
	for (current = addons_list; current != NULL && status >= 0; current = current->next) {
		status = initialize_extension(tracee, current->callback, NULL);
		if (status < 0)
			notice(tracee, WARNING, INTERNAL,
				"can't initialize '%s' addon", current->name);
	}
	return status;
}


/**
 * Register a new addon into the processing list.
 */
void syscall_addons_register(struct addon_info *addon)
{
	struct addon_info **ptr_last = &addons_list;
	struct addon_info *current;
	for (current = addons_list; current != NULL && current != addon; current = current->next)
		ptr_last = &current->next;
	if (current != addon) {
		addon->next = NULL;
		*ptr_last = addon;
	}
}
