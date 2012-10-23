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

/**
 * Current list of active addons.
 */
struct addon_info *addons_list;

/**
 * Process the syscall before execution and after default proot processing
 * with optional addons.
 * Activated only if ENABLE_ADDONS is defined.
 * Return value is the status in case of addons error or bad arguments.
 */
int syscall_addons_enter(Tracee *tracee)
{
	int status = 0;
	struct addon_info *current = addons_list;
	for (current = addons_list; current != NULL && status >= 0; current = current->next)
		if (current->enter != NULL)
			status = (*current->enter)(tracee);
	return status;
}


/**
 * Process the syscall after execution and before default proot processing
 * with optional addons.
 * Activated only if ENABLE_ADDONS is defined.
 * Return value is the status in case of addons error.
 */
int syscall_addons_exit(Tracee *tracee)
{
	int process_current_exit(struct addon_info *current)
	{
		int status = 0;
		if (current->next != NULL)
			status = process_current_exit(current->next);
		if (status >= 0)
			if (current->exit != NULL)
				status = (*current->exit)(tracee);
		return status;
	}
	int status = 0;
	struct addon_info *current = addons_list;
	if (current != NULL)
		status = process_current_exit(current);
	return status;
}


/**
 * Calls all registered addons procexit() function at tracee exit.
 * Activated only if ENABLE_ADDONS is defined.
 * A return value < 0 indicates failure of one of the addon to the
 * caller.
 * Also, if a procexit() addon function returns a status < 0
 * other procexit addons are skipped.
 */
int syscall_addons_procexit(Tracee *tracee)
{
	int status = 0;
	struct addon_info *current = addons_list;
	for (current = addons_list; current != NULL && status >= 0; current = current->next)
		if (current->procexit != NULL)
			status = (*current->procexit)(tracee);
	return status;
}


/**
 * Process the syscall before execution of canonicalization.
 * Activated only if ENABLE_ADDONS is defined.
 * Return value is the status in case of addons error or bad arguments.
 */
int syscall_addons_canon_host_enter(Tracee *tracee, char *real_path)
{
	int status = 0;
	struct addon_info *current = addons_list;
	for (current = addons_list; current != NULL && status >= 0; current = current->next)
		if (current->canon_host_enter != NULL)
		  status = (*current->canon_host_enter)(tracee, real_path);
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

/**
 * Unregister an addon from the processing list.
 */
void syscall_addons_unregister(struct addon_info *addon)
{
	struct addon_info **ptr_last = &addons_list;
	struct addon_info *current;
	for (current = addons_list; current != NULL && current != addon; current = current->next)
		ptr_last = &current->next;
	if (current == addon) {
		*ptr_last = addon->next;
		addon->next = NULL;
	}
}

