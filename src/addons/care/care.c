/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * This file is part of PRoot.
 *
 * Copyright (C) 2010, 2011, 2012 STMicroelectronics
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

#include <stdlib.h>      /* malloc(3), free(3), system(3), */
#include <string.h>      /* bzero(3), memcpy(3), */
#include <sys/utsname.h> /* uname(2), struct utsname, */
#include <unistd.h>      /* faccessat(2), */
#include <fcntl.h>       /* AT_*, */
#include <stdio.h>       /* fopen(3), fprintf(3), */
#include <glib.h>        /* g_hast_*, g_*, */
#include <assert.h>      /* assert(3),  */

#include "notice.h"
#include "execve/args.h"
#include "config.h"
#include "addons/syscall_addons.h"

extern char **environ;

/* XXX.  */
static int active;
static GHashTable *hash_table;
static char archive[PATH_MAX];
static FILE *script = NULL;
static int verbose_level = 0;
static bool append = false;

/* XXX.  */
static bool care_init()
{
	const char *option;
	bool script_exists;
	int status;

	/* XXX.  */
	hash_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
	if (hash_table == NULL) {
		notice(WARNING, INTERNAL, "care: XXXa");
		return false;
	}

	/* XXX.  */
	option = getenv("PROOT_CARE_VERBOSE");
	verbose_level = MAX(option ? atoi(option) : 0, config.verbose_level);

	/* XXX.  */
	option = getenv("PROOT_CARE_SCRIPT") ?: "/tmp/care.sh";
	script_exists = (access(option, F_OK) >= 0);

	script = fopen(option, "we");
	if (script == NULL) {
		notice(WARNING, SYSTEM, "care: open(\"%s\") for writing", option);
		return false;
	}

	notice(INFO, USER, "care: %s execution information in: %s",
		script_exists ? "overwriting (!)" : "writing", option);

	/* XXX.  */
	option = getenv("PROOT_CARE_ARCHIVE") ?: "/tmp/care.cpio";
	if (strlen(option) >= PATH_MAX) {
		notice(WARNING, USER, "care: archive option is too long");
		return false;
	}
	strcpy(archive, option);

	/* XXX test XXX.  */
	status = access(archive, R_OK | W_OK);
	if (status < 0) {
		status = open(archive, O_CREAT|O_RDWR|O_TRUNC);
		if (status < 0) {
			notice(WARNING, SYSTEM, "care: creat(\"%s\")", archive);
			return false;
		}
		close(status);

		status = unlink(archive);
		if (status < 0) {
			notice(WARNING, SYSTEM, "care: unlink(\"%s\")", archive);
			return false;
		}
	}
	else
		append = true;

	notice(INFO, USER, "care: %s data in: %s",
		append ? "appending (!)" : "writing", option);

	return true;
}

/* XXX.  */
static void care_archive(const char *path)
{
	char command[ARG_MAX];
	void *entry;
	int status;
		
	/* Don't archive if the path was already seen before.
	 * This ensures the rootfs is re-created as it was
	 * before any file creation or modification. */
	entry = g_hash_table_lookup(hash_table, path);
	if (entry != NULL)
		return;
	g_hash_table_insert(hash_table, g_strdup(path), (void *)-1);

	/* Don't call ``cpio`` if the file isn't accessible.  */
	status = faccessat(AT_FDCWD, path, F_OK, AT_SYMLINK_NOFOLLOW);
	if (status < 0)
		return;

	/* XXX.  */
	status = snprintf(command, ARG_MAX,
			"echo '%s' | cpio --create %s --file=%s %s\n",
			path,
			append ? "--append" : "",
			archive,
			verbose_level ? "" : "--quiet >/dev/null 2>&1");
	if (status < 0) {
		notice(WARNING, SYSTEM, "care: XXX");
		return;
	}
	if (status >= sizeof(command)) {
		notice(WARNING, INTERNAL, "care: XXX");
		return;
	}

	if (verbose_level > 2)
		fprintf(stderr, "cpio command: %s\n", command);

	/* XXX.  */
	status = system(command); 
	if (status != 0) {
		notice(WARNING, INTERNAL, "care: XXX");
		return;
	}

	append = true;
}

/* XXX.  */
static void care_write_script()
{
	struct utsname utsname;
	char argv0[PATH_MAX];
	int status;
	int i;

	g_hash_table_remove_all(hash_table);

	// XXX Create run.sh */
	fprintf(script, "#!/bin/sh");
	fprintf(script, "\n\n");

	/* PRoot doesn't [un]set any environment variables, so
	 * it's safe to dump them at the end.  */
	fprintf(script, "env --ignore-environment \\\n");
	for (i = 0; environ[i] != NULL; i++)
		fprintf(script, "\t'%s' \\\n", environ[i]);

	/*
	 * XXX command-line.
	 */

	status = readlink("/proc/self/exe", argv0, PATH_MAX);
	if (status < 0) {
		notice(WARNING, SYSTEM, "care: XXX");
		strcpy(argv0, "proot");
	}

	fprintf(script, "'%s' \\\n", argv0);

	/* XXX TODO: bindings */
#if 0
	bool print_binding(const struct binding *binding)
	{
		fprintf(script, "\t-b '%s:%s' \\\n",
			binding->host.path, binding->guest.path);
	}
	foreach_binding(print_binding);
#endif

	status = uname(&utsname);
	if (status < 0)
		notice(WARNING, SYSTEM, "care: XXX");
	else
		fprintf(script, "\t-k '%s' \\\n", utsname.release);

	if (config.initial_cwd)
		fprintf(script, "\t-w '%s' \\\n", config.initial_cwd);

	if (config.qemu) {
		fprintf(script, "\t-q ");
		for (i = 0; config.qemu[i] != NULL; i++)
			fprintf(script, "'%s' ", config.qemu[i]);
		fprintf(script, "\\\n");
	}

	if (config.allow_unknown_syscalls)
		fprintf(script, "\t-u \\\n");

	if (config.disable_aslr)
		fprintf(script, "\t-a \\\n");

	if (config.fake_id0)
		fprintf(script, "\t-0 \\\n");

	if (config.verbose_level) {
		fprintf(script, "\t");
		for (i = config.verbose_level; i > 0; i--)
			fprintf(script, "-v ");
		fprintf(script, "\\\n");
	}

	assert(config.guest_rootfs);
	fprintf(script, "\t'%s' \\\n", config.guest_rootfs);

	assert(config.command);
	fprintf(script, "\t");
	for (i = 0; config.command[i] != NULL; i++)
		fprintf(script, "'%s' ", config.command[i]);
	fprintf(script, "\\\n");

}

#ifdef ENABLE_ADDONS
/**
 * Register the current addon through a constructor function.
 */
static int addon_canon_host_enter(struct tracee_info *tracee, char *real_path);

static struct addon_info addon = { NULL, NULL, NULL,  &addon_canon_host_enter};

static void __attribute__((constructor)) init(void)
{
	syscall_addons_register(&addon);
	active = getenv("PROOT_ADDON_CARE") != NULL;
	if (active) {
		if (!care_init()) {
			exit(1);
		}
	}
}

static void __attribute__((destructor)) fini(void)
{
	if (active)
		care_write_script();
}

static int addon_canon_host_enter(struct tracee_info *tracee, char *real_path)
{
	if (active)
		care_archive(real_path);
	return 0;
}
#else
bool callback(enum plugin_event event, struct tracee_info *tracee, intptr_t data)
{
	switch (event) {
	case PRINT_HELP:
		puts("XXX help");
		break;

	case PRINT_INFO:
		puts("XXX info");
		break;

	case LOADED:
		return care_init();

	case CANON_HOST_ENTRY:
		care_archive((char *)data);
		return true;

	case TRACING_END:
		care_write_script();
		return true;

	default:
		break;
	}

	return true;
}
#endif
