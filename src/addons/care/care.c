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

#define _ATFILE_SOURCE
#include <stdlib.h>      /* malloc(3), free(3), system(3), */
#include <string.h>      /* bzero(3), memcpy(3), */
#include <sys/utsname.h> /* uname(2), struct utsname, */
#include <unistd.h>      /* faccessat(2), */
#include <fcntl.h>       /* AT_*, */
#include <stdio.h>       /* fopen(3), fprintf(3), */
#include <assert.h>      /* assert(3),  */
#include <sys/utsname.h> /* uname(2), struct utsname, */
#include <sys/stat.h>    /* fstatat(2), */
#include <libgen.h>      /* basename(3), dirname(3), */
#include <errno.h>       /* errno, ENOENT */

#include "notice.h"
#include "execve/args.h"
#include "config.h"
#include "addons/syscall_addons.h"
#include "cec_lib.h"

extern char **environ;

/* XXX.  */
static int active;
static cec_hash_t *hash_table;
static char archive[PATH_MAX];
#ifdef CARE_NO_CPIO		
static int archive_dir_fd;
static char copy_buffer[4096];
#endif
static FILE *script = NULL;
static int verbose_level = 0;
static bool append = false;
static const char *replay_bindings[] = {
	"/proc",
	"/sys",
	"/dev",
	NULL
};

static const char *replay_filter_env[] = {
	"PROOT_ADDON_CARE",
	"PROOT_CARE_SCRIPT",
	"PROOT_CARE_ARCHIVE",
	"PROOT_CARE_VERBOSE",
	NULL
};

static const char *replay_replace_env[] = {
	"DISPLAY",
	"http_proxy",
	"https_proxy",
	"ftp_proxy",
	"no_proxy",
	"XAUTHORITY",
	NULL
};

/* XXX.  */
static bool care_init()
{
	const char *option;
	bool script_exists;
	int status;

	/* XXX.  */
	hash_table = cec_hash_new(cec_hash_string, cec_compare_strings, cec_free_element);
	if (hash_table == NULL) {
		notice(WARNING, INTERNAL, "care: XXXa");
		return false;
	}

	/* XXX.  */
	option = getenv("PROOT_CARE_VERBOSE");
	verbose_level = option ? atoi(option) : 0;
	if (config.verbose_level > verbose_level)
		verbose_level = config.verbose_level;

	/* XXX.  */
	option = getenv("PROOT_CARE_SCRIPT") ?: "/tmp/care.sh";
	script_exists = (access(option, F_OK) >= 0);

	script = fopen(option, "we");
	if (script == NULL) {
		notice(WARNING, SYSTEM, "care: open(\"%s\") for writing", option);
		return false;
	}

	if (verbose_level > 0)
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
#ifdef CARE_NO_CPIO
	archive_dir_fd = openat(AT_FDCWD, archive, 0);
	if (archive_dir_fd < 0) {
		status = mkdirat(AT_FDCWD, archive, 0755);
		if (status < 0) {
			notice(WARNING, INTERNAL, "care: can't create archive dir: %s", archive);
			return false;
		}
		archive_dir_fd = openat(AT_FDCWD, archive, 0);
		if (archive_dir_fd < 0) {
			notice(WARNING, INTERNAL, "care: can't open archive dir: %s", archive);
			return false;
		}
	} else {
		struct stat stat_buf;
		status = fstatat(AT_FDCWD, archive, &stat_buf, 0);
		if (status < 0) {
			notice(WARNING, INTERNAL, "care: can't stat archive dir: %s", archive);
			return false;
		}
		if (!S_ISDIR(stat_buf.st_mode)) {
			notice(WARNING, INTERNAL, "care: archive is not a directory: %s", archive);
			return false;
		}
		append = true;
	}
#else
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
#endif
	if (verbose_level > 0)
		notice(INFO, USER, "care: %s data in: %s",
		       append ? "appending (!)" : "writing", option);

	return true;
}


#ifdef CARE_NO_CPIO		
/* 
 * Recursively creates a directory path relative to the given
 * file descriptor. Ignores whether the path is absolute or not,
 * i.e. skip leadings "/".
 * Returns the directory fd.
 */
static int recmkdirat(int dirfd, const char *path)
{
	char *buffer;
	char *token;
	int status = 0;
	int new_dirfd, next_dirfd;
	buffer = strdup(path);
	next_dirfd = dirfd;
	token = strtok(buffer, "/");
	while(token) {
		new_dirfd = openat(next_dirfd, token, 0);
		if (new_dirfd > 0) {
			/* Check that it's a directory or force unlink. */
			struct stat stat_buf;
			status = fstatat(next_dirfd, token, &stat_buf, 0);
			if (status < 0) {
				notice(WARNING, INTERNAL, "care: can't stat element %s", token);
				status = -1;
				break;
			}
			if (!S_ISDIR(stat_buf.st_mode)) {
				new_dirfd = -1;
			}
		}
		if (new_dirfd < 0) {
			status = unlinkat(next_dirfd, token, 0);
			if (status < 0 && errno != ENOENT) {
				notice(WARNING, INTERNAL, "care: can't unlink archive file: %s", path);
				break;
			}
			status = mkdirat(next_dirfd, token, 0755);
			if (status < 0) {
				notice(WARNING, INTERNAL, "care: can't archive directory element: %s", token);
				break;
			}
			new_dirfd = openat(next_dirfd, token, 0);
			if (new_dirfd < 0) {
				notice(WARNING, INTERNAL, "care: can't open directory element: %s", token);
				status = new_dirfd;
				break;
			}
		}
		if (next_dirfd != dirfd)
			close(next_dirfd);
		next_dirfd = new_dirfd;
		token = strtok(NULL, "/");
	}
	free(buffer);
	if (status < 0) {
		if (next_dirfd != dirfd)
			close(next_dirfd);
		return status;
	}
	return next_dirfd;
}

static int copyat_reg(int srcdirfd, const char *srcpath, int dstdirfd, const char *dstpath)
{
	int status = 0;
	int n, srcfd, dstfd;
	srcfd = openat(srcdirfd, srcpath, O_RDONLY);
	if (srcfd < 0) {
		notice(WARNING, INTERNAL, "care: can't open element for reading: %s", srcpath);
		status = srcfd;
		goto end;
	}
	dstfd = openat(dstdirfd, dstpath, O_WRONLY|O_CREAT|O_EXCL, 0600);
	if (srcfd < 0) {
		notice(WARNING, INTERNAL, "care: can't open element for reading: %s", srcpath);
		status = srcfd;
		goto close_src;
	}
	while((n = read(srcfd, copy_buffer, sizeof(copy_buffer))) > 0) {
		int m = write(dstfd, copy_buffer, n);
		if (m < n) {
			notice(WARNING, INTERNAL, "care: can't copy archive element: %s", srcpath);
			status = -1;
			goto close_dst;
		}
	}
	if (n < 0) {
		notice(WARNING, INTERNAL, "care: can't read archive element: %s", srcpath);
		status = -1;
	}
 close_dst:
	close(dstfd);
 close_src:
	close(srcfd);
 end:
	return status;
}
#endif


/* XXX.  */
static void care_archive(const char *path)
{
	int status;
#ifdef CARE_NO_CPIO		
	struct stat stat_buf;
	char link_buffer[PATH_MAX];
#else
	char command[ARG_MAX];
#endif
	/* Don't archive if the path was already seen before.
	 * This ensures the rootfs is re-created as it was
	 * before any file creation or modification. */
	if (cec_hash_has_element(hash_table, (void *)path))
		return;
	cec_hash_add_element(hash_table, strdup(path));

	/* Don't archive if the file isn't accessible.  */
	status = faccessat(AT_FDCWD, path, F_OK, AT_SYMLINK_NOFOLLOW);
	if (status < 0)
		return;

	/* XXX.  */
#ifdef CARE_NO_CPIO		
	status = fstatat(AT_FDCWD, path, &stat_buf, AT_SYMLINK_NOFOLLOW);
	if (status < 0) {
		notice(WARNING, INTERNAL, "care: can't stat %s", path);
		return;
	}
	if (S_ISREG(stat_buf.st_mode) || S_ISLNK(stat_buf.st_mode)) {
		char *buffer = strdup(path);
		char *base = basename(buffer);
		char *dir = dirname(buffer);
		int dir_fd;
		dir_fd = recmkdirat(archive_dir_fd, dir);
		if (dir_fd < 0) {
			notice(WARNING, INTERNAL, "care: can't archive directory: %s", dir);
			goto free_buffer;
		}
		status = unlinkat(dir_fd, base, 0);
		if (status < 0 && errno != ENOENT) {
			notice(WARNING, INTERNAL, "care: can't unlink archive file: %s", path);
			goto free_fd;
		}
		if (S_ISREG(stat_buf.st_mode)) {
			status = copyat_reg(AT_FDCWD, path, dir_fd, base);
			if (status < 0) {
				notice(WARNING, INTERNAL, "care: can't copy file to archive: %s", path);
				goto free_fd;
			}
			status = fchmodat(dir_fd, base, stat_buf.st_mode & 0777, 0);
			if (status < 0) 
				notice(WARNING, INTERNAL, "care: can't set permission for archive file: %s", path);
		} else if (S_ISLNK(stat_buf.st_mode)) {
			status = readlinkat(AT_FDCWD, path, link_buffer, sizeof(link_buffer));
			if (status < 0 || status >= sizeof(link_buffer)) {
				notice(WARNING, INTERNAL, "care: can't read link: %s", path);
				goto free_fd;
			}
			link_buffer[status] = '\0';
			status = symlinkat(link_buffer, dir_fd, base);
			if (status < 0) {
				notice(WARNING, INTERNAL, "care: can't add link to archive: %s", path);
				goto free_fd;
			}
		}
		if (status < 0) 
			notice(WARNING, INTERNAL, "care: can't archive file: %s", path);
	free_fd:
		if (dir_fd != archive_dir_fd) 
			close(dir_fd);
	free_buffer:
		free(buffer);
	} else if (S_ISDIR(stat_buf.st_mode)) {
		int fd = recmkdirat(archive_dir_fd, path);
		if (fd < 0) {
			notice(WARNING, INTERNAL, "care: can't archive directory: %s", path);
			return;
		}
		if (fd != archive_dir_fd) 
			close(fd);
	} /* Skipped otherwise */
#else
		status = snprintf(command, ARG_MAX,
			"echo '%s' | cpio --create %s --file=%s %s\n",
			path,
			append ? "--append" : "",
			archive,
			verbose_level ? "" : "--quiet >/dev/null 2>&1");
	if (status < 0) {
		notice(WARNING, SYSTEM, "care: can't build cpio command");
		return;
	}
	if (status >= sizeof(command)) {
		notice(WARNING, INTERNAL, "care: internal error with cpio command");
		return;
	}

	if (verbose_level > 2)
		fprintf(stderr, "cpio command: %s\n", command);

	/* XXX.  */
	status = system(command); 
	if (status != 0) {
		notice(WARNING, INTERNAL, "care: can't exec cpio command");
		return;
	}
	append = true;
#endif
}

/* XXX.  */
static void care_write_script()
{
	struct utsname utsname;
	char argv0[PATH_MAX];
	int status;
	int i, j;

	/* Force archive of replay bindings to avoid proot warnings at replay time. */
	for(i = 0; replay_bindings[i] != NULL; i++) {
		care_archive(replay_bindings[i]);
	}

	/* Destroy hash table. */
	cec_hash_del(hash_table);

	// XXX Create run.sh */
	fprintf(script, "#!/bin/sh\n");
	fprintf(script, "dir=`dirname $0`\n");
	fprintf(script, "dir=`cd $dir; pwd`\n");
	fprintf(script, "\n");

	/* PRoot doesn't [un]set any environment variables, so
	 * it's safe to dump them at the end.  */
	fprintf(script, "env --ignore-environment \\\n");
	for (i = 0; environ[i] != NULL; i++) {
		int skip = 0;
		for (j = 0; replay_filter_env[j] != NULL; j++) {
			int len = strlen(replay_filter_env[j]);
			if (strncmp(environ[i], replay_filter_env[j], len) == 0 &&
			    environ[i][len] == '=') {
				skip = 1;
				break;
			}
		}
		if (skip) continue;
		for (j = 0; replay_replace_env[j] != NULL; j++) {
			int len = strlen(replay_replace_env[j]);
			if (strncmp(environ[i], replay_replace_env[j], len) == 0 &&
			    environ[i][len] == '=') {
				fprintf(script, "\t\"%.*s=$%.*s\" \\\n", len, environ[i],
					len, environ[i]);
				skip = 1;
				break;
			}
		}
		if (skip) continue;
		fprintf(script, "\t'%s' \\\n", environ[i]);
	}

	/*
	 * XXX command-line.
	 */

	status = readlink("/proc/self/exe", argv0, PATH_MAX);
	if (status < 0) {
		notice(WARNING, SYSTEM, "care: XXX");
		strcpy(argv0, "proot");
	}

	fprintf(script, "\"${PROOT-$dir/proot}\" \\\n");

	for(i = 0; replay_bindings[i] != NULL; i++) {
		fprintf(script, "\t-b '%s' \\\n", replay_bindings[i]);
	}

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

	fprintf(script, "\t\"${ROOTFS-$dir}\" \\\n");

	fprintf(script, "\t");
	for (i = 0; config.command && config.command[i] != NULL; i++)
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
