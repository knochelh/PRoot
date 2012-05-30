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
 */

#include <limits.h>     /* PATH_MAX, */
#include <sys/types.h>  /* pid_t, */
#include <sys/ptrace.h> /* ptrace(3), PTRACE_*, */
#include <sys/types.h>  /* waitpid(2), */
#include <sys/wait.h>   /* waitpid(2), */
#include <sys/personality.h> /* personality(2), ADDR_NO_RANDOMIZE, */
#include <sys/time.h>   /* *rlimit(2), */
#include <sys/resource.h> /* *rlimit(2), */
#include <fcntl.h>      /* AT_FDCWD, */
#include <unistd.h>     /* fork(2), chdir(2), getpid(2), */
#include <string.h>     /* strcpy(3), */
#include <errno.h>      /* errno(3), */
#include <stdbool.h>    /* bool, true, false, */
#include <assert.h>     /* assert(3), */
#include <stdlib.h>     /* atexit(3), */

#include "trace.h"
#include "notice.h"
#include "path/path.h"
#include "syscall/syscall.h"
#include "config.h"

#include "compat.h"

#ifdef ENABLE_ADDONS
#include "addons/syscall_addons.h"
#endif

bool launch_process()
{
	struct rlimit rlimit;
	long status;
	pid_t pid;

	pid = fork();
	switch(pid) {
	case -1:
		notice(ERROR, SYSTEM, "fork()");

	case 0: /* child */
		/* Declare myself as ptraceable before executing the
		 * requested program. */
		status = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		if (status < 0)
			notice(ERROR, SYSTEM, "ptrace(TRACEME)");

		/* Warn about open file descriptors. They won't be
		 * translated until they are closed. */
		list_open_fd(getpid());

		/* RHEL4 uses an ASLR mechanism that creates conflicts
		 * between the layout of QEMU and the layout of the
		 * target program. */
		status = personality(0xffffffff);
		if (   status < 0
		    || personality(status | ADDR_NO_RANDOMIZE) < 0)
			notice(WARNING, INTERNAL, "can't disable ASLR");

		/* 1. The ELF interpreter is explicitly used as a
		 *    loader by PRoot, it means the Linux kernel
		 *    allocates the heap segment for this loader, not
		 *    for the application.  It isn't really a problem
		 *    since the application re-uses the loader's heap
		 *    transparently, i.e. its own brk points there.
		 *
		 * 2. When the current stack limit is set to a "high"
		 *    value, the ELF interpreter is loaded to a "low"
		 *    address, I guess it is the way the Linux kernel
		 *    deals with this constraint.
		 *
		 * This two behaviors can be observed by running the
		 * command "/usr/bin/cat /proc/self/maps", with/out
		 * the ELF interpreter and with/out a high current
		 * stack limit.
		 *
		 * When this two behaviors are combined, the dynamic
		 * ELF linker might mmap a shared libraries to the
		 * same address as the start of its heap if no heap
		 * allocation was made prior this mmap.  This problem
		 * was first observed with something similar to the
		 * example below (because GNU make sets the current
		 * limit to the maximum):
		 *
		 *     #!/usr/bin/make -f
		 *
		 *     SHELL=/lib64/ld-linux-x86-64.so.2 /usr/bin/bash
		 *     FOO:=$(shell test -e /dev/null && echo OK)
		 *
		 *     all:
		 *            @/usr/bin/test -n "$(FOO)"
		 *
		 * The code below is a workaround to this wrong
		 * combination of behaviors, however it might create
		 * conflict with tools that assume a "standard" stack
		 * layout, like libgomp and QEMU.
		 */
		status = getrlimit(RLIMIT_STACK, &rlimit);
		if (status >= 0 && rlimit.rlim_max == RLIM_INFINITY) {
			/* "No one will need more than 256MB of stack memory" (tm).  */
			rlimit.rlim_max = 256 * 1024 * 1024;
			if (rlimit.rlim_cur > rlimit.rlim_max)
				rlimit.rlim_cur = rlimit.rlim_max;
			status = setrlimit(RLIMIT_STACK, &rlimit);
		}
		if (status < 0)
			notice(WARNING, SYSTEM, "can't set the maximum stack size");

		/* Synchronize with the tracer's event loop.  Without
		 * this trick the tracer only sees the "return" from
		 * the next execve(2) so PRoot wouldn't handle the
		 * interpreter/runner.  I also verified that strace
		 * does the same thing. */
		kill(getpid(), SIGSTOP);

		/* Now process is ptraced, so the current rootfs is
		 * already the guest rootfs. */

		if (config.initial_cwd) {
			status = chdir(config.initial_cwd);
			if (status < 0) {
				notice(WARNING, SYSTEM, "chdir('%s/)", config.initial_cwd);
				chdir("/");
			}
		}
		else
			chdir("/");

		execvp(config.command[0], config.command);

		return false;

	default: /* parent */
		return (new_tracee(pid) != NULL);
		break;
	}

	/* Never reached.  */
	return false;
}

bool attach_process(pid_t pid)
{
	long status;
	struct tracee_info *tracee;

	notice(WARNING, USER, "attaching a process on-the-fly is still experimental");

	status = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
	if (status < 0)
		notice(ERROR, SYSTEM, "ptrace(ATTACH, %d)", pid);

	/* Warn about open file descriptors. They won't be translated
	 * until they are closed. */
	list_open_fd(pid);

	tracee = new_tracee(pid);
	return (tracee != NULL);
}

/* Send the KILL signal to all [known] tracees.  */
static void kill_all_tracees()
{
	int kill_tracee(pid_t pid)
	{
		kill(pid, SIGKILL);
		return 0;
	}

	foreach_tracee(kill_tracee);
}

static void kill_all_tracees2(int signum, siginfo_t *siginfo, void *ucontext)
{
	notice(WARNING, INTERNAL, "signal %d received from process %d", signum, siginfo->si_pid);
	kill_all_tracees();

	/* Exit immediately for system signals (segmentation fault,
	 * illegal instruction, ...), otherwise exit cleanly through
	 * the event loop.  */
	if (signum != SIGQUIT)
		_exit(EXIT_FAILURE);
}

int event_loop()
{
	struct sigaction signal_action;
	struct tracee_info *tracee;
	int last_exit_status = -1;
	int tracee_status;
	long status;
	int signum;
	int signal;
	pid_t pid;

	/* Kill all tracees when exiting.  */
	status = atexit(kill_all_tracees);
	if (status != 0)
		notice(WARNING, INTERNAL, "atexit() failed");

	/* All signals are blocked when the signal handler is called.
	 * SIGINFO is used to know which process has signaled us and
	 * RESTART is used to restart waitpid(2) seamlessly.  */
	bzero(&signal_action, sizeof(signal_action));
	signal_action.sa_flags = SA_SIGINFO | SA_RESTART;
	status = sigfillset(&signal_action.sa_mask);
	if (status < 0)
		notice(WARNING, SYSTEM, "sigfillset()");

	/* Handle all signals.  */
	for (signum = 0; signum < SIGRTMAX; signum++) {
		switch (signum) {
		case SIGQUIT:
		case SIGILL:
		case SIGABRT:
		case SIGFPE:
		case SIGSEGV:
			/* Kill all tracees on abnormal termination
			 * signals.  This ensures no process is left
			 * untraced.  */
			signal_action.sa_sigaction = kill_all_tracees2;
			break;

		case SIGCHLD:
		case SIGCONT:
		case SIGSTOP:
		case SIGTSTP:
		case SIGTTIN:
		case SIGTTOU:
			/* The default action is OK for these signals,
			 * they are related to tty and job control.  */
			continue;

		default:
			/* Ignore all other signals, including
			 * terminating ones (^C for instance). */
			signal_action.sa_sigaction = (void *)SIG_IGN;
			break;
		}

		status = sigaction(signum, &signal_action, NULL);
		if (status < 0 && errno != EINVAL)
			notice(WARNING, SYSTEM, "sigaction(%d)", signum);
	}

	signal = 0;
	while (1) {
		/* Wait for the next tracee's stop. */
		pid = waitpid(-1, &tracee_status, __WALL);
		if (pid < 0) {
			if (errno != ECHILD)
				notice(ERROR, SYSTEM, "waitpid()");
			else
				break;
		}

		/* Check every tracee file descriptors. */
		if (config.check_fd)
			foreach_tracee(check_fd);

		/* Get the information about this tracee. */
		tracee = get_tracee_info(pid, true);
		assert(tracee != NULL);

		if (WIFEXITED(tracee_status)) {
			VERBOSE(1, "pid %d: exited with status %d",
			           pid, WEXITSTATUS(tracee_status));
			last_exit_status = WEXITSTATUS(tracee_status);
			delete_tracee(tracee);
			continue; /* Skip the call to ptrace(SYSCALL). */
		}
		else if (WIFSIGNALED(tracee_status)) {
			VERBOSE(get_nb_tracees() != 1,
				"pid %d: terminated with signal %d",
				pid, WTERMSIG(tracee_status));
			delete_tracee(tracee);
			continue; /* Skip the call to ptrace(SYSCALL). */
		}
		else if (WIFCONTINUED(tracee_status)) {
			VERBOSE(1, "pid %d: continued", pid);
			signal = SIGCONT;
		}
		else if (WIFSTOPPED(tracee_status)) {

			/* Don't use WSTOPSIG() to extract the signal
			 * since it clears the PTRACE_EVENT_* bits. */
			signal = (tracee_status & 0xfff00) >> 8;

			switch (signal) {
				static bool skip_bare_sigtrap = false;

			case SIGTRAP:
				/* Distinguish some events from others and
				 * automatically trace each new process with
				 * the same options.
				 *
				 * Note that only the first bare SIGTRAP is
				 * related to the tracing loop, others SIGTRAP
				 * carry tracing information because of
				 * TRACE*FORK/CLONE/EXEC.
				 */
				if (skip_bare_sigtrap)
					break;
				skip_bare_sigtrap = true;

				status = ptrace(PTRACE_SETOPTIONS, tracee->pid, NULL,
						PTRACE_O_TRACESYSGOOD |
						PTRACE_O_TRACEFORK    |
						PTRACE_O_TRACEVFORK   |
						PTRACE_O_TRACEEXEC    |
						PTRACE_O_TRACECLONE   |
						PTRACE_O_TRACEEXIT);
				if (status < 0)
					notice(ERROR, SYSTEM, "ptrace(PTRACE_SETOPTIONS)");
				/* Fall through. */
			case SIGTRAP | 0x80:
				status = translate_syscall(tracee);
				if (status < 0) {
					/* The process died in a syscall. */
					delete_tracee(tracee);
					continue; /* Skip the call to ptrace(SYSCALL). */
				}
				signal = 0;
				break;

			case SIGTRAP | PTRACE_EVENT_FORK  << 8:
			case SIGTRAP | PTRACE_EVENT_VFORK << 8:
			case SIGTRAP | PTRACE_EVENT_CLONE << 8:
			case SIGTRAP | PTRACE_EVENT_EXEC  << 8:
				/* Ignore these signals. */
				signal = 0;
				break;

			case SIGTRAP | PTRACE_EVENT_EXIT  << 8:
#ifdef ENABLE_ADDONS
				syscall_addons_procexit(get_tracee_info(pid, false));
#endif
				signal = 0;
				break;
			case SIGSTOP:
				/* For each tracee, the first SIGSTOP
				 * is only used to notify the tracer.  */
				if (!tracee->allow_sigstop)
					signal = 0;
				tracee->allow_sigstop = true;
				break;

			default:
				break;
			}
		}
		else {
			notice(WARNING, INTERNAL, "unknown trace event");
			signal = 0;
		}

		/* Restart the tracee and stop it at the next entry or
		 * exit of a system call. */
		status = ptrace(PTRACE_SYSCALL, tracee->pid, NULL, signal);
		if (status < 0) {
			 /* The process died in a syscall.  */
			notice(WARNING, SYSTEM, "ptrace(SYSCALL)");
			delete_tracee(tracee);
		}
	}

	return last_exit_status;
}
