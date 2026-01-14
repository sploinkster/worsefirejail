/*
 * Copyright (C) 2014-2026 Firejail Authors
 *
 * This file is part of firejail project
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "fbuilder.h"
#include <sys/wait.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#define TRACE_OUTPUT   "/tmp/firejail-trace.XXXXXX"
#define SYSCALL_OUTPUT "/tmp/firejail-syscalls.XXXXXX"

static int startswith(const char *s, const char *pfx) {
	return strncmp(s, pfx, strlen(pfx)) == 0;
}

// parse build-mode options found before the program index
static const char *parse_caps_keep(int argc, char **argv, int prog_index) {
	for (int i = 1; i < prog_index; i++) {
		if (startswith(argv[i], "--caps.keep="))
			return argv[i] + strlen("--caps.keep=");
		if (strcmp(argv[i], "--caps.keep") == 0 && i + 1 < prog_index)
			return argv[i + 1];
	}
	return NULL;
}

static int parse_build_timeout(int argc, char **argv, int prog_index) {
	for (int i = 1; i < prog_index; i++) {
		if (startswith(argv[i], "--build-timeout=")) {
			const char *v = argv[i] + strlen("--build-timeout=");
			int n = atoi(v);
			if (n < 0) n = 0;
			return n;
		}
		if (strcmp(argv[i], "--build-timeout") == 0 && i + 1 < prog_index) {
			int n = atoi(argv[i + 1]);
			if (n < 0) n = 0;
			return n;
		}
	}
	return 0;
}

static void kill_process_group(pid_t pgid) {
	// terminate nicely first
	kill(-pgid, SIGTERM);
	usleep(250 * 1000);

	// if anything is still alive, nuke it
	kill(-pgid, SIGKILL);
}

void build_profile(int argc, char **argv, int index, FILE *fp) {
	// next index is the application name
	if (index >= argc) {
		fprintf(stderr, "Error fbuilder: application name missing\n");
		exit(1);
	}

	const char *caps_keep = parse_caps_keep(argc, argv, index);
	int build_timeout = parse_build_timeout(argc, argv, index);

	char trace_output[] = TRACE_OUTPUT;
	int tfile = mkstemp(trace_output);
	if (tfile == -1)
		errExit("mkstemp");
	close(tfile);

	char syscall_output[] = SYSCALL_OUTPUT;
	int sfile = mkstemp(syscall_output);
	if (sfile == -1)
		errExit("mkstemp");
	close(sfile);

	char *trace_arg;
	if (asprintf(&trace_arg, "--trace=%s", trace_output) == -1)
		errExit("asprintf");

	// We run the program under strace INSIDE the sandbox so we capture real syscalls.
	// firejail ... strace -f -qq -o <syscall_output> -e trace=%syscall -- <program...>
	//
	// (strace doesn't trace itself; it traces the sandboxed program and descendants.)
	const char *strace_path = "/usr/bin/strace";

	// calculate command length
	// plenty of space for firejail options + strace wrapper + program args + NULL
	unsigned len = 128;
	len += (unsigned)(argc - index);
	len += 16; // strace args etc.
	len += 1;  // NULL

	// build command
	char *cmd[len];
	unsigned curr_len = 0;
	cmd[curr_len++] = BINDIR "/firejail";
	cmd[curr_len++] = "--quiet";
	cmd[curr_len++] = "--noprofile";
	cmd[curr_len++] = "--seccomp=!chroot";
	cmd[curr_len++] = trace_arg;

	if (caps_keep && *caps_keep) {
		char *caparg;
		if (asprintf(&caparg, "--caps.keep=%s", caps_keep) == -1)
			errExit("asprintf");
		cmd[curr_len++] = caparg;
	}

	if (arg_appimage)
		cmd[curr_len++] = "--appimage";

	// strace wrapper
	cmd[curr_len++] = (char *)strace_path;
	cmd[curr_len++] = "-f";
	cmd[curr_len++] = "-qq";
	cmd[curr_len++] = "-o";
	cmd[curr_len++] = syscall_output;
	cmd[curr_len++] = "-e";
	cmd[curr_len++] = "trace=%syscall";
	cmd[curr_len++] = "--";

	for (int i = index; i < argc; i++)
		cmd[curr_len++] = argv[i];

	assert(curr_len < len);
	cmd[curr_len] = NULL;

	if (arg_debug) {
		for (int i = 0; cmd[i]; i++)
			printf("%s%s\n", (i) ? "\t" : "", cmd[i]);
	}

	// fork and execute
	pid_t child = fork();
	if (child == -1)
		errExit("fork");

	if (child == 0) {
		// Put the whole sandbox run in its own process group so we can kill it cleanly.
		setpgid(0, 0);

		assert(cmd[0]);
		int rv = execvp(cmd[0], cmd);
		(void)rv;
		errExit("execv");
	}

	// parent: ensure the child is the group leader
	setpgid(child, child);

	int status = 0;

	if (build_timeout > 0) {
		time_t start = time(NULL);
		for (;;) {
			pid_t r = waitpid(child, &status, WNOHANG);
			if (r == child)
				break;

			time_t now = time(NULL);
			if ((int)(now - start) >= build_timeout) {
				kill_process_group(child);
				(void)waitpid(child, &status, 0);
				break;
			}

			usleep(100 * 1000);
		}
	} else {
		(void)waitpid(child, &status, 0);
	}

	// Always emit the profile, even if the sandbox was killed by timeout/signal.
	if (fp == stdout)
		printf("--- Built profile begins after this line ---\n");

	fprintf(fp, "# Save this file as \"application.profile\" (change \"application\" with the\n");
	fprintf(fp, "# program name) in ~/.config/firejail directory. Firejail will find it\n");
	fprintf(fp, "# automatically every time you sandbox your application.\n#\n");
	fprintf(fp, "# Run \"firejail application\" to test it. In the file there are\n");
	fprintf(fp, "# some other commands you can try. Enable them by removing the \"#\".\n\n");

	fprintf(fp, "# Firejail profile for %s\n", argv[index]);
	fprintf(fp, "# Persistent local customizations\n");
	fprintf(fp, "#include %s.local\n", argv[index]);
	fprintf(fp, "# Persistent global definitions\n");
	fprintf(fp, "#include globals.local\n");
	fprintf(fp, "\n");

	fprintf(fp, "### Basic Blacklisting ###\n");
	fprintf(fp, "### Enable as many of them as you can! A very important one is\n");
	fprintf(fp, "### \"disable-exec.inc\". This will make among other things your home\n");
	fprintf(fp, "### and /tmp directories non-executable.\n");
	fprintf(fp, "include disable-common.inc\t# dangerous directories like ~/.ssh and ~/.gnupg\n");
	fprintf(fp, "#include disable-devel.inc\t# development tools such as gcc and gdb\n");
	fprintf(fp, "#include disable-exec.inc\t# non-executable directories such as /var, /tmp, and /home\n");
	fprintf(fp, "#include disable-interpreters.inc\t# perl, python, lua etc.\n");
	fprintf(fp, "include disable-programs.inc\t# user configuration for programs such as firefox, vlc etc.\n");
	fprintf(fp, "#include disable-shell.inc\t# sh, bash, zsh etc.\n");
	fprintf(fp, "#include disable-xdg.inc\t# standard user directories: Documents, Pictures, Videos, Music\n");
	fprintf(fp, "\n");

	fprintf(fp, "### Home Directory Whitelisting ###\n");
	fprintf(fp, "### If something goes wrong, this section is the first one to comment out.\n");
	fprintf(fp, "### Instead, you'll have to relay on the basic blacklisting above.\n");
	build_home(trace_output, fp);
	fprintf(fp, "\n");

	fprintf(fp, "### Filesystem Whitelisting ###\n");
	build_run(trace_output, fp);
	build_runuser(trace_output, fp);
	if (!arg_appimage)
		build_share(trace_output, fp);
	build_var(trace_output, fp);
	fprintf(fp, "\n");

	fprintf(fp, "#apparmor\t# if you have AppArmor running, try this one!\n");

	// Update output based on the user's chosen caps.keep
	if (caps_keep && *caps_keep)
		fprintf(fp, "caps.keep %s\n", caps_keep);
	// else: leave it out (same behavior as before: no caps directive)

	fprintf(fp, "ipc-namespace\n");
	fprintf(fp, "netfilter\n");
	fprintf(fp, "#no3d\t# disable 3D acceleration\n");
	fprintf(fp, "#nodvd\t# disable DVD and CD devices\n");
	fprintf(fp, "#nogroups\t# disable supplementary user groups\n");
	fprintf(fp, "#noinput\t# disable input devices\n");
	fprintf(fp, "nonewprivs\n");
	fprintf(fp, "noroot\n");
	fprintf(fp, "#notv\t# disable DVB TV devices\n");
	fprintf(fp, "#nou2f\t# disable U2F devices\n");
	fprintf(fp, "#novideo\t# disable video capture devices\n");
	build_protocol(trace_output, fp);

	// IMPORTANT: pass the STRACE syscall log here (not the firejail --trace log)
	build_seccomp(syscall_output, fp);

	fprintf(fp, "#tracelog\t# send blacklist violations to syslog\n");
	fprintf(fp, "\n");

	fprintf(fp, "#disable-mnt\t# no access to /mnt, /media, /run/mount and /run/media\n");
	if (!arg_appimage)
		build_bin(trace_output, fp);
	fprintf(fp, "#private-cache\t# run with an empty ~/.cache directory\n");
	build_dev(trace_output, fp);
	build_etc(trace_output, fp);
	fprintf(fp, "#private-lib\n");
	build_tmp(trace_output, fp);
	fprintf(fp, "\n");

	fprintf(fp, "#dbus-user none\n");
	fprintf(fp, "#dbus-system none\n");
	fprintf(fp, "\n");
	fprintf(fp, "#memory-deny-write-execute\n");

	if (!arg_debug) {
		unlink(trace_output);
		unlink(syscall_output);
	}
}
