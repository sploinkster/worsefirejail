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
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

/*
 * build_seccomp(): parse RAW strace output (not strace -c, not firejail --trace)
 * and emit a seccomp.keep line with actual syscalls observed.
 *
 * This avoids the “0 syscalls total” issue you saw when you were feeding it
 * Firejail’s --trace log format.
 */

static int add_unique(char **arr, int *n, int cap, const char *s) {
	if (!s || !*s)
		return 0;

	for (int i = 0; i < *n; i++) {
		if (strcmp(arr[i], s) == 0)
			return 0;
	}

	if (*n >= cap)
		return 0;

	char *dup = strdup(s);
	if (!dup)
		errExit("strdup");
	arr[(*n)++] = dup;
	return 1;
}

static void free_list(char **arr, int n) {
	for (int i = 0; i < n; i++)
		free(arr[i]);
}

static int cmp_str(const void *a, const void *b) {
	const char *sa = *(const char * const *)a;
	const char *sb = *(const char * const *)b;
	return strcmp(sa, sb);
}

static const char *skip_pid_prefix(const char *line) {
	// Examples:
	//   [pid 12345] openat(...)
	//   openat(...)
	const char *p = line;
	while (isspace((unsigned char)*p)) p++;

	if (strncmp(p, "[pid", 4) == 0) {
		const char *end = strchr(p, ']');
		if (end) {
			p = end + 1;
			while (isspace((unsigned char)*p)) p++;
		}
	}
	return p;
}

static int extract_syscall_name(const char *line, char *out, size_t outsz) {
	const char *p = skip_pid_prefix(line);

	// Ignore common non-syscall lines
	if (strncmp(p, "+++", 3) == 0) return 0;
	if (strncmp(p, "---", 3) == 0) return 0;
	if (strncmp(p, "strace:", 7) == 0) return 0;
	if (strncmp(p, "Process ", 8) == 0) return 0;

	// Syscall name begins with alpha or underscore
	if (!isalpha((unsigned char)*p) && *p != '_')
		return 0;

	size_t i = 0;
	while ((isalnum((unsigned char)*p) || *p == '_') && i + 1 < outsz) {
		out[i++] = *p++;
	}
	out[i] = '\0';

	// Require '(' after optional whitespace; that’s the normal “syscall(args” format.
	while (isspace((unsigned char)*p)) p++;
	if (*p != '(')
		return 0;

	return (i > 0);
}

void build_seccomp(const char *fname, FILE *fp) {
	assert(fname);
	assert(fp);

	FILE *in = fopen(fname, "r");
	if (!in) {
		fprintf(fp, "# 0 syscalls total\n");
		fprintf(fp, "# Probably you will need to add more syscalls to seccomp.keep. Look for\n");
		fprintf(fp, "# seccomp errors in /var/log/syslog or /var/log/audit/audit.log while\n");
		fprintf(fp, "# running your sandbox.\n");
		return;
	}

	enum { CAP = 4096 };
	char *syscalls[CAP];
	int n = 0;
	memset(syscalls, 0, sizeof(syscalls));

	char buf[MAX_BUF];
	char name[128];

	while (fgets(buf, MAX_BUF, in)) {
		char *nl = strchr(buf, '\n');
		if (nl) *nl = '\0';

		if (extract_syscall_name(buf, name, sizeof(name)))
			add_unique(syscalls, &n, CAP, name);
	}

	fclose(in);

	qsort(syscalls, n, sizeof(char *), cmp_str);

	if (n == 0) {
		fprintf(fp, "# 0 syscalls total\n");
		fprintf(fp, "# Probably you will need to add more syscalls to seccomp.keep. Look for\n");
		fprintf(fp, "# seccomp errors in /var/log/syslog or /var/log/audit/audit.log while\n");
		fprintf(fp, "# running your sandbox.\n");
		free_list(syscalls, n);
		return;
	}

	fprintf(fp, "seccomp.keep ");
	for (int i = 0; i < n; i++) {
		if (i) fprintf(fp, ",");
		fprintf(fp, "%s", syscalls[i]);
	}
	fprintf(fp, "\n");

	fprintf(fp, "# %d syscalls total\n", n);
	fprintf(fp, "# Probably you will need to add more syscalls to seccomp.keep. Look for\n");
	fprintf(fp, "# seccomp errors in /var/log/syslog or /var/log/audit/audit.log while\n");
	fprintf(fp, "# running your sandbox.\n");

	free_list(syscalls, n);
}

/*************************************************
 * build_protocol()
 * (RESTORED) — this is why your link was failing.
 *************************************************/

static int unix_s = 0;
static int inet = 0;
static int inet6 = 0;
static int netlink = 0;
static int packet = 0;
static int bluetooth = 0;

static void process_protocol(const char *fname) {
	assert(fname);

	FILE *fp = fopen(fname, "r");
	if (!fp) {
		fprintf(stderr, "Error fbuilder: cannot open %s\n", fname);
		exit(1);
	}

	char buf[MAX_BUF];
	while (fgets(buf, MAX_BUF, fp)) {
		char *ptr = strchr(buf, '\n');
		if (ptr)
			*ptr = '\0';

		// parse line: 4:prog:socket AF_INET ...:0
		ptr = buf;
		if (!isdigit((unsigned char)*ptr))
			continue;
		while (isdigit((unsigned char)*ptr))
			ptr++;
		if (*ptr != ':')
			continue;
		ptr++;

		ptr = strchr(ptr, ':');
		if (!ptr)
			continue;
		ptr++;
		if (strncmp(ptr, "socket ", 7) == 0)
			ptr += 7;
		else
			continue;

		if (strncmp(ptr, "AF_LOCAL ", 9) == 0)
			unix_s = 1;
		else if (strncmp(ptr, "AF_INET ", 8) == 0)
			inet = 1;
		else if (strncmp(ptr, "AF_INET6 ", 9) == 0)
			inet6 = 1;
		else if (strncmp(ptr, "AF_NETLINK ", 11) == 0)
			netlink = 1;
		else if (strncmp(ptr, "AF_PACKET ", 10) == 0)
			packet = 1;
		else if (strncmp(ptr, "AF_BLUETOOTH ", 13) == 0)
			bluetooth = 1;
	}

	fclose(fp);
}

// process fname, fname.1, fname.2, fname.3, fname.4, fname.5
void build_protocol(const char *fname, FILE *fp) {
	assert(fname);

	// reset (important if build_protocol is called more than once)
	unix_s = inet = inet6 = netlink = packet = bluetooth = 0;

	process_protocol(fname);

	struct stat s;
	for (int i = 1; i <= 5; i++) {
		char *newname;
		if (asprintf(&newname, "%s.%d", fname, i) == -1)
			errExit("asprintf");
		if (stat(newname, &s) == 0)
			process_protocol(newname);
		free(newname);
	}

	int net = 0;
	if (unix_s || inet || inet6 || netlink || packet || bluetooth) {
		fprintf(fp, "protocol ");
		if (unix_s)
			fprintf(fp, "unix,");
		if (inet || inet6) {
			fprintf(fp, "inet,inet6,");
			net = 1;
		}
		if (netlink)
			fprintf(fp, "netlink,");
		if (packet) {
			fprintf(fp, "packet,");
			net = 1;
		}
		if (bluetooth) {
			fprintf(fp, "bluetooth");
			net = 1;
		}
		fprintf(fp, "\n");
	}

	if (net == 0)
		fprintf(fp, "net none\n");
	else {
		fprintf(fp, "#net eth0\n");
		fprintf(fp, "netfilter\n");
	}
}
