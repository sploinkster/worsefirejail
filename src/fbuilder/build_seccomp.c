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
	// strace can prefix with:  [pid 12345]  openat(...)
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

	// ignore noise lines
	if (strncmp(p, "+++", 3) == 0) return 0;
	if (strncmp(p, "---", 3) == 0) return 0;
	if (strncmp(p, "strace:", 7) == 0) return 0;
	if (strncmp(p, "Process", 7) == 0) return 0;

	// syscall name begins with [A-Za-z_]
	if (!isalpha((unsigned char)*p) && *p != '_')
		return 0;

	size_t i = 0;
	while ((isalnum((unsigned char)*p) || *p == '_') && i + 1 < outsz) {
		out[i++] = *p++;
	}
	out[i] = '\0';

	// require '(' after the name (normal syscall line format)
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
		// strip newline
		char *nl = strchr(buf, '\n');
		if (nl) *nl = '\0';

		if (extract_syscall_name(buf, name, sizeof(name)))
			add_unique(syscalls, &n, CAP, name);
	}

	fclose(in);

	// stable output
	qsort(syscalls, n, sizeof(char *), cmp_str);

	if (n == 0) {
		fprintf(fp, "# 0 syscalls total\n");
		fprintf(fp, "# Probably you will need to add more syscalls to seccomp.keep. Look for\n");
		fprintf(fp, "# seccomp errors in /var/log/syslog or /var/log/audit/audit.log while\n");
		fprintf(fp, "# running your sandbox.\n");
		free_list(syscalls, n);
		return;
	}

	// Emit a real seccomp.keep line (this is what you asked for: actual syscalls collected).
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
