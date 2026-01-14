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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

int arg_debug = 0;
int arg_appimage = 0;

static void usage(void) {
	fprintf(stderr, "Firejail profile builder\n");
	fprintf(stderr, "Usage: firejail [--debug] --build[=profile-file] [--caps.keep=LIST] [--build-timeout=SECONDS] program-and-arguments\n");
	exit(1);
}

static int startswith(const char *s, const char *pfx) {
	return strncmp(s, pfx, strlen(pfx)) == 0;
}

int main(int argc, char **argv) {
	if (argc < 2)
		usage();

	FILE *outfp = stdout;
	int have_build = 0;
	int prog_index = -1;

	for (int i = 1; i < argc; i++) {
		const char *a = argv[i];

		if (strcmp(a, "--debug") == 0) {
			arg_debug = 1;
			continue;
		}
		if (strcmp(a, "--appimage") == 0) {
			arg_appimage = 1;
			continue;
		}

		// build flag (optionally with =file)
		if (strcmp(a, "--build") == 0 || startswith(a, "--build=")) {
			have_build = 1;
			if (startswith(a, "--build=")) {
				const char *fname = a + strlen("--build=");
				if (*fname == '\0')
					usage();
				outfp = fopen(fname, "w");
				if (!outfp) {
					fprintf(stderr, "Error fbuilder: cannot open %s: %s\n", fname, strerror(errno));
					exit(1);
				}
			}
			continue;
		}

		// accept these flags in build mode (fbuilder will read them again later)
		if (startswith(a, "--caps.keep=")) {
			continue;
		}
		if (strcmp(a, "--caps.keep") == 0) {
			// consume the next arg if present
			if (i + 1 >= argc)
				usage();
			i++;
			continue;
		}

		if (startswith(a, "--build-timeout=")) {
			continue;
		}
		if (strcmp(a, "--build-timeout") == 0) {
			if (i + 1 >= argc)
				usage();
			i++;
			continue;
		}

		// explicit end of options
		if (strcmp(a, "--") == 0) {
			if (i + 1 >= argc)
				usage();
			prog_index = i + 1;
			break;
		}

		// first non-option is the program
		if (a[0] != '-') {
			prog_index = i;
			break;
		}

		// unknown option
		usage();
	}

	if (!have_build)
		usage();
	if (prog_index < 0 || prog_index >= argc)
		usage();

	build_profile(argc, argv, prog_index, outfp);

	if (outfp != stdout)
		fclose(outfp);

	return 0;
}
