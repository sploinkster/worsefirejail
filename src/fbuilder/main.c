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
#include <string.h>

int arg_debug = 0;
int arg_appimage = 0;

static const char *const usage_str =
	"Firejail profile builder\n"
	"Usage: firejail [--debug] --build[=profile-file] [--build-timeout=SECONDS] [--caps.keep=LIST] program-and-arguments\n";

static void usage(void) {
	puts(usage_str);
}

int main(int argc, char **argv) {
#if 0
{
system("cat /proc/self/status");
int i;
for (i = 0; i < argc; i++)
	printf("*%s* ", argv[i]);
printf("\n");
}
#endif

	int i;
	int prog_index = 0;
	FILE *fp = stdout;
	char *prof_file = NULL;

	// parse arguments and extract program index
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-?") ==0) {
			usage();
			return 0;
		}
		else if (strcmp(argv[i], "--debug") == 0)
			arg_debug = 1;
		else if (strcmp(argv[i], "--appimage") == 0)
			arg_appimage = 1;
		else if (strcmp(argv[i], "--build") == 0)
			; // do nothing, this is passed down from firejail
		else if (strncmp(argv[i], "--build=", 8) == 0) {
			// don't run if the file exists
			if (access(argv[i] + 8, F_OK) == 0) {
				fprintf(stderr, "Error fbuilder: the profile file already exists. Please use a different file name.\n");
				exit(1);
			}

			// check file access
			fp = fopen(argv[i] + 8, "w");
			if (!fp) {
				fprintf(stderr, "Error fbuilder: cannot open profile file.\n");
				exit(1);
			}
			prof_file = argv[i] + 8;
		}
		// accept build-only options so they don't get treated as "the program"
		else if (strncmp(argv[i], "--caps.keep=", 12) == 0)
			;
		else if (strcmp(argv[i], "--caps.keep") == 0) {
			// consume the next argument (the list)
			if (i + 1 >= argc) {
				fprintf(stderr, "Error fbuilder: --caps.keep requires an argument\n");
				exit(1);
			}
			i++;
		}
		else if (strncmp(argv[i], "--build-timeout=", 16) == 0)
			;
		else if (strcmp(argv[i], "--build-timeout") == 0) {
			// consume the next argument (seconds)
			if (i + 1 >= argc) {
				fprintf(stderr, "Error fbuilder: --build-timeout requires an argument\n");
				exit(1);
			}
			i++;
		}
		else {
			if (*argv[i] == '-') {
				fprintf(stderr, "Error fbuilder: invalid program\n");
				usage();
				exit(1);
			}
			prog_index = i;
			break;
		}
	}

	if (prog_index == 0) {
		fprintf(stderr, "Error fbuilder: program and arguments required\n");
		usage();
		if (prof_file) {
			fclose(fp);
			int rv = unlink(prof_file);
			(void) rv;
		}
		exit(1);
	}

	build_profile(argc, argv, prog_index, fp);
	if (prof_file)
		fclose(fp);
	return 0;
}
