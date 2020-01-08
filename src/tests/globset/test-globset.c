/*
 * Copyright (C) 2015-2020 "IoT.bzh"
 * Author: José Bollo <jose.bollo@iot.bzh>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "globset.h"

void process(FILE *in, FILE *out)
{
	int rc;
	char buffer[1024], *str;
	const struct globset_handler *gh;
	struct globset *set;

	set = globset_create();
	while (fgets(buffer, sizeof buffer, in)) {
		str = strchr(buffer,'\n');
		if (str) *str = 0;
		errno = 0;
		switch (buffer[0]) {
		case '+':
			rc = globset_add(set, &buffer[1], NULL, NULL);
			fprintf(out, "add [%s]: %d, %m\n", &buffer[1], rc);
			break;
		case '-':
			rc = globset_del(set, &buffer[1], NULL);
			fprintf(out, "del [%s]: %d, %m\n", &buffer[1], rc);
			break;
		case '?':
			gh = globset_search(set, &buffer[1]);
			fprintf(out, "search [%s]: %s%s\n", &buffer[1], gh ? "found " : "NOT FOUND", gh ? gh->pattern : "");
			break;
		default:
			gh = globset_match(set, buffer);
			fprintf(out, "match [%s]: %s%s\n", buffer, gh ? "found by " : "NOT FOUND", gh ? gh->pattern : "");
			break;
		}
	}
	globset_destroy(set);
}

int compare(FILE *f1, FILE *f2)
{
	int l = 0, n = 0;
	char b1[1024], b2[1024];
	char *s1, *s2;

	for(;;) {
		l++;
		s1 = fgets(b1, sizeof b1, f1);
		s2 = fgets(b2, sizeof b2, f2);
		if (s1 == NULL || s2 == NULL) {
			if (s1 != s2) {
				fprintf(stderr, "Length of outputs differ\n");
				n++;
			}
			return n;
		}
		if (strcmp(s1, s2)) {
			fprintf(stderr, "Line %d differ\n\t%s\t%s", l, s1, s2);
			n++;
		}
	}
}

int main(int ac, char **av)
{
	FILE *in = stdin;
	FILE *out = stdout;
	FILE *ref = NULL;

	if (ac >= 2) {
		in = fopen(av[1], "r");
		if (in == NULL) {
			fprintf(stderr, "Can't open file %s: %m\n", av[1]);
			return 1;
		}
	}

	if (ac < 3)
		setvbuf(stdout, NULL, _IOLBF, 0);
	else {
		ref = fopen(av[2], "r");
		if (ref == NULL) {
			fprintf(stderr, "Can't open file %s: %m\n", av[2]);
			return 1;
		}
		out = tmpfile();
		if (out == NULL) {
			fprintf(stderr, "Can't create temporary file: %m\n");
			return 1;
		}
	}

	process(in, out);

	if (ref) {
		rewind(out);
		if (compare(out, ref))
			return 1;
	}

	return 0;
}
