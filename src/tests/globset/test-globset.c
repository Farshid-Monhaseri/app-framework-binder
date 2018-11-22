/*
 * Copyright (C) 2018 "IoT.bzh"
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

int main()
{
	int rc;
	char buffer[1024], *str;
	const struct globset_handler *gh;
	struct globset *set;

	setvbuf(stdout, NULL, _IOLBF, 0);
	set = globset_create();
	while (fgets(buffer, sizeof buffer, stdin)) {
		str = strchr(buffer,'\n');
		if (str) *str = 0;
		errno = 0;
		switch (buffer[0]) {
		case '+':
			rc = globset_add(set, &buffer[1], NULL, NULL);
			printf("add [%s]: %d, %m\n", &buffer[1], rc);
			break;
		case '-':
			rc = globset_del(set, &buffer[1], NULL);
			printf("del [%s]: %d, %m\n", &buffer[1], rc);
			break;
		case '?':
			gh = globset_search(set, &buffer[1]);
			printf("search [%s]: %s%s\n", &buffer[1], gh ? "found " : "NOT FOUND", gh ? gh->pattern : "");
			break;
		default:
			gh = globset_match(set, buffer);
			printf("match [%s]: %s%s\n", buffer, gh ? "found by " : "NOT FOUND", gh ? gh->pattern : "");
			break;
		}
	}
	globset_destroy(set);
	return 0;
}
