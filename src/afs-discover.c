/*
 * Copyright (C) 2016-2019 "IoT.bzh"
 * Author José Bollo <jose.bollo@iot.bzh>
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

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>

void afs_discover(const char *pattern, void (*callback)(void *closure, pid_t pid), void *closure)
{
	intmax_t n;
	DIR *dir;
	struct dirent *ent;
	char *name;
	char exe[PATH_MAX], lnk[PATH_MAX];

	dir = opendir("/proc");
	while ((ent = readdir(dir))) {
		name = ent->d_name;
		while (isdigit(*name))
			name++;
		if (*name)
			continue;
		n = snprintf(exe, sizeof exe, "/proc/%s/exe", ent->d_name);
		if (n < 0 || (size_t)n >= sizeof exe)
			continue;
		n = readlink(exe, lnk, sizeof lnk);
		if (n < 0 || (size_t)n >= sizeof lnk)
			continue;
		lnk[n] = 0;
		name = lnk;
		while(*name) {
			while(*name == '/')
				name++;
			if (*name) {
				if (!strcmp(name, pattern)) {
					callback(closure, (pid_t)atoi(ent->d_name));
					break;
				}
				while(*++name && *name != '/');
			}
		}
	}
	closedir(dir);
}

