/*
 Copyright (C) 2015-2019 "IoT.bzh"

 author: José Bollo <jose.bollo@iot.bzh>

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
*/

#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <limits.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>

#include "subpath.h"

/* a valid subpath is a relative path not looking deeper than root using .. */
int subpath_is_valid(const char *path)
{
	int l = 0, i = 0;

	/* absolute path is not valid */
	if (path[i] == '/')
		return 0;

	/* inspect the path */
	while(path[i]) {
		switch(path[i++]) {
		case '.':
			if (!path[i])
				break;
			if (path[i] == '/') {
				i++;
				break;
			}
			if (path[i++] == '.') {
				if (!path[i]) {
					l--;
					break;
				}
				if (path[i++] == '/') {
					l--;
					break;
				}
			}
		default:
			while(path[i] && path[i] != '/')
				i++;
			if (l >= 0)
				l++;
		case '/':
			break;
		}
	}
	return l >= 0;
}

/*
 * Return the path or NULL is not valid.
 * Ensure that the path doesn't start with '/' and that
 * it does not contains sequence of '..' going deeper than
 * root.
 * Returns the path or NULL in case of
 * invalid path.
 */
const char *subpath(const char *path)
{
	return path && subpath_is_valid(path) ? (path[0] ? path : ".") : NULL;
}

/*
 * Normalizes and checks the 'path'.
 * Removes any starting '/' and checks that 'path'
 * does not contains sequence of '..' going deeper than
 * root.
 * Returns the normalized path or NULL in case of
 * invalid path.
 */
const char *subpath_force(const char *path)
{
	while(path && *path == '/')
		path++;
	return subpath(path);
}

#if defined(TEST_subpath)
#include <stdio.h>
void t(const char *subpath, int validity) {
  printf("%s -> %d = %d, %s\n", subpath, validity, subpath_is_valid(subpath), subpath_is_valid(subpath)==validity ? "ok" : "NOT OK");
}
int main() {
  t("/",0);
  t("..",0);
  t(".",1);
  t("../a",0);
  t("a/..",1);
  t("a/../////..",0);
  t("a/../b/..",1);
  t("a/b/c/..",1);
  t("a/b/c/../..",1);
  t("a/b/c/../../..",1);
  t("a/b/c/../../../.",1);
  t("./..a/././..b/..c/./.././.././../.",1);
  t("./..a/././..b/..c/./.././.././.././..",0);
  t("./..a//.//./..b/..c/./.././/./././///.././.././a/a/a/a/a",1);
  return 0;
}
#endif

