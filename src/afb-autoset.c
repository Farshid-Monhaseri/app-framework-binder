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
#include <stdint.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "verbose.h"
#include "afb-api-ws.h"
#include "afb-api-so.h"
#include "afb-apiset.h"
#include "afb-autoset.h"

static void cleanup(void *closure)
{
	struct afb_apiset *call_set = closure;
	afb_apiset_unref(call_set);
}

static int onlack(void *closure, struct afb_apiset *set, const char *name, int (*create)(const char *path, struct afb_apiset *declare_set, struct afb_apiset *call_set))
{
	struct afb_apiset *call_set = closure;
	char *path;
	const char *base;
	size_t lbase, lname;

	base = afb_apiset_name(set);
	lbase = strlen(base);
	lname = strlen(name);

	path = alloca(2 + lbase + lname);
	memcpy(path, base, lbase);
	path[lbase] = '/';
	memcpy(&path[lbase + 1], name, lname + 1);

	return create(path, set, call_set);
}

static int add(const char *path, struct afb_apiset *declare_set, struct afb_apiset *call_set, int (*callback)(void *, struct afb_apiset *, const char*))
{
	struct afb_apiset *ownset;

	/* create a sub-apiset */
	ownset = afb_apiset_create_subset_last(declare_set, path, 3600);
	if (!ownset) {
		ERROR("Can't create apiset autoset-ws %s", path);
		return -1;
	}

	/* set the onlack behaviour on this set */
	afb_apiset_onlack_set(ownset, callback, afb_apiset_addref(call_set), cleanup);
	return 0;
}

/*******************************************************************/

static int create_ws(const char *path, struct afb_apiset *declare_set, struct afb_apiset *call_set)
{
	return afb_api_ws_add_client(path, declare_set, call_set, 0) >= 0;
}

static int onlack_ws(void *closure, struct afb_apiset *set, const char *name)
{
	return onlack(closure, set, name, create_ws);
}

int afb_autoset_add_ws(const char *path, struct afb_apiset *declare_set, struct afb_apiset *call_set)
{
	return add(path, declare_set, call_set, onlack_ws);
}

/*******************************************************************/

static int create_so(const char *path, struct afb_apiset *declare_set, struct afb_apiset *call_set)
{
	return afb_api_so_add_binding(path, declare_set, call_set) >= 0;
}

static int onlack_so(void *closure, struct afb_apiset *set, const char *name)
{
	return onlack(closure, set, name, create_so);
}

int afb_autoset_add_so(const char *path, struct afb_apiset *declare_set, struct afb_apiset *call_set)
{
	return add(path, declare_set, call_set, onlack_so);
}

/*******************************************************************/

static int create_any(const char *path, struct afb_apiset *declare_set, struct afb_apiset *call_set)
{
	int rc;
	struct stat st;
	char sockname[PATH_MAX + 7];

	rc = stat(path, &st);
	if (!rc) {
		switch(st.st_mode & S_IFMT) {
		case S_IFREG:
			rc = afb_api_so_add_binding(path, declare_set, call_set);
			break;
		case S_IFSOCK:
			snprintf(sockname, sizeof sockname, "unix:%s", path);
			rc = afb_api_ws_add_client(sockname, declare_set, call_set, 0);
			break;
		default:
			NOTICE("Unexpected autoset entry: %s", path);
			rc = -1;
			break;
		}
	}
	return rc >= 0;
}

static int onlack_any(void *closure, struct afb_apiset *set, const char *name)
{
	return onlack(closure, set, name, create_any);
}

int afb_autoset_add_any(const char *path, struct afb_apiset *declare_set, struct afb_apiset *call_set)
{
	return add(path, declare_set, call_set, onlack_any);
}
