/*
 * Copyright (C) 2015-2020 "IoT.bzh"
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

#if WITH_DYNAMIC_BINDING

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>

#include "afb-api-so.h"
#include "afb-api-so-v3.h"
#include "verbose.h"
#include "sig-monitor.h"

#if WITH_LEGACY_BINDING_V1
#   include "afb-api-so-v1.h"
#endif
#if WITH_LEGACY_BINDING_VDYN
#   include "afb-api-so-vdyn.h"
#endif
#if WITH_LEGACY_BINDING_V2
#   include "afb-api-so-v2.h"
#endif

struct safe_dlopen
{
	const char *path;
	void *handle;
	int flags;
};

static void safe_dlopen_cb(int sig, void *closure)
{
	struct safe_dlopen *sd = closure;
	if (!sig)
		sd->handle = dlopen(sd->path, sd->flags);
	else {
		ERROR("dlopen of %s raised signal %s", sd->path, strsignal(sig));
		sd->handle = NULL;
	}
}

static void *safe_dlopen(const char *filename, int flags)
{
	struct safe_dlopen sd;
	sd.path = filename;
	sd.flags = flags;
	sd.handle = NULL;
	sig_monitor(0, safe_dlopen_cb, &sd);
	return sd.handle;
}

static int load_binding(const char *path, int force, struct afb_apiset *declare_set, struct afb_apiset * call_set)
{
	int obsolete = 0;
	int rc;
	void *handle;
	static int dlopen_flags = 0;

	/* compute the dlopen flags */
	if (dlopen_flags == 0) {
		/* For ASan mode, export AFB_NO_RTLD_DEEPBIND=1, to disable RTLD_DEEPBIND */
		char *string = secure_getenv("AFB_NO_RTLD_DEEPBIND");
		if (string && string[0] == '1' && string[1] == 0)
			dlopen_flags = RTLD_NOW | RTLD_LOCAL;
		else
			dlopen_flags = RTLD_NOW | RTLD_LOCAL | RTLD_DEEPBIND;
	}

	/* set default return code rc according to force */
	rc = -!!force;

	/* try to open the library */
	handle = safe_dlopen(path, dlopen_flags);
	if (handle == NULL) {
		if (force)
			ERROR("binding [%s] not loadable: %s", path, dlerror());
		else
			WARNING("binding [%s] not loadable: %s", path, dlerror());
		goto error;
	}
	/*
	 * This is a loadable library let's check if it's a binding ...
	 */

	/* try the version 3 */
	rc = afb_api_so_v3_add(path, handle, declare_set, call_set);
	if (rc < 0) {
		/* error when loading a valid v3 binding */
		goto error2;
	}
	if (rc)
		return 0; /* yes version 3 */

#if WITH_LEGACY_BINDING_V2
	/* try the version 2 */
	rc = afb_api_so_v2_add(path, handle, declare_set, call_set);
	if (rc < 0) {
		/* error when loading a valid v2 binding */
		goto error2;
	}
	if (rc)
		return 0; /* yes version 2 */
#else
	if (dlsym(handle, "afbBindingV2")) {
		WARNING("binding [%s]: version 2 not supported", path);
		obsolete = 1;
	}
#endif

#if WITH_LEGACY_BINDING_VDYN
	/* try the version dyn */
	rc = afb_api_so_vdyn_add(path, handle, declare_set, call_set);
	if (rc < 0) {
		/* error when loading a valid dyn binding */
		goto error2;
	}
	if (rc)
		return 0; /* yes version dyn */
#else
	if (dlsym(handle, "afbBindingVdyn")) {
		WARNING("binding [%s]: version DYN not supported", path);
		obsolete = 1;
	}
#endif

#if WITH_LEGACY_BINDING_V1
	/* try the version 1 */
	rc = afb_api_so_v1_add(path, handle, declare_set, call_set);
	if (rc < 0) {
		/* error when loading a valid v1 binding */
		goto error2;
	}
	if (rc)
		return 0; /* yes version 1 */
#else
	if (dlsym(handle, "afbBindingV1Register")) {
		WARNING("binding [%s]: version 1 not supported", path);
		obsolete = 1;
	}
#endif

	/* not a valid binding */
	_VERBOSE_(force ? Log_Level_Error : Log_Level_Info, "binding [%s] %s",
			path, obsolete ? "is obsolete" : "isn't an AFB binding");

error2:
	dlclose(handle);
error:
	return rc;
}


int afb_api_so_add_binding(const char *path, struct afb_apiset *declare_set, struct afb_apiset * call_set)
{
	return load_binding(path, 1, declare_set, call_set);
}

static int adddirs(char path[PATH_MAX], size_t end, struct afb_apiset *declare_set, struct afb_apiset * call_set, int failstops)
{
	DIR *dir;
	struct dirent *dent;
	struct stat st;
	size_t len;
	int rc = 0;

	/* open the DIR now */
	dir = opendir(path);
	if (dir == NULL) {
		ERROR("can't scan binding directory %s, %m", path);
		return -1;
	}
	INFO("Scanning dir=[%s] for bindings", path);

	/* scan each entry */
	if (end)
		path[end++] = '/';
	for (;;) {
		errno = 0;
		dent = readdir(dir);
		if (dent == NULL) {
			if (errno != 0)
				ERROR("read error while scanning directory %.*s: %m", (int)(end - 1), path);
			break;
		}

		/* get the name and inspect dereferenced link instead of the directory entry */
		len = strlen(dent->d_name);
		if (len + end >= PATH_MAX) {
			ERROR("path too long while scanning bindings for %.*s%s", (int)end, path, dent->d_name);
			continue;
		}
		memcpy(&path[end], dent->d_name, len+1);
		rc = stat(path, &st);
		if (rc < 0) {
			ERROR("getting status of %s failed: %m", path);
			continue;
		}
		else if (S_ISDIR(st.st_mode)) {
			/* case of directories */
			if (dent->d_name[0] == '.') {
/*
Exclude from the search of bindings any
directory starting with a dot (.) by default.

It is possible to reactivate the prvious behaviour
by defining the following preprocessor variables

 - AFB_API_SO_ACCEPT_DOT_PREFIXED_DIRS

   When this variable is defined, the directories
   starting with a dot are searched except
   if their name is "." or ".." or ".debug"

 - AFB_API_SO_ACCEPT_DOT_DEBUG_DIRS

   When this variable is defined and the variable
   AFB_API_SO_ACCEPT_DOT_PREFIXED_DIRS is also defined
   scans any directory not being "." or "..".

The previous behaviour was like difining the 2 variables,
meaning that only . and .. were excluded from the search.

This change is intended to definitely solve the issue
SPEC-662. Yocto installed the debugging symbols in the
subdirectory .debug. For example the binding.so also
had a .debug/binding.so file attached. Opening that
debug file made dlopen crashing.
See https://sourceware.org/bugzilla/show_bug.cgi?id=22101
 */
#if !defined(AFB_API_SO_ACCEPT_DOT_PREFIXED_DIRS) /* not defined by default */
				continue; /* ignore any directory beginning with a dot */
#else
				if (len == 1)
					continue; /* . */
				if (dent->d_name[1] == '.' && len == 2)
					continue; /* .. */
#if !defined(AFB_API_SO_ACCEPT_DOT_DEBUG_DIRS) /* not defined by default */
				if (len == 6
				 && dent->d_name[1] == 'd'
				 && dent->d_name[2] == 'e'
				 && dent->d_name[3] == 'b'
				 && dent->d_name[4] == 'u'
				 && dent->d_name[5] == 'g')
					continue; /* .debug */
#endif
#endif
			}
			rc = adddirs(path, end+len, declare_set, call_set, failstops);
		} else if (S_ISREG(st.st_mode)) {
			/* case of files */
			if (memcmp(&dent->d_name[len - 3], ".so", 4))
				continue;
			rc = load_binding(path, 0, declare_set, call_set);
		}
		if (rc < 0 && failstops) {
			closedir(dir);
			return rc;
		}
	}
	closedir(dir);
	return 0;
}

int afb_api_so_add_directory(const char *path, struct afb_apiset *declare_set, struct afb_apiset * call_set, int failstops)
{
	size_t length;
	char buffer[PATH_MAX];

	length = strlen(path);
	if (length >= sizeof(buffer)) {
		ERROR("path too long %lu [%.99s...]", (unsigned long)length, path);
		return -1;
	}

	memcpy(buffer, path, length + 1);
	return adddirs(buffer, length, declare_set, call_set, failstops);
}

int afb_api_so_add_path(const char *path, struct afb_apiset *declare_set, struct afb_apiset * call_set, int failstops)
{
	struct stat st;
	int rc;

	rc = stat(path, &st);
	if (rc < 0)
		ERROR("Invalid binding path [%s]: %m", path);
	else if (S_ISDIR(st.st_mode))
		rc = afb_api_so_add_directory(path, declare_set, call_set, failstops);
	else if (strstr(path, ".so"))
		rc = load_binding(path, 0, declare_set, call_set);
	else
		INFO("not a binding [%s], skipped", path);
	return rc;
}

int afb_api_so_add_pathset(const char *pathset, struct afb_apiset *declare_set, struct afb_apiset * call_set, int failstops)
{
	static char sep[] = ":";
	char *ps, *p;
	int rc;

	ps = strdupa(pathset);
	for (;;) {
		p = strsep(&ps, sep);
		if (!p)
			return 0;
		rc = afb_api_so_add_path(p, declare_set, call_set, failstops);
		if (rc < 0)
			return rc;
	}
}

int afb_api_so_add_pathset_fails(const char *pathset, struct afb_apiset *declare_set, struct afb_apiset * call_set)
{
	return afb_api_so_add_pathset(pathset, declare_set, call_set, 1);
}

int afb_api_so_add_pathset_nofails(const char *pathset, struct afb_apiset *declare_set, struct afb_apiset * call_set)
{
	return afb_api_so_add_pathset(pathset, declare_set, call_set, 0);
}

#endif
