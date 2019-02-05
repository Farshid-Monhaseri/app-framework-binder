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

#if defined(WITH_LEGACY_BINDING_VDYN)

#define _GNU_SOURCE

#include <stdlib.h>
#include <dlfcn.h>

#define AFB_BINDING_VERSION 0
#include <afb/afb-binding.h>

#include "afb-api-so-v3.h"
#include "afb-api-so-vdyn.h"
#include "afb-export.h"
#include "verbose.h"

/*
 * names of symbols
 */
static const char afb_api_so_vdyn_entry[] = "afbBindingVdyn";

static int preinit(void *closure, struct afb_api_x3 *api)
{
	int (*entry)(struct afb_api_x3*) = closure;
	return entry(api);
}

int afb_api_so_vdyn_add(const char *path, void *handle, struct afb_apiset *declare_set, struct afb_apiset * call_set)
{
	int (*entry)(struct afb_api_x3*);
	struct afb_export *export;

	entry = dlsym(handle, afb_api_so_vdyn_entry);
	if (!entry)
		return 0;

	INFO("binding [%s] looks like an AFB binding Vdyn", path);

	export = afb_export_create_none_for_path(declare_set, call_set, path, preinit, entry);
	if (!export) {
		INFO("binding [%s] creation failed", path);
		return -1;
	}

	return 1;
}

#endif

