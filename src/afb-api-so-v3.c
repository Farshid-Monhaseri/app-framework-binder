/*
 * Copyright (C) 2018, 2019 "IoT.bzh"
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
#include <string.h>
#include <dlfcn.h>
#include <assert.h>
#include <stdarg.h>

#include <json-c/json.h>
#include <afb/afb-binding-v3.h>

#include "afb-api.h"
#include "afb-api-so-v3.h"
#include "afb-api-v3.h"
#include "afb-apiset.h"
#include "afb-export.h"
#include "verbose.h"

/*
 * names of symbols
 */
static const char afb_api_so_v3_desc[] = "afbBindingV3";
static const char afb_api_so_v3_root[] = "afbBindingV3root";
static const char afb_api_so_v3_entry[] = "afbBindingV3entry";

struct args
{
	struct afb_api_x3 **root;
	const struct afb_binding_v3 *desc;
	int (*entry)(struct afb_api_x3 *);
};

static int init(void *closure, struct afb_api_x3 *api)
{
	const struct args *a = closure;
	int rc = 0;

	*a->root = api;
	if (a->desc) {
		api->userdata = a->desc->userdata;
		rc = afb_api_v3_set_binding_fields(a->desc, api);
	}

	if (rc >= 0 && a->entry)
		rc = afb_api_v3_safe_preinit(api, a->entry);

	if (rc >= 0)
		afb_api_x3_seal(api);

	return rc;
}

int afb_api_so_v3_add(const char *path, void *handle, struct afb_apiset *declare_set, struct afb_apiset * call_set)
{
	struct args a;
	struct afb_api_v3 *api;
	struct afb_export *export;

	/* retrieves the register function */
	a.root = dlsym(handle, afb_api_so_v3_root);
	a.desc = dlsym(handle, afb_api_so_v3_desc);
	a.entry = dlsym(handle, afb_api_so_v3_entry);
	if (!a.root && !a.desc && !a.entry)
		return 0;

	INFO("binding [%s] looks like an AFB binding V3", path);

	/* basic checks */
	if (!a.root) {
		ERROR("binding [%s] incomplete symbol set: %s is missing",
			path, afb_api_so_v3_root);
		goto error;
	}
	if (a.desc) {
		if (a.desc->api == NULL || *a.desc->api == 0) {
			ERROR("binding [%s] bad api name...", path);
			goto error;
		}
		if (!afb_api_is_valid_name(a.desc->api)) {
			ERROR("binding [%s] invalid api name...", path);
			goto error;
		}
		if (!a.entry)
			a.entry = a.desc->preinit;
		else if (a.desc->preinit) {
			ERROR("binding [%s] clash: you can't define %s and %s.preinit, choose only one",
				path, afb_api_so_v3_entry, afb_api_so_v3_desc);
			goto error;
		}

		api = afb_api_v3_create(declare_set, call_set, a.desc->api, a.desc->info, a.desc->noconcurrency, init, &a, 0, NULL, path);
		if (api)
			return 1;
	} else {
		if (!a.entry) {
			ERROR("binding [%s] incomplete symbol set: %s is missing",
				path, afb_api_so_v3_entry);
			goto error;
		}

		export = afb_export_create_none_for_path(declare_set, call_set, path, init, &a);
		if (export) {
			/*
			 *  No call is done to afb_export_unref(export) because:
			 *   - legacy applications may use the root API emitting messages
			 *   - it allows writting applications like bindings without API
			 *  But this has the sad effect to introduce a kind of leak.
			 *  To avoid this, if necessary further developement should list bindings
			 *  and their data.
			 */
			return 1;
		}
	}

	ERROR("binding [%s] initialisation failed", path);

error:
	return -1;
}

