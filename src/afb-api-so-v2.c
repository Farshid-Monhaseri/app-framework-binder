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

#if WITH_LEGACY_BINDING_V2 && WITH_DYNAMIC_BINDING

#define _GNU_SOURCE

#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <assert.h>
#include <stdarg.h>
#include <errno.h>

#include <json-c/json.h>
#include <afb/afb-binding-v2.h>

#include "afb-api.h"
#include "afb-api-so-v2.h"
#include "afb-apiset.h"
#include "afb-auth.h"
#include "afb-export.h"
#include "afb-evt.h"
#include "afb-context.h"
#include "afb-api-so.h"
#include "afb-xreq.h"
#include "sig-monitor.h"
#include "verbose.h"

/*
 * names of symbols
 */
static const char afb_api_so_v2_descriptor[] = "afbBindingV2";
static const char afb_api_so_v2_data[] = "afbBindingV2data";

struct preinit
{
	int return_code;
	const struct afb_binding_v2 *binding;
};

static const struct afb_verb_v2 *search(const struct afb_binding_v2 *binding, const char *name)
{
	const struct afb_verb_v2 *verb;

	verb = binding->verbs;
	while (verb->verb && strcasecmp(verb->verb, name))
		verb++;
	return verb->verb ? verb : NULL;
	return NULL;
}

void afb_api_so_v2_process_call(const struct afb_binding_v2 *binding, struct afb_xreq *xreq)
{
	const struct afb_verb_v2 *verb;

	verb = search(binding, xreq->request.called_verb);
	afb_xreq_call_verb_v2(xreq, verb);
}

struct json_object *afb_api_so_v2_make_description_openAPIv3(const struct afb_binding_v2 *binding, const char *apiname)
{
	char buffer[256];
	const struct afb_verb_v2 *verb;
	struct json_object *r, *f, *a, *i, *p, *g;
	enum json_tokener_error jerr;

	if (binding->specification) {
		r = json_tokener_parse_verbose(binding->specification, &jerr);
		if (jerr == json_tokener_success)
			return r;
	}

	r = json_object_new_object();
	json_object_object_add(r, "openapi", json_object_new_string("3.0.0"));

	i = json_object_new_object();
	json_object_object_add(r, "info", i);
	json_object_object_add(i, "title", json_object_new_string(apiname));
	json_object_object_add(i, "version", json_object_new_string("0.0.0"));
	json_object_object_add(i, "description", json_object_new_string(binding->info ?: apiname));

	p = json_object_new_object();
	json_object_object_add(r, "paths", p);
	verb = binding->verbs;
	while (verb->verb) {
		buffer[0] = '/';
		strncpy(buffer + 1, verb->verb, sizeof buffer - 1);
		buffer[sizeof buffer - 1] = 0;
		f = json_object_new_object();
		json_object_object_add(p, buffer, f);
		g = json_object_new_object();
		json_object_object_add(f, "get", g);

		a = afb_auth_json_v2(verb->auth, verb->session);
		if (a)
			json_object_object_add(g, "x-permissions", a);

		a = json_object_new_object();
		json_object_object_add(g, "responses", a);
		f = json_object_new_object();
		json_object_object_add(a, "200", f);
		json_object_object_add(f, "description", json_object_new_string(verb->info?:verb->verb));
		verb++;
	}
	return r;
}

static void do_preinit(int sig, void *closure)
{
	struct preinit *preinit = closure;

	if (!sig)
		preinit->return_code = preinit->binding->preinit();
	else {
		errno = EINTR;
		preinit->return_code = -1;
	}
};

int afb_api_so_v2_add_binding(
		const struct afb_binding_v2 *binding,
		void *handle,
		struct afb_apiset *declare_set,
		struct afb_apiset * call_set,
		struct afb_binding_data_v2 *data,
		const char *path)
{
	int rc;
	struct afb_export *export;
	struct preinit preinit;

	/* basic checks */
	assert(binding);
	assert(binding->api);
	assert(binding->verbs);
	assert(data);

	/* allocates the description */
	export = afb_export_create_v2(declare_set, call_set, binding->api, binding, data, binding->init, binding->onevent, path);
	if (!export) {
		ERROR("out of memory");
		goto error;
	}

	/* records the binding */
	if (afb_export_declare(export, binding->noconcurrency) < 0) {
		ERROR("binding %s can't be registered to set %s...", afb_export_apiname(export), afb_apiset_name(declare_set));
		goto error;
	}
	/* init the binding */
	if (binding->preinit) {
		INFO("binding %s calling preinit function", binding->api);
		preinit.binding = binding;
		sig_monitor(0, do_preinit, &preinit);
		rc = preinit.return_code;
		if (rc < 0) {
			ERROR("binding %s preinit function failed...", afb_export_apiname(export));
			afb_export_undeclare(export);
			goto error;
		}
	}

	INFO("binding %s added to set %s", afb_export_apiname(export), afb_apiset_name(declare_set));
	return 1;

error:
	afb_export_unref(export);

	return -1;
}

int afb_api_so_v2_add(const char *path, void *handle, struct afb_apiset *declare_set, struct afb_apiset * call_set)
{
	const struct afb_binding_v2 *binding;
	struct afb_binding_data_v2 *data;

	/* retrieves the register function */
	binding = dlsym(handle, afb_api_so_v2_descriptor);
	data = dlsym(handle, afb_api_so_v2_data);
	if (!binding && !data)
		return 0;

	INFO("binding [%s] looks like an AFB binding V2", path);

	/* basic checks */
	if (!binding || !data) {
		ERROR("binding [%s] incomplete symbol set: %s is missing",
			path, binding ? afb_api_so_v2_data : afb_api_so_v2_descriptor);
		goto error;
	}
	if (binding->api == NULL || *binding->api == 0) {
		ERROR("binding [%s] bad api name...", path);
		goto error;
	}
	if (!afb_api_is_valid_name(binding->api)) {
		ERROR("binding [%s] invalid api name...", path);
		goto error;
	}

	if (binding->verbs == NULL) {
		ERROR("binding [%s] no verbs...", path);
		goto error;
	}

	return afb_api_so_v2_add_binding(binding, handle, declare_set, call_set, data, path);

 error:
	return -1;
}

#endif
