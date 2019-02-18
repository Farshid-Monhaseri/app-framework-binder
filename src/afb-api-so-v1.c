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

#if WITH_LEGACY_BINDING_V1

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <assert.h>
#include <stdarg.h>

#include <json-c/json.h>
#include <afb/afb-binding-v1.h>

#include "afb-api.h"
#include "afb-api-so-v1.h"
#include "afb-apiset.h"
#include "afb-export.h"
#include "afb-common.h"
#include "afb-context.h"
#include "afb-api-so.h"
#include "afb-xreq.h"
#include "verbose.h"

/*
 * names of symbols
 */
static const char afb_api_so_v1_register[] = "afbBindingV1Register";
static const char afb_api_so_v1_service_init[] = "afbBindingV1ServiceInit";
static const char afb_api_so_v1_service_event[] = "afbBindingV1ServiceEvent";

static const struct afb_verb_desc_v1 *search(struct afb_binding_v1 *binding, const char *name)
{
	const struct afb_verb_desc_v1 *verb;

	verb = binding->v1.verbs;
	while (verb->name && strcasecmp(verb->name, name))
		verb++;
	return verb->name ? verb : NULL;
}

void afb_api_so_v1_process_call(struct afb_binding_v1 *binding, struct afb_xreq *xreq)
{
	const struct afb_verb_desc_v1 *verb;

	verb = search(binding, xreq->request.called_verb);
	afb_xreq_call_verb_v1(xreq, verb);
}

static struct json_object *addperm(struct json_object *o, struct json_object *x)
{
	struct json_object *a;

	if (!o)
		return x;

	if (!json_object_object_get_ex(o, "allOf", &a)) {
		a = json_object_new_array();
		json_object_array_add(a, o);
		o = json_object_new_object();
		json_object_object_add(o, "allOf", a);
	}
	json_object_array_add(a, x);
	return o;
}

static struct json_object *addperm_key_val(struct json_object *o, const char *key, struct json_object *val)
{
	struct json_object *x = json_object_new_object();
	json_object_object_add(x, key, val);
	return addperm(o, x);
}

static struct json_object *addperm_key_valstr(struct json_object *o, const char *key, const char *val)
{
	return addperm_key_val(o, key, json_object_new_string(val));
}

static struct json_object *addperm_key_valint(struct json_object *o, const char *key, int val)
{
	return addperm_key_val(o, key, json_object_new_int(val));
}

struct json_object *afb_api_so_v1_make_description_openAPIv3(struct afb_binding_v1 *binding, const char *apiname)
{
	char buffer[256];
	const struct afb_verb_desc_v1 *verb;
	struct json_object *r, *f, *a, *i, *p, *g;

	r = json_object_new_object();
	json_object_object_add(r, "openapi", json_object_new_string("3.0.0"));

	i = json_object_new_object();
	json_object_object_add(r, "info", i);
	json_object_object_add(i, "title", json_object_new_string(apiname));
	json_object_object_add(i, "version", json_object_new_string("0.0.0"));
	json_object_object_add(i, "description", json_object_new_string(binding->v1.info ?: apiname));

	p = json_object_new_object();
	json_object_object_add(r, "paths", p);
	verb = binding->v1.verbs;
	while (verb->name) {
		buffer[0] = '/';
		strncpy(buffer + 1, verb->name, sizeof buffer - 1);
		buffer[sizeof buffer - 1] = 0;
		f = json_object_new_object();
		json_object_object_add(p, buffer, f);
		g = json_object_new_object();
		json_object_object_add(f, "get", g);

		a = NULL;
		if (verb->session & AFB_SESSION_CLOSE_X1)
			a = addperm_key_valstr(a, "session", "close");
		if (verb->session & AFB_SESSION_CHECK_X1)
			a = addperm_key_valstr(a, "session", "check");
		if (verb->session & AFB_SESSION_RENEW_X1)
			a = addperm_key_valstr(a, "token", "refresh");
		if (verb->session & AFB_SESSION_LOA_MASK_X1)
			a = addperm_key_valint(a, "LOA", (verb->session >> AFB_SESSION_LOA_SHIFT_X1) & AFB_SESSION_LOA_MASK_X1);
		if (a)
			json_object_object_add(g, "x-permissions", a);

		a = json_object_new_object();
		json_object_object_add(g, "responses", a);
		f = json_object_new_object();
		json_object_object_add(a, "200", f);
		json_object_object_add(f, "description", json_object_new_string(verb->info));
		verb++;
	}
	return r;
}

int afb_api_so_v1_add(const char *path, void *handle, struct afb_apiset *declare_set, struct afb_apiset * call_set)
{
	struct afb_binding_v1 *binding;	/* descriptor */
	struct afb_binding_v1 *(*register_function) (const struct afb_binding_interface_v1 *interface);
	int (*init)(struct afb_service_x1 service);
	void (*onevent)(const char *event, struct json_object *object);
	struct afb_export *export;

	/* retrieves the register function */
	register_function = dlsym(handle, afb_api_so_v1_register);
	if (!register_function)
		return 0;

	INFO("binding [%s] is a valid AFB binding V1", path);

	/* allocates the description */
	init = dlsym(handle, afb_api_so_v1_service_init);
	onevent = dlsym(handle, afb_api_so_v1_service_event);
	export = afb_export_create_v1(declare_set, call_set, path, init, onevent, path);
	if (export == NULL) {
		ERROR("binding [%s] creation failure...", path);
		goto error;
	}
	binding = afb_export_register_v1(export, register_function);
	if (binding == NULL) {
		ERROR("binding [%s] register failure...", path);
		goto error;
	}

	/* check the returned structure */
	if (binding->type != AFB_BINDING_VERSION_1) {
		ERROR("binding [%s] invalid type %d...", path, binding->type);
		goto error;
	}
	if (binding->v1.prefix == NULL || *binding->v1.prefix == 0) {
		ERROR("binding [%s] bad prefix...", path);
		goto error;
	}
	if (!afb_api_is_valid_name(binding->v1.prefix)) {
		ERROR("binding [%s] invalid prefix...", path);
		goto error;
	}
	if (binding->v1.info == NULL || *binding->v1.info == 0) {
		ERROR("binding [%s] bad description...", path);
		goto error;
	}
	if (binding->v1.verbs == NULL) {
		ERROR("binding [%s] no verbs...", path);
		goto error;
	}

	/* records the binding */
	if (!strcmp(path, afb_export_apiname(export))) {
		if (afb_export_rename(export, binding->v1.prefix) < 0) {
			ERROR("binding [%s] can't be renamed to %s", path, binding->v1.prefix);
			goto error;
		}
	}

	if (afb_export_declare(export, 0) < 0) {
		ERROR("binding [%s] can't be registered...", path);
		goto error;
	}
	INFO("binding %s loaded with API prefix %s", path, afb_export_apiname(export));
	afb_export_unref(export);
	return 1;

error:
	afb_export_unref(export);

	return -1;
}

#endif

