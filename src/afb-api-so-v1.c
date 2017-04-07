/*
 * Copyright (C) 2016, 2017 "IoT.bzh"
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
#define NO_BINDING_VERBOSE_MACRO

#include <string.h>
#include <dlfcn.h>
#include <assert.h>

#include <afb/afb-binding.h>

#include "afb-apis.h"
#include "afb-svc.h"
#include "afb-evt.h"
#include "afb-common.h"
#include "afb-context.h"
#include "afb-api-so.h"
#include "afb-xreq.h"
#include "afb-ditf.h"
#include "verbose.h"

/*
 * names of symbols
 */
static const char afb_api_so_v1_register[] = "afbBindingV1Register";
static const char afb_api_so_v1_service_init[] = "afbBindingV1ServiceInit";
static const char afb_api_so_v1_service_event[] = "afbBindingV1ServiceEvent";

/*
 * Description of a binding
 */
struct api_so_v1 {
	struct afb_binding *binding;	/* descriptor */
	void *handle;			/* context of dlopen */
	struct afb_svc *service;	/* handler for service started */
	struct afb_ditf ditf;		/* daemon interface */
};

static const struct afb_verb_desc_v1 *search(struct api_so_v1 *desc, const char *name)
{
	const struct afb_verb_desc_v1 *verb;

	verb = desc->binding->v1.verbs;
	while (verb->name && strcasecmp(verb->name, name))
		verb++;
	return verb->name ? verb : NULL;
}

static void call_cb(void *closure, struct afb_xreq *xreq)
{
	const struct afb_verb_desc_v1 *verb;
	struct api_so_v1 *desc = closure;

	verb = search(desc, xreq->verb);
	if (!verb)
		afb_xreq_fail_f(xreq, "unknown-verb", "verb %s unknown within api %s", xreq->verb, desc->binding->v1.prefix);
	else
		afb_xreq_call(xreq, verb->session, verb->callback);
}

static int service_start_cb(void *closure, int share_session, int onneed)
{
	int (*init)(struct afb_service service);
	void (*onevent)(const char *event, struct json_object *object);

	struct api_so_v1 *desc = closure;

	/* check state */
	if (desc->service != NULL) {
		/* not an error when onneed */
		if (onneed != 0)
			return 0;

		/* already started: it is an error */
		ERROR("Service %s already started", desc->binding->v1.prefix);
		return -1;
	}

	/* get the initialisation */
	init = dlsym(desc->handle, afb_api_so_v1_service_init);
	if (init == NULL) {
		/* not an error when onneed */
		if (onneed != 0)
			return 0;

		/* no initialisation method */
		ERROR("Binding %s is not a service", desc->binding->v1.prefix);
		return -1;
	}

	/* get the event handler if any */
	onevent = dlsym(desc->handle, afb_api_so_v1_service_event);
	desc->service = afb_svc_create(share_session, init, onevent);
	if (desc->service == NULL) {
		/* starting error */
		ERROR("Starting service %s failed", desc->binding->v1.prefix);
		return -1;
	}

	return 0;
}

int afb_api_so_v1_add(const char *path, void *handle)
{
	struct api_so_v1 *desc;
	struct afb_binding *(*register_function) (const struct afb_binding_interface *interface);

	/* retrieves the register function */
	register_function = dlsym(handle, afb_api_so_v1_register);
	if (!register_function)
		return 0;
	INFO("binding [%s] is a valid AFB binding V1", path);

	/* allocates the description */
	desc = calloc(1, sizeof *desc);
	if (desc == NULL) {
		ERROR("out of memory");
		goto error;
	}
	desc->handle = handle;

	/* init the interface */
	afb_ditf_init(&desc->ditf, path);

	/* init the binding */
	NOTICE("binding [%s] calling registering function %s", path, afb_api_so_v1_register);
	desc->binding = register_function(&desc->ditf.interface);
	if (desc->binding == NULL) {
		ERROR("binding [%s] register function failed. continuing...", path);
		goto error2;
	}

	/* check the returned structure */
	if (desc->binding->type != AFB_BINDING_VERSION_1) {
		ERROR("binding [%s] invalid type %d...", path, desc->binding->type);
		goto error2;
	}
	if (desc->binding->v1.prefix == NULL || *desc->binding->v1.prefix == 0) {
		ERROR("binding [%s] bad prefix...", path);
		goto error2;
	}
	if (!afb_apis_is_valid_api_name(desc->binding->v1.prefix)) {
		ERROR("binding [%s] invalid prefix...", path);
		goto error2;
	}
	if (desc->binding->v1.info == NULL || *desc->binding->v1.info == 0) {
		ERROR("binding [%s] bad description...", path);
		goto error2;
	}
	if (desc->binding->v1.verbs == NULL) {
		ERROR("binding [%s] no APIs...", path);
		goto error2;
	}

	/* records the binding */
	afb_ditf_rename(&desc->ditf, desc->binding->v1.prefix);
	if (afb_apis_add(desc->binding->v1.prefix, (struct afb_api){
			.closure = desc,
			.call = call_cb,
			.service_start = service_start_cb }) < 0) {
		ERROR("binding [%s] can't be registered...", path);
		goto error2;
	}
	NOTICE("binding %s loaded with API prefix %s", path, desc->binding->v1.prefix);
	return 1;

error2:
	free(desc);
error:
	return -1;
}
