/*
 * Copyright (C) 2017-2019 "IoT.bzh"
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

#pragma once

#include <stdarg.h>
#include <afb/afb-req-x1-itf.h>
#include <afb/afb-req-x2-itf.h>
#include "afb-context.h"

struct json_object;
struct afb_evt_listener;
struct afb_xreq;
struct afb_cred;
struct afb_apiset;
struct afb_event_x2;
struct afb_verb_desc_v1;
struct afb_verb_v2;
struct afb_verb_v3;
struct afb_req_x1;
struct afb_stored_req;

struct afb_xreq_query_itf {
	struct json_object *(*json)(struct afb_xreq *xreq);
	struct afb_arg (*get)(struct afb_xreq *xreq, const char *name);
	void (*reply)(struct afb_xreq *xreq, struct json_object *obj, const char *error, const char *info);
	void (*unref)(struct afb_xreq *xreq);
	int (*subscribe)(struct afb_xreq *xreq, struct afb_event_x2 *event);
	int (*unsubscribe)(struct afb_xreq *xreq, struct afb_event_x2 *event);
};

/**
 * Internal data for requests
 */
struct afb_xreq
{
	struct afb_req_x2 request;	/**< exported request */
	struct afb_context context;	/**< context of the request */
	struct afb_apiset *apiset;	/**< apiset of the xreq */
	struct json_object *json;	/**< the json object (or NULL) */
	const struct afb_xreq_query_itf *queryitf; /**< interface of xreq implementation functions */
	int refcount;			/**< current ref count */
	int replied;			/**< is replied? */
#if WITH_AFB_HOOK
	int hookflags;			/**< flags for hooking */
	int hookindex;			/**< hook index of the request if hooked */
#endif
	struct afb_cred *cred;		/**< client credential if revelant */
	struct afb_xreq *caller;	/**< caller request if any */
};

/**
 * Macro for retrieve the pointer of a structure of 'type' having a field named 'field'
 * of address 'ptr'.
 * @param type the type that has the 'field' (ex: "struct mystruct")
 * @param field the name of the field within the structure 'type'
 * @param ptr the pointer to an element 'field'
 * @return the pointer to the structure that contains the 'field' at address 'ptr'
 */
#define CONTAINER_OF(type,field,ptr) ((type*)(((char*)(ptr))-((char*)&(((type*)NULL)->field))))

/**
 * Macro for retrieve the pointer of a structure of 'type' having a field named "xreq"
 * of address 'x'.
 * @param type the type that has the field "xreq" (ex: "struct mystruct")
 * @param x the pointer to the field "xreq"
 * @return the pointer to the structure that contains the field "xreq" of address 'x'
 */
#define CONTAINER_OF_XREQ(type,x) CONTAINER_OF(type,xreq,x)

/* req wrappers for xreq */
extern struct afb_req_x1 afb_xreq_unstore(struct afb_stored_req *sreq);

extern void afb_xreq_addref(struct afb_xreq *xreq);
extern void afb_xreq_unref(struct afb_xreq *xreq);
extern void afb_xreq_unhooked_addref(struct afb_xreq *xreq);
extern void afb_xreq_unhooked_unref(struct afb_xreq *xreq);

extern struct json_object *afb_xreq_unhooked_json(struct afb_xreq *xreq);
extern struct json_object *afb_xreq_json(struct afb_xreq *xreq);

extern void afb_xreq_reply(struct afb_xreq *xreq, struct json_object *obj, const char *error, const char *info);
extern void afb_xreq_reply_f(struct afb_xreq *xreq, struct json_object *obj, const char *error, const char *info, ...);

extern int afb_xreq_reply_unknown_api(struct afb_xreq *xreq);
extern int afb_xreq_reply_unknown_verb(struct afb_xreq *xreq);

extern int afb_xreq_reply_invalid_token(struct afb_xreq *xreq);
extern int afb_xreq_reply_insufficient_scope(struct afb_xreq *xreq, const char *scope);


extern const char *afb_xreq_raw(struct afb_xreq *xreq, size_t *size);

extern int afb_xreq_subscribe(struct afb_xreq *xreq, struct afb_event_x2 *event);
extern int afb_xreq_unsubscribe(struct afb_xreq *xreq, struct afb_event_x2 *event);

extern void afb_xreq_legacy_subcall(
		struct afb_xreq *xreq,
		const char *api,
		const char *verb,
		struct json_object *args,
		void (*callback)(void*, int, struct json_object*, struct afb_req_x2 *),
		void *cb_closure);
extern void afb_xreq_unhooked_legacy_subcall(
		struct afb_xreq *xreq,
		const char *api,
		const char *verb,
		struct json_object *args,
		void (*callback)(void*, int, struct json_object*, struct afb_req_x2 *),
		void *cb_closure);

extern void afb_xreq_subcall(
		struct afb_xreq *xreq,
		const char *api,
		const char *verb,
		struct json_object *args,
		int flags,
		void (*callback)(void*, struct json_object*, const char*, const char*, struct afb_req_x2 *),
		void *closure);
extern void afb_xreq_unhooked_subcall(
		struct afb_xreq *xreq,
		const char *api,
		const char *verb,
		struct json_object *args,
		int flags,
		void (*callback)(void*, struct json_object*, const char*, const char*, struct afb_req_x2 *),
		void *closure);

extern int afb_xreq_unhooked_legacy_subcall_sync(
		struct afb_xreq *xreq,
		const char *api,
		const char *verb,
		struct json_object *args,
		struct json_object **result);
extern int afb_xreq_legacy_subcall_sync(
		struct afb_xreq *xreq,
		const char *api,
		const char *verb,
		struct json_object *args,
		struct json_object **result);

/* initialisation and processing of xreq */
extern void afb_xreq_init(struct afb_xreq *xreq, const struct afb_xreq_query_itf *queryitf);

extern void afb_xreq_process(struct afb_xreq *xreq, struct afb_apiset *apiset);

#if WITH_LEGACY_BINDING_V1
extern void afb_xreq_call_verb_v1(struct afb_xreq *xreq, const struct afb_verb_desc_v1 *verb);
#endif
#if WITH_LEGACY_BINDING_V2
extern void afb_xreq_call_verb_v2(struct afb_xreq *xreq, const struct afb_verb_v2 *verb);
#endif

extern void afb_xreq_call_verb_v3(struct afb_xreq *xreq, const struct afb_verb_v3 *verb);

extern const char *xreq_on_behalf_cred_export(struct afb_xreq *xreq);

/******************************************************************************/

static inline struct afb_req_x1 xreq_to_req_x1(struct afb_xreq *xreq)
{
	return (struct afb_req_x1){ .itf = xreq->request.itf, .closure = &xreq->request };
}

static inline struct afb_req_x2 *xreq_to_req_x2(struct afb_xreq *xreq)
{
	return &xreq->request;
}

static inline struct afb_xreq *xreq_from_req_x2(struct afb_req_x2 *req)
{
	return CONTAINER_OF(struct afb_xreq, request, req);
}

