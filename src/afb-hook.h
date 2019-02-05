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

#pragma once

#include <stdarg.h>
#include <time.h>

struct req;
struct afb_context;
struct json_object;
struct afb_arg;
struct afb_event_x2;
struct afb_verb_v2;
struct afb_verb_v3;
struct afb_session;
struct afb_xreq;
struct afb_export;
struct afb_stored_req;
struct sd_bus;
struct sd_event;
struct afb_hook_xreq;
struct afb_hook_api;
struct afb_hook_evt;
struct afb_hook_session;
struct afb_hook_global;

/*********************************************************
* section hookid
*********************************************************/
struct afb_hookid
{
	unsigned id;		/* id of the hook event */
	struct timespec time;	/* time of the hook event */
};

/*********************************************************
* section hooking xreq
*********************************************************/

/* individual flags */
#define afb_hook_flag_req_begin			0x00000001
#define afb_hook_flag_req_end			0x00000002
#define afb_hook_flag_req_json			0x00000004
#define afb_hook_flag_req_get			0x00000008
#define afb_hook_flag_req_reply 		0x00000010
#define afb_hook_flag_req_get_client_info	0x00000020
#define afb_hook_flag_req_legacy_context_get	0x00000040
#define afb_hook_flag_req_legacy_context_set	0x00000080
#define afb_hook_flag_req_addref		0x00000100
#define afb_hook_flag_req_unref			0x00000200
#define afb_hook_flag_req_session_close		0x00000400
#define afb_hook_flag_req_session_set_LOA	0x00000800
#define afb_hook_flag_req_subscribe		0x00001000
#define afb_hook_flag_req_unsubscribe		0x00002000
#define afb_hook_flag_req_subcall		0x00004000
#define afb_hook_flag_req_subcall_result	0x00008000
#define afb_hook_flag_req_subcallsync		0x00010000
#define afb_hook_flag_req_subcallsync_result	0x00020000
#define afb_hook_flag_req_vverbose		0x00040000
#define afb_hook_flag_req_legacy_store		0x00080000
#define afb_hook_flag_req_legacy_unstore	0x00100000
#define afb_hook_flag_req_has_permission	0x00200000
#define afb_hook_flag_req_get_application_id	0x00400000
#define afb_hook_flag_req_context_make		0x00800000
#define afb_hook_flag_req_get_uid		0x01000000

/* common flags */
#define afb_hook_flags_req_life		(afb_hook_flag_req_begin|afb_hook_flag_req_end)
#define afb_hook_flags_req_args		(afb_hook_flag_req_json|afb_hook_flag_req_get)
#define afb_hook_flags_req_session	(afb_hook_flag_req_session_close|afb_hook_flag_req_session_set_LOA)
#define afb_hook_flags_req_event	(afb_hook_flag_req_subscribe|afb_hook_flag_req_unsubscribe)
#define afb_hook_flags_req_subcalls	(afb_hook_flag_req_subcall|afb_hook_flag_req_subcall_result\
					|afb_hook_flag_req_subcallsync|afb_hook_flag_req_subcallsync_result)
#define afb_hook_flags_req_security	(afb_hook_flag_req_has_permission|afb_hook_flag_req_get_application_id\
					|afb_hook_flag_req_get_uid|afb_hook_flag_req_get_client_info)

/* extra flags */
#define afb_hook_flags_req_ref		(afb_hook_flag_req_addref|afb_hook_flag_req_unref)
#define afb_hook_flags_req_context	(afb_hook_flag_req_legacy_context_get|afb_hook_flag_req_legacy_context_set\
					|afb_hook_flag_req_context_make)
#define afb_hook_flags_req_stores	(afb_hook_flag_req_legacy_store|afb_hook_flag_req_legacy_unstore)

/* predefined groups */
#define afb_hook_flags_req_common	(afb_hook_flags_req_life|afb_hook_flags_req_args|afb_hook_flag_req_reply\
					|afb_hook_flags_req_session|afb_hook_flags_req_event|afb_hook_flags_req_subcalls\
					|afb_hook_flag_req_vverbose|afb_hook_flags_req_security)
#define afb_hook_flags_req_extra	(afb_hook_flags_req_common|afb_hook_flags_req_ref|afb_hook_flags_req_context\
					|afb_hook_flags_req_stores)
#define afb_hook_flags_req_all		(afb_hook_flags_req_extra)

struct afb_hook_xreq_itf {
	void (*hook_xreq_begin)(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq);
	void (*hook_xreq_end)(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq);
	void (*hook_xreq_json)(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, struct json_object *obj);
	void (*hook_xreq_get)(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, const char *name, struct afb_arg arg);
	void (*hook_xreq_reply)(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, struct json_object *obj, const char *error, const char *info);
	void (*hook_xreq_legacy_context_get)(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, void *value);
	void (*hook_xreq_legacy_context_set)(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, void *value, void (*free_value)(void*));
	void (*hook_xreq_addref)(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq);
	void (*hook_xreq_unref)(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq);
	void (*hook_xreq_session_close)(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq);
	void (*hook_xreq_session_set_LOA)(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, unsigned level, int result);
	void (*hook_xreq_subscribe)(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, struct afb_event_x2 *event_x2, int result);
	void (*hook_xreq_unsubscribe)(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, struct afb_event_x2 *event_x2, int result);
	void (*hook_xreq_subcall)(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, const char *api, const char *verb, struct json_object *args);
	void (*hook_xreq_subcall_result)(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, struct json_object *object, const char *error, const char *info);
	void (*hook_xreq_subcallsync)(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, const char *api, const char *verb, struct json_object *args);
	void (*hook_xreq_subcallsync_result)(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, int status, struct json_object *object, const char *error, const char *info);
	void (*hook_xreq_vverbose)(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, int level, const char *file, int line, const char *func, const char *fmt, va_list args);
	void (*hook_xreq_legacy_store)(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, struct afb_stored_req *sreq);
	void (*hook_xreq_legacy_unstore)(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq);
	void (*hook_xreq_has_permission)(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, const char *permission, int result);
	void (*hook_xreq_get_application_id)(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, char *result);
	void (*hook_xreq_context_make)(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, int replace, void *(*create_value)(void*), void (*free_value)(void*), void *create_closure, void *result);
	void (*hook_xreq_get_uid)(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, int result);
	void (*hook_xreq_get_client_info)(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, struct json_object *result);
};

extern void afb_hook_init_xreq(struct afb_xreq *xreq);

extern struct afb_hook_xreq *afb_hook_create_xreq(const char *api, const char *verb, struct afb_session *session, int flags, struct afb_hook_xreq_itf *itf, void *closure);
extern struct afb_hook_xreq *afb_hook_addref_xreq(struct afb_hook_xreq *spec);
extern void afb_hook_unref_xreq(struct afb_hook_xreq *spec);

/* hooks for xreq */
extern void afb_hook_xreq_begin(const struct afb_xreq *xreq);
extern void afb_hook_xreq_end(const struct afb_xreq *xreq);
extern struct json_object *afb_hook_xreq_json(const struct afb_xreq *xreq, struct json_object *obj);
extern struct afb_arg afb_hook_xreq_get(const struct afb_xreq *xreq, const char *name, struct afb_arg arg);
extern void afb_hook_xreq_reply(const struct afb_xreq *xreq, struct json_object *obj, const char *error, const char *info);
extern void *afb_hook_xreq_legacy_context_get(const struct afb_xreq *xreq, void *value);
extern void afb_hook_xreq_legacy_context_set(const struct afb_xreq *xreq, void *value, void (*free_value)(void*));
extern void afb_hook_xreq_addref(const struct afb_xreq *xreq);
extern void afb_hook_xreq_unref(const struct afb_xreq *xreq);
extern void afb_hook_xreq_session_close(const struct afb_xreq *xreq);
extern int afb_hook_xreq_session_set_LOA(const struct afb_xreq *xreq, unsigned level, int result);
extern int afb_hook_xreq_subscribe(const struct afb_xreq *xreq, struct afb_event_x2 *event_x2, int result);
extern int afb_hook_xreq_unsubscribe(const struct afb_xreq *xreq, struct afb_event_x2 *event_x2, int result);
extern void afb_hook_xreq_subcall(const struct afb_xreq *xreq, const char *api, const char *verb, struct json_object *args, int flags);
extern void afb_hook_xreq_subcall_result(const struct afb_xreq *xreq, struct json_object *object, const char *error, const char *info);
extern void afb_hook_xreq_subcallsync(const struct afb_xreq *xreq, const char *api, const char *verb, struct json_object *args, int flags);
extern int afb_hook_xreq_subcallsync_result(const struct afb_xreq *xreq, int status, struct json_object *object, const char *error, const char *info);
extern void afb_hook_xreq_vverbose(const struct afb_xreq *xreq, int level, const char *file, int line, const char *func, const char *fmt, va_list args);
extern void afb_hook_xreq_legacy_store(const struct afb_xreq *xreq, struct afb_stored_req *sreq);
extern void afb_hook_xreq_legacy_unstore(const struct afb_xreq *xreq);
extern int afb_hook_xreq_has_permission(const struct afb_xreq *xreq, const char *permission, int result);
extern char *afb_hook_xreq_get_application_id(const struct afb_xreq *xreq, char *result);
extern void *afb_hook_xreq_context_make(const struct afb_xreq *xreq, int replace, void *(*create_value)(void*), void (*free_value)(void*), void *create_closure, void *result);
extern int afb_hook_xreq_get_uid(const struct afb_xreq *xreq, int result);
extern struct json_object *afb_hook_xreq_get_client_info(const struct afb_xreq *xreq, struct json_object *result);

/*********************************************************
* section hooking apis
*********************************************************/

#define afb_hook_flag_api_vverbose			0x00000001
#define afb_hook_flag_api_get_event_loop		0x00000002
#define afb_hook_flag_api_get_user_bus			0x00000004
#define afb_hook_flag_api_get_system_bus		0x00000008
#define afb_hook_flag_api_rootdir_get_fd		0x00000010
#define afb_hook_flag_api_rootdir_open_locale		0x00000020
#define afb_hook_flag_api_queue_job			0x00000040
#define afb_hook_flag_api_require_api			0x00000080
#define afb_hook_flag_api_add_alias			0x00000100
#define afb_hook_flag_api_event_broadcast		0x00000200
#define afb_hook_flag_api_event_make			0x00000400
#define afb_hook_flag_api_new_api			0x00000800
#define afb_hook_flag_api_api_set_verbs			0x00001000
#define afb_hook_flag_api_api_add_verb			0x00002000
#define afb_hook_flag_api_api_del_verb			0x00004000
#define afb_hook_flag_api_api_set_on_event		0x00008000
#define afb_hook_flag_api_api_set_on_init		0x00010000
#define afb_hook_flag_api_api_seal			0x00020000
#define afb_hook_flag_api_event_handler_add		0x00040000
#define afb_hook_flag_api_event_handler_del		0x00080000
#define afb_hook_flag_api_call				0x00100000
#define afb_hook_flag_api_callsync			0x00200000
#define afb_hook_flag_api_class_provide			0x00400000
#define afb_hook_flag_api_class_require			0x00800000
#define afb_hook_flag_api_delete_api			0x01000000
#define afb_hook_flag_api_start				0x02000000
#define afb_hook_flag_api_on_event			0x04000000
#define afb_hook_flag_api_legacy_unstore_req		0x08000000
#define afb_hook_flag_api_on_event_handler		0x10000000
#define afb_hook_flag_api_settings			0x20000000

/* common flags */
/* extra flags */
/* predefined groups */

#define afb_hook_flags_api_common	(afb_hook_flag_api_vverbose\
					|afb_hook_flag_api_event_broadcast\
					|afb_hook_flag_api_event_make\
					|afb_hook_flag_api_call\
					|afb_hook_flag_api_callsync\
					|afb_hook_flag_api_start\
					|afb_hook_flag_api_queue_job\
					|afb_hook_flag_api_settings)


#define afb_hook_flags_api_extra	(afb_hook_flag_api_get_event_loop\
					|afb_hook_flag_api_get_user_bus\
					|afb_hook_flag_api_get_system_bus\
					|afb_hook_flag_api_rootdir_get_fd\
					|afb_hook_flag_api_rootdir_open_locale\
					|afb_hook_flag_api_legacy_unstore_req)


#define afb_hook_flags_api_api		(afb_hook_flag_api_new_api\
					|afb_hook_flag_api_api_set_verbs\
					|afb_hook_flag_api_api_add_verb\
					|afb_hook_flag_api_api_del_verb\
					|afb_hook_flag_api_api_set_on_event\
					|afb_hook_flag_api_api_set_on_init\
					|afb_hook_flag_api_api_seal\
					|afb_hook_flag_api_class_provide\
					|afb_hook_flag_api_class_require\
					|afb_hook_flag_api_require_api\
					|afb_hook_flag_api_add_alias\
					|afb_hook_flag_api_delete_api)

#define afb_hook_flags_api_event	(afb_hook_flag_api_event_broadcast\
					|afb_hook_flag_api_event_make\
					|afb_hook_flag_api_event_handler_add\
					|afb_hook_flag_api_event_handler_del\
					|afb_hook_flag_api_on_event\
					|afb_hook_flag_api_on_event_handler)

#define afb_hook_flags_api_all		(afb_hook_flags_api_common\
					|afb_hook_flags_api_extra\
					|afb_hook_flags_api_api\
					|afb_hook_flags_api_event)

/*********************************************************
*********************************************************/
#define afb_hook_flags_api_svc_all	(afb_hook_flag_api_start|afb_hook_flag_api_start\
					|afb_hook_flag_api_on_event|afb_hook_flag_api_on_event\
					|afb_hook_flag_api_call|afb_hook_flag_api_call\
					|afb_hook_flag_api_callsync|afb_hook_flag_api_callsync)

#define afb_hook_flags_api_ditf_common	(afb_hook_flag_api_vverbose\
					|afb_hook_flag_api_event_make\
					|afb_hook_flag_api_event_broadcast\
					|afb_hook_flag_api_event_broadcast\
					|afb_hook_flag_api_add_alias)

#define afb_hook_flags_api_ditf_extra	(afb_hook_flag_api_get_event_loop\
					|afb_hook_flag_api_get_user_bus\
					|afb_hook_flag_api_get_system_bus\
					|afb_hook_flag_api_rootdir_get_fd\
					|afb_hook_flag_api_rootdir_open_locale\
					|afb_hook_flag_api_queue_job\
					|afb_hook_flag_api_legacy_unstore_req\
					|afb_hook_flag_api_require_api\
					|afb_hook_flag_api_require_api)

#define afb_hook_flags_api_ditf_all	(afb_hook_flags_api_ditf_common|afb_hook_flags_api_ditf_extra)
/*********************************************************
*********************************************************/


struct afb_hook_api_itf {
	void (*hook_api_event_broadcast_before)(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, const char *name, struct json_object *object);
	void (*hook_api_event_broadcast_after)(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, const char *name, struct json_object *object, int result);
	void (*hook_api_get_event_loop)(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, struct sd_event *result);
	void (*hook_api_get_user_bus)(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, struct sd_bus *result);
	void (*hook_api_get_system_bus)(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, struct sd_bus *result);
	void (*hook_api_vverbose)(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, int level, const char *file, int line, const char *function, const char *fmt, va_list args);
	void (*hook_api_event_make)(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, const char *name, struct afb_event_x2 *result);
	void (*hook_api_rootdir_get_fd)(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, int result);
	void (*hook_api_rootdir_open_locale)(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, const char *filename, int flags, const char *locale, int result);
	void (*hook_api_queue_job)(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, void (*callback)(int signum, void *arg), void *argument, void *group, int timeout, int result);
	void (*hook_api_legacy_unstore_req)(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, struct afb_stored_req *sreq);
	void (*hook_api_require_api)(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, const char *name, int initialized);
	void (*hook_api_require_api_result)(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, const char *name, int initialized, int result);
	void (*hook_api_add_alias)(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, const char *oldname, const char *newname, int result);
	void (*hook_api_start_before)(void *closure, const struct afb_hookid *hookid, const struct afb_export *export);
	void (*hook_api_start_after)(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, int status);
	void (*hook_api_on_event_before)(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, const char *event, int event_x2, struct json_object *object);
	void (*hook_api_on_event_after)(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, const char *event, int event_x2, struct json_object *object);
	void (*hook_api_call)(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, const char *api, const char *verb, struct json_object *args);
	void (*hook_api_call_result)(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, struct json_object *object, const char *error, const char *info);
	void (*hook_api_callsync)(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, const char *api, const char *verb, struct json_object *args);
	void (*hook_api_callsync_result)(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, int result, struct json_object *object, const char *error, const char *info);
	void (*hook_api_new_api_before)(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, const char *api, const char *info, int noconcurrency);
	void (*hook_api_new_api_after)(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, int result, const char *api);
	void (*hook_api_api_set_verbs_v2)(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, int result, const struct afb_verb_v2 *verbs);
	void (*hook_api_api_set_verbs_v3)(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, int result, const struct afb_verb_v3 *verbs);
	void (*hook_api_api_add_verb)(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, int result, const char *verb, const char *info, int glob);
	void (*hook_api_api_del_verb)(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, int result, const char *verb);
	void (*hook_api_api_set_on_event)(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, int result);
	void (*hook_api_api_set_on_init)(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, int result);
	void (*hook_api_api_seal)(void *closure, const struct afb_hookid *hookid, const struct afb_export *export);
	void (*hook_api_event_handler_add)(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, int result, const char *pattern);
	void (*hook_api_event_handler_del)(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, int result, const char *pattern);
	void (*hook_api_class_provide)(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, int result, const char *name);
	void (*hook_api_class_require)(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, int result, const char *name);
	void (*hook_api_delete_api)(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, int result);
	void (*hook_api_on_event_handler_before)(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, const char *event, int event_x2, struct json_object *object, const char *pattern);
	void (*hook_api_on_event_handler_after)(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, const char *event, int event_x2, struct json_object *object, const char *pattern);
	void (*hook_api_settings)(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, struct json_object *object);
};

extern void afb_hook_api_event_broadcast_before(const struct afb_export *export, const char *name, struct json_object *object);
extern int afb_hook_api_event_broadcast_after(const struct afb_export *export, const char *name, struct json_object *object, int result);
extern struct sd_event *afb_hook_api_get_event_loop(const struct afb_export *export, struct sd_event *result);
extern struct sd_bus *afb_hook_api_get_user_bus(const struct afb_export *export, struct sd_bus *result);
extern struct sd_bus *afb_hook_api_get_system_bus(const struct afb_export *export, struct sd_bus *result);
extern void afb_hook_api_vverbose(const struct afb_export *export, int level, const char *file, int line, const char *function, const char *fmt, va_list args);
extern struct afb_event_x2 *afb_hook_api_event_make(const struct afb_export *export, const char *name, struct afb_event_x2 *result);
extern int afb_hook_api_rootdir_get_fd(const struct afb_export *export, int result);
extern int afb_hook_api_rootdir_open_locale(const struct afb_export *export, const char *filename, int flags, const char *locale, int result);
extern int afb_hook_api_queue_job(const struct afb_export *export, void (*callback)(int signum, void *arg), void *argument, void *group, int timeout, int result);
extern void afb_hook_api_legacy_unstore_req(const struct afb_export *export, struct afb_stored_req *sreq);
extern void afb_hook_api_require_api(const struct afb_export *export, const char *name, int initialized);
extern int afb_hook_api_require_api_result(const struct afb_export *export, const char *name, int initialized, int result);
extern int afb_hook_api_add_alias(const struct afb_export *export, const char *api, const char *alias, int result);
extern void afb_hook_api_start_before(const struct afb_export *export);
extern int afb_hook_api_start_after(const struct afb_export *export, int status);
extern void afb_hook_api_on_event_before(const struct afb_export *export, const char *event, int event_x2, struct json_object *object);
extern void afb_hook_api_on_event_after(const struct afb_export *export, const char *event, int event_x2, struct json_object *object);
extern void afb_hook_api_call(const struct afb_export *export, const char *api, const char *verb, struct json_object *args);
extern void afb_hook_api_call_result(const struct afb_export *export, struct json_object *object, const char *error, const char *info);
extern void afb_hook_api_callsync(const struct afb_export *export, const char *api, const char *verb, struct json_object *args);
extern int afb_hook_api_callsync_result(const struct afb_export *export, int result, struct json_object *object, const char *error, const char *info);
extern void afb_hook_api_new_api_before(const struct afb_export *export, const char *api, const char *info, int noconcurrency);
extern int afb_hook_api_new_api_after(const struct afb_export *export, int result, const char *api);
extern int afb_hook_api_api_set_verbs_v2(const struct afb_export *export, int result, const struct afb_verb_v2 *verbs);
extern int afb_hook_api_api_set_verbs_v3(const struct afb_export *export, int result, const struct afb_verb_v3 *verbs);
extern int afb_hook_api_api_add_verb(const struct afb_export *export, int result, const char *verb, const char *info, int glob);
extern int afb_hook_api_api_del_verb(const struct afb_export *export, int result, const char *verb);
extern int afb_hook_api_api_set_on_event(const struct afb_export *export, int result);
extern int afb_hook_api_api_set_on_init(const struct afb_export *export, int result);
extern void afb_hook_api_api_seal(const struct afb_export *export);
extern int afb_hook_api_event_handler_add(const struct afb_export *export, int result, const char *pattern);
extern int afb_hook_api_event_handler_del(const struct afb_export *export, int result, const char *pattern);
extern int afb_hook_api_class_provide(const struct afb_export *export, int result, const char *name);
extern int afb_hook_api_class_require(const struct afb_export *export, int result, const char *name);
extern int afb_hook_api_delete_api(const struct afb_export *export, int result);
extern void afb_hook_api_on_event_handler_before(const struct afb_export *export, const char *event, int event_x2, struct json_object *object, const char *pattern);
extern void afb_hook_api_on_event_handler_after(const struct afb_export *export, const char *event, int event_x2, struct json_object *object, const char *pattern);
extern struct json_object *afb_hook_api_settings(const struct afb_export *export, struct json_object *object);

extern int afb_hook_flags_api(const char *api);
extern struct afb_hook_api *afb_hook_create_api(const char *api, int flags, struct afb_hook_api_itf *itf, void *closure);
extern struct afb_hook_api *afb_hook_addref_api(struct afb_hook_api *hook);
extern void afb_hook_unref_api(struct afb_hook_api *hook);

/*********************************************************
* section hooking evt (event interface)
*********************************************************/

#define afb_hook_flag_evt_create			0x000001
#define afb_hook_flag_evt_push_before			0x000002
#define afb_hook_flag_evt_push_after			0x000004
#define afb_hook_flag_evt_broadcast_before		0x000008
#define afb_hook_flag_evt_broadcast_after		0x000010
#define afb_hook_flag_evt_name				0x000020
#define afb_hook_flag_evt_addref			0x000040
#define afb_hook_flag_evt_unref				0x000080

#define afb_hook_flags_evt_common	(afb_hook_flag_evt_push_before|afb_hook_flag_evt_broadcast_before)
#define afb_hook_flags_evt_extra	(afb_hook_flags_evt_common\
					|afb_hook_flag_evt_push_after|afb_hook_flag_evt_broadcast_after\
					|afb_hook_flag_evt_create\
					|afb_hook_flag_evt_addref|afb_hook_flag_evt_unref)
#define afb_hook_flags_evt_all		(afb_hook_flags_evt_extra|afb_hook_flag_evt_name)

struct afb_hook_evt_itf {
	void (*hook_evt_create)(void *closure, const struct afb_hookid *hookid, const char *evt, int id);
	void (*hook_evt_push_before)(void *closure, const struct afb_hookid *hookid, const char *evt, int id, struct json_object *obj);
	void (*hook_evt_push_after)(void *closure, const struct afb_hookid *hookid, const char *evt, int id, struct json_object *obj, int result);
	void (*hook_evt_broadcast_before)(void *closure, const struct afb_hookid *hookid, const char *evt, int id, struct json_object *obj);
	void (*hook_evt_broadcast_after)(void *closure, const struct afb_hookid *hookid, const char *evt, int id, struct json_object *obj, int result);
	void (*hook_evt_name)(void *closure, const struct afb_hookid *hookid, const char *evt, int id, const char *result);
	void (*hook_evt_addref)(void *closure, const struct afb_hookid *hookid, const char *evt, int id);
	void (*hook_evt_unref)(void *closure, const struct afb_hookid *hookid, const char *evt, int id);
};

extern void afb_hook_evt_create(const char *evt, int id);
extern void afb_hook_evt_push_before(const char *evt, int id, struct json_object *obj);
extern int afb_hook_evt_push_after(const char *evt, int id, struct json_object *obj, int result);
extern void afb_hook_evt_broadcast_before(const char *evt, int id, struct json_object *obj);
extern int afb_hook_evt_broadcast_after(const char *evt, int id, struct json_object *obj, int result);
extern void afb_hook_evt_name(const char *evt, int id, const char *result);
extern void afb_hook_evt_addref(const char *evt, int id);
extern void afb_hook_evt_unref(const char *evt, int id);

extern int afb_hook_flags_evt(const char *name);
extern struct afb_hook_evt *afb_hook_create_evt(const char *pattern, int flags, struct afb_hook_evt_itf *itf, void *closure);
extern struct afb_hook_evt *afb_hook_addref_evt(struct afb_hook_evt *hook);
extern void afb_hook_unref_evt(struct afb_hook_evt *hook);

/*********************************************************
* section hooking session (session interface)
*********************************************************/

#define afb_hook_flag_session_create			0x000001
#define afb_hook_flag_session_close			0x000002
#define afb_hook_flag_session_destroy			0x000004
#define afb_hook_flag_session_renew			0x000008
#define afb_hook_flag_session_addref			0x000010
#define afb_hook_flag_session_unref			0x000020

#define afb_hook_flags_session_common	(afb_hook_flag_session_create|afb_hook_flag_session_close\
					|afb_hook_flag_session_renew)
#define afb_hook_flags_session_all	(afb_hook_flags_session_common|afb_hook_flag_session_destroy\
					|afb_hook_flag_session_addref|afb_hook_flag_session_unref)

struct afb_hook_session_itf {
	void (*hook_session_create)(void *closure, const struct afb_hookid *hookid, struct afb_session *session);
	void (*hook_session_close)(void *closure, const struct afb_hookid *hookid, struct afb_session *session);
	void (*hook_session_destroy)(void *closure, const struct afb_hookid *hookid, struct afb_session *session);
	void (*hook_session_renew)(void *closure, const struct afb_hookid *hookid, struct afb_session *session);
	void (*hook_session_addref)(void *closure, const struct afb_hookid *hookid, struct afb_session *session);
	void (*hook_session_unref)(void *closure, const struct afb_hookid *hookid, struct afb_session *session);
};

extern void afb_hook_session_create(struct afb_session *session);
extern void afb_hook_session_close(struct afb_session *session);
extern void afb_hook_session_destroy(struct afb_session *session);
extern void afb_hook_session_renew(struct afb_session *session);
extern void afb_hook_session_addref(struct afb_session *session);
extern void afb_hook_session_unref(struct afb_session *session);

extern struct afb_hook_session *afb_hook_create_session(const char *pattern, int flags, struct afb_hook_session_itf *itf, void *closure);
extern struct afb_hook_session *afb_hook_addref_session(struct afb_hook_session *hook);
extern void afb_hook_unref_session(struct afb_hook_session *hook);

/*********************************************************
* section hooking global (global interface)
*********************************************************/

#define afb_hook_flag_global_vverbose			0x000001

#define afb_hook_flags_global_all	(afb_hook_flag_global_vverbose)

struct afb_hook_global_itf {
	void (*hook_global_vverbose)(void *closure, const struct afb_hookid *hookid, int level, const char *file, int line, const char *function, const char *fmt, va_list args);
};

extern struct afb_hook_global *afb_hook_create_global(int flags, struct afb_hook_global_itf *itf, void *closure);
extern struct afb_hook_global *afb_hook_addref_global(struct afb_hook_global *hook);
extern void afb_hook_unref_global(struct afb_hook_global *hook);


