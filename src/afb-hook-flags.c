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

#if WITH_AFB_HOOK  /***********************************************************/

#define _GNU_SOURCE

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "afb-hook.h"
#include "afb-hook-flags.h"

/* structure for searching flags by names */
struct flag
{
	const char *name;	/** the name */
	int value;		/** the value */
};

struct flags
{
	struct flag *flags;
	int count;
};

#define FLAGS(x)   ((struct flags){ .flags = x, .count = (int)(sizeof x / sizeof * x) })

static struct flag xreq_flags[] = { /* must be sorted by names */
		{ "addref",		afb_hook_flag_req_addref },
		{ "all",		afb_hook_flags_req_all },
		{ "args",		afb_hook_flags_req_args },
		{ "begin",		afb_hook_flag_req_begin },
		{ "common",		afb_hook_flags_req_common },
		{ "context",		afb_hook_flags_req_context },
		{ "context_get",	afb_hook_flag_req_legacy_context_get },
		{ "context_make",	afb_hook_flag_req_context_make },
		{ "context_set",	afb_hook_flag_req_legacy_context_set },
		{ "end",		afb_hook_flag_req_end },
		{ "event",		afb_hook_flags_req_event },
		{ "extra",		afb_hook_flags_req_extra },
		{ "get",		afb_hook_flag_req_get },
		{ "get_application_id",	afb_hook_flag_req_get_application_id },
		{ "get_client_info",	afb_hook_flag_req_get_client_info },
		{ "get_uid",		afb_hook_flag_req_get_uid },
		{ "has_permission",	afb_hook_flag_req_has_permission },
		{ "json",		afb_hook_flag_req_json },
		{ "life",		afb_hook_flags_req_life },
		{ "ref",		afb_hook_flags_req_ref },
		{ "reply",		afb_hook_flag_req_reply },
		{ "security",		afb_hook_flags_req_security },
		{ "session",		afb_hook_flags_req_session },
		{ "session_close",	afb_hook_flag_req_session_close },
		{ "session_set_LOA",	afb_hook_flag_req_session_set_LOA },
		{ "store",		afb_hook_flag_req_legacy_store },
		{ "stores",		afb_hook_flags_req_stores },
		{ "subcall",		afb_hook_flag_req_subcall },
		{ "subcall_result",	afb_hook_flag_req_subcall_result },
		{ "subcalls",		afb_hook_flags_req_subcalls },
		{ "subcallsync",	afb_hook_flag_req_subcallsync },
		{ "subcallsync_result",	afb_hook_flag_req_subcallsync_result },
		{ "subscribe",		afb_hook_flag_req_subscribe },
		{ "unref",		afb_hook_flag_req_unref },
		{ "unstore",		afb_hook_flag_req_legacy_unstore },
		{ "unsubscribe",	afb_hook_flag_req_unsubscribe },
		{ "vverbose",		afb_hook_flag_req_vverbose },
};

static struct flag api_flags[] = { /* must be sorted by names */
		{ "add_alias",		afb_hook_flag_api_add_alias },
		{ "all",		afb_hook_flags_api_all },
		{ "api_add_verb",	afb_hook_flag_api_api_add_verb },
		{ "api",		afb_hook_flags_api_api },
		{ "api_del_verb",	afb_hook_flag_api_api_del_verb },
		{ "api_seal",		afb_hook_flag_api_api_seal },
		{ "api_set_on_event",	afb_hook_flag_api_api_set_on_event },
		{ "api_set_on_init",	afb_hook_flag_api_api_set_on_init },
		{ "api_set_verbs",	afb_hook_flag_api_api_set_verbs },
		{ "call",		afb_hook_flag_api_call },
		{ "callsync",		afb_hook_flag_api_callsync },
		{ "class_provide",	afb_hook_flag_api_class_provide },
		{ "class_require",	afb_hook_flag_api_class_require },
		{ "common",		afb_hook_flags_api_common },
		{ "delete_api",		afb_hook_flag_api_delete_api },
		{ "event",		afb_hook_flags_api_event },
		{ "event_broadcast",	afb_hook_flag_api_event_broadcast },
		{ "event_handler_add",	afb_hook_flag_api_event_handler_add },
		{ "event_handler_del",	afb_hook_flag_api_event_handler_del },
		{ "event_make",		afb_hook_flag_api_event_make },
		{ "extra",		afb_hook_flags_api_extra },
		{ "get_event_loop",	afb_hook_flag_api_get_event_loop },
		{ "get_system_bus",	afb_hook_flag_api_get_system_bus },
		{ "get_user_bus",	afb_hook_flag_api_get_user_bus },
		{ "legacy_unstore_req",	afb_hook_flag_api_legacy_unstore_req },
		{ "new_api",		afb_hook_flag_api_new_api },
		{ "on_event",		afb_hook_flag_api_on_event },
		{ "on_event_handler",	afb_hook_flag_api_on_event_handler },
		{ "queue_job",		afb_hook_flag_api_queue_job },
		{ "require_api",	afb_hook_flag_api_require_api },
		{ "rootdir_get_fd",	afb_hook_flag_api_rootdir_get_fd },
		{ "rootdir_open_locale",afb_hook_flag_api_rootdir_open_locale },
		{ "settings",		afb_hook_flag_api_settings },
		{ "start",		afb_hook_flag_api_start },
		{ "vverbose",		afb_hook_flag_api_vverbose },
};

static struct flag evt_flags[] = { /* must be sorted by names */
		{ "addref",		afb_hook_flag_evt_addref },
		{ "all",		afb_hook_flags_evt_all },
		{ "broadcast_after",	afb_hook_flag_evt_broadcast_after },
		{ "broadcast_before",	afb_hook_flag_evt_broadcast_before },
		{ "common",		afb_hook_flags_evt_common },
		{ "create",		afb_hook_flag_evt_create },
		{ "extra",		afb_hook_flags_evt_extra },
		{ "name",		afb_hook_flag_evt_name },
		{ "push_after",		afb_hook_flag_evt_push_after },
		{ "push_before",	afb_hook_flag_evt_push_before },
		{ "unref",		afb_hook_flag_evt_unref },
};

static struct flag session_flags[] = { /* must be sorted by names */
		{ "addref",		afb_hook_flag_session_addref },
		{ "all",		afb_hook_flags_session_all },
		{ "close",		afb_hook_flag_session_close },
		{ "common",		afb_hook_flags_session_common },
		{ "create",		afb_hook_flag_session_create },
		{ "destroy",		afb_hook_flag_session_destroy },
		{ "renew",		afb_hook_flag_session_renew },
		{ "unref",		afb_hook_flag_session_unref },
};

static struct flag global_flags[] = { /* must be sorted by names */
		{ "all",		afb_hook_flags_global_all },
		{ "vverbose",		afb_hook_flag_global_vverbose },
};

static int compare(const char *query, const char *value, size_t query_length)
{
	size_t i;
	char q, v;

	for (i = 0 ; i < query_length ; i++) {
		v = value[i];
		q = query[i];
		if (!v)
			return -1;
		v = v == '_' ? '-' : (char)toupper(v);
		q = q == '_' ? '-' : (char)toupper(q);
		if (q != v)
			return (int)((unsigned)q - (unsigned)v);
	}
	return !!value[i];
}

/* get the value of the flag of 'name' in the array 'flags' of 'count elements */
static int get_flag(const char *name, struct flags flags, size_t length)
{
	/* replace "*" by "all" */
	if (length == 1 && *name == '*') {
		name = "all";
		length = 3;
	}

	/* dichotomic search */
	int lower = 0, upper = flags.count;
	while (lower < upper) {
		int mid = (lower + upper) >> 1;
		int cmp = compare(name, flags.flags[mid].name, length);
		if (!cmp)
			return flags.flags[mid].value;
		if (cmp < 0)
			upper = mid;
		else
			lower = mid + 1;
	}

	return -(compare(name, "no", length) && compare(name, "none", length));
}

static int from_text(const char *text, struct flags flags)
{
	static const char sep[] = " \t,";
	size_t s;
	int result = 0, val;

	if (text) {
		for (;;) {
			text += strspn(text, sep);
			if (!*text)
				break;
			s = strcspn(text, sep);
			val = get_flag(text, flags, s);
			if (val == -1)
				return val;
			result |= val;
			text += s;
		}
	}
	return result;
}

static char *to_text(int value, struct flags flags)
{
	int borrow = 0, mask = 0, i, v, imask;
	size_t s = 0;
	char *result = NULL;

	if (!value)
		return strdup("none");

	do {
		if (s) {
			result = malloc(s + 1);
			if (!result)
				break;
		}
		borrow = 0;
		while (borrow != value) {
			mask = imask = 0;
			i = flags.count;
			while (i) {
				v = flags.flags[--i].value;
				if ((mask & v) == mask && (borrow & v) == 0 && (value & v) == v) {
					mask = v;
					imask = i;
				}
			}
			if (mask == 0)
				borrow = value;
			else {
				if (!result)
					s += strlen(flags.flags[imask].name) + !!s;
				else {
					if (s)
						result[s++] = ',';
					strcpy(&result[s], flags.flags[imask].name);
					s += strlen(flags.flags[imask].name);
				}
			}
		}
	} while (!result);
	return result;
}

int afb_hook_flags_xreq_from_text(const char *text)
{
	return from_text(text, FLAGS(xreq_flags));
}

int afb_hook_flags_api_from_text(const char *text)
{
	return from_text(text, FLAGS(api_flags));
}

int afb_hook_flags_evt_from_text(const char *text)
{
	return from_text(text, FLAGS(evt_flags));
}

int afb_hook_flags_session_from_text(const char *text)
{
	return from_text(text, FLAGS(session_flags));
}

int afb_hook_flags_global_from_text(const char *text)
{
	return from_text(text, FLAGS(global_flags));
}

char *afb_hook_flags_xreq_to_text(int value)
{
	return to_text(value, FLAGS(xreq_flags));
}

char *afb_hook_flags_api_to_text(int value)
{
	return to_text(value, FLAGS(api_flags));
}

char *afb_hook_flags_evt_to_text(int value)
{
	return to_text(value, FLAGS(evt_flags));
}

char *afb_hook_flags_session_to_text(int value)
{
	return to_text(value, FLAGS(session_flags));
}

char *afb_hook_flags_global_to_text(int value)
{
	return to_text(value, FLAGS(global_flags));
}

#if !defined(REMOVE_LEGACY_TRACE)
static struct flag legacy_ditf_flags[] = { /* must be sorted by names */
		{ "all",			afb_hook_flags_api_ditf_all },
		{ "common",			afb_hook_flags_api_ditf_common },
		{ "event_broadcast_after",	afb_hook_flag_api_event_broadcast },
		{ "event_broadcast_before",	afb_hook_flag_api_event_broadcast },
		{ "event_make",			afb_hook_flag_api_event_make },
		{ "extra",			afb_hook_flags_api_ditf_extra },
		{ "get_event_loop",		afb_hook_flag_api_get_event_loop },
		{ "get_system_bus",		afb_hook_flag_api_get_system_bus },
		{ "get_user_bus",		afb_hook_flag_api_get_user_bus },
		{ "queue_job",			afb_hook_flag_api_queue_job },
		{ "require_api",		afb_hook_flag_api_require_api },
		{ "require_api_result",		afb_hook_flag_api_require_api },
		{ "rootdir_get_fd",		afb_hook_flag_api_rootdir_get_fd },
		{ "rootdir_open_locale",	afb_hook_flag_api_rootdir_open_locale },
		{ "unstore_req",		afb_hook_flag_api_legacy_unstore_req },
		{ "vverbose",			afb_hook_flag_api_vverbose },
};

static struct flag legacy_svc_flags[] = { /* must be sorted by names */
		{ "all",		afb_hook_flags_api_svc_all },
		{ "call",		afb_hook_flag_api_call },
		{ "call_result",	afb_hook_flag_api_call },
		{ "callsync",		afb_hook_flag_api_callsync },
		{ "callsync_result",	afb_hook_flag_api_callsync },
		{ "on_event_after",	afb_hook_flag_api_on_event },
		{ "on_event_before",	afb_hook_flag_api_on_event },
		{ "start_after",	afb_hook_flag_api_start },
		{ "start_before",	afb_hook_flag_api_start },
};

int afb_hook_flags_legacy_ditf_from_text(const char *text)
{
	return from_text(text, FLAGS(legacy_ditf_flags));
}

int afb_hook_flags_legacy_svc_from_text(const char *text)
{
	return from_text(text, FLAGS(legacy_svc_flags));
}

char *afb_hook_flags_legacy_ditf_to_text(int value)
{
	return to_text(value, FLAGS(legacy_ditf_flags));
}

char *afb_hook_flags_legacy_svc_to_text(int value)
{
	return to_text(value, FLAGS(legacy_svc_flags));
}
#endif

#endif /* WITH_AFB_HOOK *******************************************************/
