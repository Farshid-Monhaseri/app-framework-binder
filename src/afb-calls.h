/*
 * Copyright (C) 2016-2019 "IoT.bzh"
 * Author: José Bollo <jose.bollo@iot.bzh>
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

struct json_object;

struct afb_export;
struct afb_xreq;

struct afb_api_x3;
struct afb_req_x1;
struct afb_req_x2;

/******************************************************************************/

extern
void afb_calls_call(
		struct afb_export *export,
		const char *api,
		const char *verb,
		struct json_object *args,
		void (*callback)(void*, struct json_object*, const char *error, const char *info, struct afb_api_x3*),
		void *closure);

extern
void afb_calls_hooked_call(
		struct afb_export *export,
		const char *api,
		const char *verb,
		struct json_object *args,
		void (*callback)(void*, struct json_object*, const char *error, const char *info, struct afb_api_x3*),
		void *closure);

extern
int afb_calls_call_sync(
		struct afb_export *export,
		const char *api,
		const char *verb,
		struct json_object *args,
		struct json_object **object,
		char **error,
		char **info);

extern
int afb_calls_hooked_call_sync(
		struct afb_export *export,
		const char *api,
		const char *verb,
		struct json_object *args,
		struct json_object **object,
		char **error,
		char **info);

extern
void afb_calls_subcall(
			struct afb_xreq *xreq,
			const char *api,
			const char *verb,
			struct json_object *args,
			int flags,
			void (*callback)(void *closure, struct json_object *object, const char *error, const char * info, struct afb_req_x2 *req),
			void *closure);

extern
void afb_calls_hooked_subcall(
			struct afb_xreq *xreq,
			const char *api,
			const char *verb,
			struct json_object *args,
			int flags,
			void (*callback)(void *closure, struct json_object *object, const char *error, const char * info, struct afb_req_x2 *req),
			void *closure);

extern
int afb_calls_subcall_sync(
			struct afb_xreq *xreq,
			const char *api,
			const char *verb,
			struct json_object *args,
			int flags,
			struct json_object **object,
			char **error,
			char **info);

extern
int afb_calls_hooked_subcall_sync(
			struct afb_xreq *xreq,
			const char *api,
			const char *verb,
			struct json_object *args,
			int flags,
			struct json_object **object,
			char **error,
			char **info);

/******************************************************************************/

extern
void afb_calls_legacy_call_v12(
		struct afb_export *export,
		const char *api,
		const char *verb,
		struct json_object *args,
		void (*callback)(void*, int, struct json_object*),
		void *closure);

extern
void afb_calls_legacy_hooked_call_v12(
		struct afb_export *export,
		const char *api,
		const char *verb,
		struct json_object *args,
		void (*callback)(void*, int, struct json_object*),
		void *closure);

extern
void afb_calls_legacy_call_v3(
		struct afb_export *export,
		const char *api,
		const char *verb,
		struct json_object *args,
		void (*callback)(void*, int, struct json_object*, struct afb_api_x3 *),
		void *closure);

extern
void afb_calls_legacy_hooked_call_v3(
		struct afb_export *export,
		const char *api,
		const char *verb,
		struct json_object *args,
		void (*callback)(void*, int, struct json_object*, struct afb_api_x3 *),
		void *closure);

extern
int afb_calls_legacy_call_sync(
		struct afb_export *export,
		const char *api,
		const char *verb,
		struct json_object *args,
		struct json_object **result);

extern
int afb_calls_legacy_hooked_call_sync(
		struct afb_export *export,
		const char *api,
		const char *verb,
		struct json_object *args,
		struct json_object **result);

/******************************************************************************/

extern
void afb_calls_legacy_subcall_v1(
		struct afb_xreq *caller,
		const char *api,
		const char *verb,
		struct json_object *args,
		void (*callback)(void*, int, struct json_object*),
		void *closure);

extern
void afb_calls_legacy_hooked_subcall_v1(
		struct afb_xreq *caller,
		const char *api,
		const char *verb,
		struct json_object *args,
		void (*callback)(void*, int, struct json_object*),
		void *closure);

extern
void afb_calls_legacy_subcall_v2(
		struct afb_xreq *caller,
		const char *api,
		const char *verb,
		struct json_object *args,
		void (*callback)(void*, int, struct json_object*, struct afb_req_x1),
		void *closure);

extern
void afb_calls_legacy_hooked_subcall_v2(
		struct afb_xreq *caller,
		const char *api,
		const char *verb,
		struct json_object *args,
		void (*callback)(void*, int, struct json_object*, struct afb_req_x1),
		void *closure);

extern
void afb_calls_legacy_subcall_v3(
		struct afb_xreq *caller,
		const char *api,
		const char *verb,
		struct json_object *args,
		void (*callback)(void*, int, struct json_object*, struct afb_req_x2 *),
		void *closure);

extern
void afb_calls_legacy_hooked_subcall_v3(
		struct afb_xreq *caller,
		const char *api,
		const char *verb,
		struct json_object *args,
		void (*callback)(void*, int, struct json_object*, struct afb_req_x2 *),
		void *closure);

extern
int afb_calls_legacy_subcall_sync(
		struct afb_xreq *caller,
		const char *api,
		const char *verb,
		struct json_object *args,
		struct json_object **result);

extern
int afb_calls_legacy_hooked_subcall_sync(
		struct afb_xreq *caller,
		const char *api,
		const char *verb,
		struct json_object *args,
		struct json_object **result);
