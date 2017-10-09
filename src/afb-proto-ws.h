/*
 * Copyright (C) 2016, 2017 "IoT.bzh"
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

struct afb_proto_ws;
struct afb_proto_ws_call;
struct afb_proto_ws_subcall;
struct afb_proto_ws_describe;

struct afb_proto_ws_client_itf
{
	void (*on_reply_success)(void *closure, void *request, struct json_object *result, const char *info);
	void (*on_reply_fail)(void *closure, void *request, const char *status, const char *info);

	void (*on_event_create)(void *closure, const char *event_name, int event_id);
	void (*on_event_remove)(void *closure, const char *event_name, int event_id);
	void (*on_event_subscribe)(void *closure, void *request, const char *event_name, int event_id);
	void (*on_event_unsubscribe)(void *closure, void *request, const char *event_name, int event_id);
	void (*on_event_push)(void *closure, const char *event_name, int event_id, struct json_object *data);
	void (*on_event_broadcast)(void *closure, const char *event_name, struct json_object *data);

	void (*on_subcall)(void *closure, struct afb_proto_ws_subcall *subcall, void *request, const char *api, const char *verb, struct json_object *args);
};

struct afb_proto_ws_server_itf
{
	void (*on_call)(void *closure, struct afb_proto_ws_call *call, const char *verb, struct json_object *args, const char *sessionid);
	void (*on_describe)(void *closure, struct afb_proto_ws_describe *describe);
};

extern struct afb_proto_ws *afb_proto_ws_create_client(int fd, const struct afb_proto_ws_client_itf *itf, void *closure);
extern struct afb_proto_ws *afb_proto_ws_create_server(int fd, const struct afb_proto_ws_server_itf *itf, void *closure);

extern void afb_proto_ws_unref(struct afb_proto_ws *protows);
extern void afb_proto_ws_addref(struct afb_proto_ws *protows);

extern int afb_proto_ws_is_client(struct afb_proto_ws *protows);
extern int afb_proto_ws_is_server(struct afb_proto_ws *protows);

extern void afb_proto_ws_hangup(struct afb_proto_ws *protows);
extern void afb_proto_ws_on_hangup(struct afb_proto_ws *protows, void (*on_hangup)(void *closure));



extern int afb_proto_ws_client_call(struct afb_proto_ws *protows, const char *verb, struct json_object *args, const char *sessionid, void *request);
extern int afb_proto_ws_client_describe(struct afb_proto_ws *protows, void (*callback)(void*, struct json_object*), void *closure);

extern int afb_proto_ws_server_event_create(struct afb_proto_ws *protows, const char *event_name, int event_id);
extern int afb_proto_ws_server_event_remove(struct afb_proto_ws *protows, const char *event_name, int event_id);
extern int afb_proto_ws_server_event_push(struct afb_proto_ws *protows, const char *event_name, int event_id, struct json_object *data);
extern int afb_proto_ws_server_event_broadcast(struct afb_proto_ws *protows, const char *event_name, struct json_object *data);

extern void afb_proto_ws_call_addref(struct afb_proto_ws_call *call);
extern void afb_proto_ws_call_unref(struct afb_proto_ws_call *call);

extern int afb_proto_ws_call_success(struct afb_proto_ws_call *call, struct json_object *obj, const char *info);
extern int afb_proto_ws_call_fail(struct afb_proto_ws_call *call, const char *status, const char *info);

extern int afb_proto_ws_call_subcall(struct afb_proto_ws_call *call, const char *api, const char *verb, struct json_object *args, void (*callback)(void*, int, struct json_object*), void *cb_closure);
extern int afb_proto_ws_call_subscribe(struct afb_proto_ws_call *call, const char *event_name, int event_id);
extern int afb_proto_ws_call_unsubscribe(struct afb_proto_ws_call *call, const char *event_name, int event_id);

extern int afb_proto_ws_subcall_reply(struct afb_proto_ws_subcall *subcall, int status, struct json_object *result);

extern int afb_proto_ws_describe_put(struct afb_proto_ws_describe *describe, struct json_object *description);

