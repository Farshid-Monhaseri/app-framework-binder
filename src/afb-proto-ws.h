/*
 * Copyright (C) 2016, 2017, 2018 "IoT.bzh"
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

/*
 * Defined since version 3, the value AFB_PROTO_WS_VERSION can be used to
 * track versions of afb-proto-ws.
 */
#define AFB_PROTO_WS_VERSION	3

struct fdev;
struct afb_proto_ws;
struct afb_proto_ws_call;
struct afb_proto_ws_describe;

struct afb_proto_ws_client_itf
{
	/* can't be NULL */
	void (*on_reply)(void *closure, void *request, struct json_object *obj, const char *error, const char *info);

	/* can be NULL */
	void (*on_event_create)(void *closure, const char *event_name, int event_id);
	void (*on_event_remove)(void *closure, const char *event_name, int event_id);
	void (*on_event_subscribe)(void *closure, void *request, const char *event_name, int event_id);
	void (*on_event_unsubscribe)(void *closure, void *request, const char *event_name, int event_id);
	void (*on_event_push)(void *closure, const char *event_name, int event_id, struct json_object *data);
	void (*on_event_broadcast)(void *closure, const char *event_name, struct json_object *data);
};

struct afb_proto_ws_server_itf
{
	void (*on_call)(void *closure, struct afb_proto_ws_call *call, const char *verb, struct json_object *args, const char *sessionid, const char *user_creds);
	void (*on_describe)(void *closure, struct afb_proto_ws_describe *describe);
};

extern struct afb_proto_ws *afb_proto_ws_create_client(struct fdev *fdev, const struct afb_proto_ws_client_itf *itf, void *closure);
extern struct afb_proto_ws *afb_proto_ws_create_server(struct fdev *fdev, const struct afb_proto_ws_server_itf *itf, void *closure);

extern void afb_proto_ws_unref(struct afb_proto_ws *protows);
extern void afb_proto_ws_addref(struct afb_proto_ws *protows);

extern int afb_proto_ws_is_client(struct afb_proto_ws *protows);
extern int afb_proto_ws_is_server(struct afb_proto_ws *protows);

extern void afb_proto_ws_hangup(struct afb_proto_ws *protows);

extern void afb_proto_ws_on_hangup(struct afb_proto_ws *protows, void (*on_hangup)(void *closure));
extern void afb_proto_ws_set_queuing(struct afb_proto_ws *protows, int (*queuing)(void (*)(int,void*), void*));


extern int afb_proto_ws_client_call(struct afb_proto_ws *protows, const char *verb, struct json_object *args, const char *sessionid, void *request, const char *user_creds);
extern int afb_proto_ws_client_describe(struct afb_proto_ws *protows, void (*callback)(void*, struct json_object*), void *closure);

extern int afb_proto_ws_server_event_create(struct afb_proto_ws *protows, const char *event_name, int event_id);
extern int afb_proto_ws_server_event_remove(struct afb_proto_ws *protows, const char *event_name, int event_id);
extern int afb_proto_ws_server_event_push(struct afb_proto_ws *protows, const char *event_name, int event_id, struct json_object *data);
extern int afb_proto_ws_server_event_broadcast(struct afb_proto_ws *protows, const char *event_name, struct json_object *data);

extern void afb_proto_ws_call_addref(struct afb_proto_ws_call *call);
extern void afb_proto_ws_call_unref(struct afb_proto_ws_call *call);

extern int afb_proto_ws_call_reply(struct afb_proto_ws_call *call, struct json_object *obj, const char *error, const char *info);

extern int afb_proto_ws_call_subscribe(struct afb_proto_ws_call *call, const char *event_name, int event_id);
extern int afb_proto_ws_call_unsubscribe(struct afb_proto_ws_call *call, const char *event_name, int event_id);

extern int afb_proto_ws_describe_put(struct afb_proto_ws_describe *describe, struct json_object *description);
