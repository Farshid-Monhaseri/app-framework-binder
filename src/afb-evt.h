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

#include "uuid.h"

struct afb_event_x1;
struct afb_event_x2;
struct afb_evtid;
struct afb_session;
struct json_object;
struct afb_evt_listener;

struct afb_evt_itf
{
	void (*push)(void *closure, const char *event, uint16_t evtid, struct json_object *object);
	void (*broadcast)(void *closure, const char *event, struct json_object *object, const uuid_binary_t uuid, uint8_t hop);
	void (*add)(void *closure, const char *event, uint16_t evtid);
	void (*remove)(void *closure, const char *event, uint16_t evtid);
};

extern struct afb_evt_listener *afb_evt_listener_create(const struct afb_evt_itf *itf, void *closure);

extern int afb_evt_broadcast(const char *event, struct json_object *object);
extern int afb_evt_rebroadcast(const char *event, struct json_object *object, const  uuid_binary_t uuid, uint8_t hop);

extern struct afb_evt_listener *afb_evt_listener_addref(struct afb_evt_listener *listener);
extern void afb_evt_listener_unref(struct afb_evt_listener *listener);

extern struct afb_evtid *afb_evt_evtid_create(const char *fullname);
extern struct afb_evtid *afb_evt_evtid_create2(const char *prefix, const char *name);

extern struct afb_evtid *afb_evt_evtid_addref(struct afb_evtid *evtid);

extern void afb_evt_evtid_unref(struct afb_evtid *evtid);

extern const char *afb_evt_evtid_fullname(struct afb_evtid *evtid);
extern uint16_t afb_evt_evtid_id(struct afb_evtid *evtid);

extern const char *afb_evt_evtid_name(struct afb_evtid *evtid);

extern int afb_evt_evtid_push(struct afb_evtid *evtid, struct json_object *obj);

extern int afb_evt_evtid_broadcast(struct afb_evtid *evtid, struct json_object *object);

extern int afb_evt_watch_add_evtid(struct afb_evt_listener *listener, struct afb_evtid *evtid);
extern int afb_evt_watch_sub_evtid(struct afb_evt_listener *listener, struct afb_evtid *evtid);
extern int afb_evt_watch_sub_eventid(struct afb_evt_listener *listener, uint16_t eventid);


extern struct afb_event_x2 *afb_evt_event_x2_create(const char *fullname);
extern struct afb_event_x2 *afb_evt_event_x2_create2(const char *prefix, const char *name);
extern const char *afb_evt_event_x2_fullname(struct afb_event_x2 *event);
extern uint16_t afb_evt_event_x2_id(struct afb_event_x2 *eventid);
extern struct afb_event_x2 *afb_evt_event_x2_addref(struct afb_event_x2 *eventid);
extern void afb_evt_event_x2_unref(struct afb_event_x2 *eventid);

extern int afb_evt_event_x2_push(struct afb_event_x2 *eventid, struct json_object *object);
extern int afb_evt_event_x2_unhooked_push(struct afb_event_x2 *eventid, struct json_object *object);

extern int afb_evt_event_x2_add_watch(struct afb_evt_listener *listener, struct afb_event_x2 *eventid);
extern int afb_evt_event_x2_remove_watch(struct afb_evt_listener *listener, struct afb_event_x2 *eventid);

extern struct afb_evtid *afb_evt_event_x2_to_evtid(struct afb_event_x2 *eventid);
extern struct afb_event_x2 *afb_evt_event_x2_from_evtid(struct afb_evtid *evtid);

#if WITH_LEGACY_BINDING_V1 || WITH_LEGACY_BINDING_V2
extern struct afb_event_x1 afb_evt_event_from_evtid(struct afb_evtid *evtid);
#endif

#if WITH_AFB_HOOK
extern struct afb_evtid *afb_evt_evtid_hooked_addref(struct afb_evtid *evtid);
extern void afb_evt_evtid_hooked_unref(struct afb_evtid *evtid);
extern const char *afb_evt_evtid_hooked_name(struct afb_evtid *evtid);
extern int afb_evt_evtid_hooked_push(struct afb_evtid *evtid, struct json_object *obj);
extern int afb_evt_evtid_hooked_broadcast(struct afb_evtid *evtid, struct json_object *object);
extern void afb_evt_update_hooks();
#endif
