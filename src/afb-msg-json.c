/*
 * Copyright (C) 2015-2020 "IoT.bzh"
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

#define _GNU_SOURCE

#include <json-c/json.h>

#include "afb-msg-json.h"
#include "afb-context.h"

static const char _success_[] = "success";

struct json_object *afb_msg_json_reply(struct json_object *resp, const char *error, const char *info, struct afb_context *context)
{
	json_object *msg, *request;
	json_object *type_reply = NULL;

	msg = json_object_new_object();
	if (resp != NULL)
		json_object_object_add(msg, "response", resp);

	type_reply = json_object_new_string("afb-reply");
	json_object_object_add(msg, "jtype", type_reply);

	request = json_object_new_object();
	json_object_object_add(msg, "request", request);
	json_object_object_add(request, "status", json_object_new_string(error ?: _success_));

	if (info != NULL)
		json_object_object_add(request, "info", json_object_new_string(info));

	return msg;
}

struct json_object *afb_msg_json_event(const char *event, struct json_object *object)
{
	json_object *msg;
	json_object *type_event = NULL;

	msg = json_object_new_object();

	json_object_object_add(msg, "event", json_object_new_string(event));

	if (object != NULL)
		json_object_object_add(msg, "data", object);

	type_event = json_object_new_string("afb-event");
	json_object_object_add(msg, "jtype", type_event);

	return msg;
}


