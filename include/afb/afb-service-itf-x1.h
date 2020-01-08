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

#pragma once

struct afb_api_x3;

/** @defgroup AFB_SERVICE
 *  @{ */

/**
 * @deprecated use bindings version 3
 *
 * Interface for internal of services
 * It records the functions to be called for the request.
 * Don't use this structure directly.
 * Use the helper functions documented below.
 */
struct afb_service_itf_x1
{
	/* CAUTION: respect the order, add at the end */

	void (*call)(struct afb_api_x3 *closure, const char *api, const char *verb, struct json_object *args,
	             void (*callback)(void*, int, struct json_object*), void *callback_closure);

	int (*call_sync)(struct afb_api_x3 *closure, const char *api, const char *verb, struct json_object *args,
	                 struct json_object **result);
};

/**
 * @deprecated use bindings version 3
 *
 * Object that encapsulate accesses to service items
 */
struct afb_service_x1
{
	const struct afb_service_itf_x1 *itf;
	struct afb_api_x3 *closure;
};

/** @} */
