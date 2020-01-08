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

#include "afb-service-itf-x1.h"

/** @addtogroup AFB_SERVICE
 *  @{ */

/**
 * @deprecated use bindings version 3
 *
 * Calls the 'verb' of the 'api' with the arguments 'args' and 'verb' in the name of the binding.
 * The result of the call is delivered to the 'callback' function with the 'callback_closure'.
 *
 * For convenience, the function calls 'json_object_put' for 'args'.
 * Thus, in the case where 'args' should remain available after
 * the function returns, the function 'json_object_get' shall be used.
 *
 * The 'callback' receives 3 arguments:
 *  1. 'closure' the user defined closure pointer 'callback_closure',
 *  2. 'status' a status being 0 on success or negative when an error occured,
 *  2. 'result' the resulting data as a JSON object.
 *
 * @param service  The service as received during initialisation
 * @param api      The api name of the method to call
 * @param verb     The verb name of the method to call
 * @param args     The arguments to pass to the method
 * @param callback The to call on completion
 * @param callback_closure The closure to pass to the callback
 *
 * @see also 'afb_req_subcall'
 */
static inline void afb_service_call_v1(
	struct afb_service_x1 service,
	const char *api,
	const char *verb,
	struct json_object *args,
	void (*callback)(void*closure, int status, struct json_object *result),
	void *callback_closure)
{
	service.itf->call(service.closure, api, verb, args, callback, callback_closure);
}

/**
 * @deprecated use bindings version 3
 *
 * Calls the 'verb' of the 'api' with the arguments 'args' and 'verb' in the name of the binding.
 * 'result' will receive the response.
 *
 * For convenience, the function calls 'json_object_put' for 'args'.
 * Thus, in the case where 'args' should remain available after
 * the function returns, the function 'json_object_get' shall be used.
 *
 * @param service  The service as received during initialisation
 * @param api      The api name of the method to call
 * @param verb     The verb name of the method to call
 * @param args     The arguments to pass to the method
 * @param result   Where to store the result - should call json_object_put on it -
 *
 * @returns 0 in case of success or a negative value in case of error.
 *
 * @see also 'afb_req_subcall'
 */
static inline int afb_service_call_sync_v1(
	struct afb_service_x1 service,
	const char *api,
	const char *verb,
	struct json_object *args,
	struct json_object **result)
{
	return service.itf->call_sync(service.closure, api, verb, args, result);
}

/** @} */
