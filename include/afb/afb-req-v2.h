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

#include "afb-req.h"

/*
 * Stores 'req' on heap for asynchrnous use.
 * Returns a handler to the stored 'req' or NULL on memory depletion.
 * The count of reference to 'req' is incremented on success
 * (see afb_req_addref).
 */
static inline struct afb_stored_req *afb_req_store_v2(struct afb_req req)
{
	return req.itf->store(req.closure);
}

