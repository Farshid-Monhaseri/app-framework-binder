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

#include "afb-request-itf.h"

/*
 * Describes the request by bindings from afb-daemon
 */
struct afb_req
{
	const struct afb_request_itf *itf;	/* the interface to use */
	struct afb_request *closure;		/* the closure argument for functions of 'itf' */
};

