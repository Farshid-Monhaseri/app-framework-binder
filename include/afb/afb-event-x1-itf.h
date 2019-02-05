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

#include "afb-event-x2-itf.h"

/** @addtogroup AFB_EVENT
 *  @{ */

/**
 * @deprecated use bindings version 3
 *
 * Describes the request of afb-daemon for bindings
 */
struct afb_event_x1
{
	const struct afb_event_x2_itf *itf;	/**< the interface to use */
	struct afb_event_x2 *closure;		/**< the closure argument for functions of 'itf' */
};

/** @} */
