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

#include "afb-event-x1-itf.h"

/** @addtogroup AFB_EVENT
 *  @{ */

/**
 * @deprecated use bindings version 3
 *
 * Converts the 'event' to an afb_eventid.
 */
static inline struct afb_event_x2 *afb_event_x1_to_event_x2(struct afb_event_x1 event)
{
	return event.closure;
}

/**
 * @deprecated use bindings version 3
 *
 * Checks wether the 'event' is valid or not.
 *
 * Returns 0 if not valid or 1 if valid.
 */
static inline int afb_event_x1_is_valid(struct afb_event_x1 event)
{
	return !!event.itf;
}

/**
 * @deprecated use bindings version 3
 *
 * Broadcasts widely the 'event' with the data 'object'.
 * 'object' can be NULL.
 *
 * For convenience, the function calls 'json_object_put' for 'object'.
 * Thus, in the case where 'object' should remain available after
 * the function returns, the function 'json_object_get' shall be used.
 *
 * Returns the count of clients that received the event.
 */
static inline int afb_event_x1_broadcast(struct afb_event_x1 event, struct json_object *object)
{
	return event.itf->broadcast(event.closure, object);
}

/**
 * @deprecated use bindings version 3
 *
 * Pushes the 'event' with the data 'object' to its observers.
 * 'object' can be NULL.
 *
 * For convenience, the function calls 'json_object_put' for 'object'.
 * Thus, in the case where 'object' should remain available after
 * the function returns, the function 'json_object_get' shall be used.
 *
 * Returns the count of clients that received the event.
 */
static inline int afb_event_x1_push(struct afb_event_x1 event, struct json_object *object)
{
	return event.itf->push(event.closure, object);
}

/* OBSOLETE */
#define afb_event_x1_drop afb_event_x1_unref

/**
 * @deprecated use bindings version 3
 *
 * Gets the name associated to the 'event'.
 */
static inline const char *afb_event_x1_name(struct afb_event_x1 event)
{
	return event.itf->name(event.closure);
}

/**
 * @deprecated use bindings version 3
 *
 * Decreases the count of reference to 'event' and
 * destroys the event when the reference count falls to zero.
 */
static inline void afb_event_x1_unref(struct afb_event_x1 event)
{
	event.itf->unref(event.closure);
}

/**
 * @deprecated use bindings version 3
 *
 * Increases the count of reference to 'event'
 */
static inline void afb_event_x1_addref(struct afb_event_x1 event)
{
	event.itf->addref(event.closure);
}

/** @} */
