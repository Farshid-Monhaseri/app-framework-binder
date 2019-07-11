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

/** @defgroup AFB_EVENT
 *  @{ */

/**
 * Checks whether the 'event' is valid or not.
 *
 * @param event the event to check
 *
 * @return 0 if not valid or 1 if valid.
 */
static inline int afb_event_x2_is_valid(struct afb_event_x2 *event)
{
	return !!event;
}

/**
 * Broadcasts widely an event of 'event' with the data 'object'.
 * 'object' can be NULL.
 *
 * For convenience, the function calls 'json_object_put' for 'object'.
 * Thus, in the case where 'object' should remain available after
 * the function returns, the function 'json_object_get' shall be used.
 *
 * @param event the event to broadcast
 * @param object the companion object to associate to the broadcasted event (can be NULL)
 *
 * @return 0 in case of success or -1 in case of error
 */
static inline int afb_event_x2_broadcast(
			struct afb_event_x2 *event,
			struct json_object *object)
{
	return event->itf->broadcast(event, object);
}

/**
 * Pushes an event of 'event' with the data 'object' to its observers.
 * 'object' can be NULL.
 *
 * For convenience, the function calls 'json_object_put' for 'object'.
 * Thus, in the case where 'object' should remain available after
 * the function returns, the function 'json_object_get' shall be used.
 *
 * @param event the event to push
 * @param object the companion object to associate to the pushed event (can be NULL)
 *
 * @Return
 *   *  1 if at least one client listen for the event
 *   *  0 if no more client listen for the event
 *   * -1 in case of error (the event can't be delivered)
 */
static inline int afb_event_x2_push(
			struct afb_event_x2 *event,
			struct json_object *object)
{
	return event->itf->push(event, object);
}

/**
 * Gets the name associated to 'event'.
 *
 * @param event the event whose name is requested
 *
 * @return the name of the event
 *
 * The returned name can be used until call to 'afb_event_x2_unref'.
 * It shouldn't be freed.
 */
static inline const char *afb_event_x2_name(struct afb_event_x2 *event)
{
	return event->itf->name(event);
}

/**
 * Decrease the count of references to 'event'.
 * Call this function when the evenid is no more used.
 * It destroys the event_x2 when the reference count falls to zero.
 *
 * @param event the event
 */
static inline void afb_event_x2_unref(struct afb_event_x2 *event)
{
	event->itf->unref(event);
}

/**
 * Increases the count of references to 'event'
 *
 * @param event the event
 *
 * @return the event
 */
static inline struct afb_event_x2 *afb_event_x2_addref(
					struct afb_event_x2 *event)
{
	return event->itf->addref(event);
}

/** @} */
