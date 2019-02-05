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

struct afb_event_x2;
struct afb_event_x2_itf;

/** @addtogroup AFB_EVENT
 *  @{ */

/**
 * Interface for handling event_x2.
 *
 * It records the functions to be called for the event_x2.
 *
 * Don't use this structure directly.
 */
struct afb_event_x2_itf
{
	/* CAUTION: respect the order, add at the end */

	/** broadcast the event */
	int (*broadcast)(struct afb_event_x2 *event, struct json_object *obj);

	/** push the event to its subscribers */
	int (*push)(struct afb_event_x2 *event, struct json_object *obj);

	/** unreference the event */
	void (*unref)(struct afb_event_x2 *event); /* aka drop */

	/** get the event name */
	const char *(*name)(struct afb_event_x2 *event);

	/** rereference the event */
	struct afb_event_x2 *(*addref)(struct afb_event_x2 *event);
};

/**
 * Describes the event_x2
 */
struct afb_event_x2
{
	const struct afb_event_x2_itf *itf;	/**< the interface functions to use */
};

/** @} */
