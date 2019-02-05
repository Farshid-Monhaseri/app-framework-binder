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

#include <stdarg.h>

/* declaration of features of libsystemd */
struct sd_event;
struct sd_bus;
struct afb_stored_req;
struct afb_req_x1;
struct afb_event_x1;
struct afb_api_x3;

/** @defgroup AFB_DAEMON
 *  @{ */

/**
 * @deprecated use bindings version 3
 *
 * Definition of the facilities provided by the daemon.
 */
struct afb_daemon_itf_x1
{
	/** broadcasts evant 'name' with 'object' */
	int (*event_broadcast)(struct afb_api_x3 *closure, const char *name, struct json_object *object);

	/** gets the common systemd's event loop */
	struct sd_event *(*get_event_loop)(struct afb_api_x3 *closure);

	/** gets the common systemd's user d-bus */
	struct sd_bus *(*get_user_bus)(struct afb_api_x3 *closure);

	/** gets the common systemd's system d-bus */
	struct sd_bus *(*get_system_bus)(struct afb_api_x3 *closure);

	/** logging messages */
	void (*vverbose_v1)(struct afb_api_x3*closure, int level, const char *file, int line, const char *fmt, va_list args);

	/** creates an event of 'name' */
	struct afb_event_x1 (*event_make)(struct afb_api_x3 *closure, const char *name);

	/** get the file descriptor of the install directory */
	int (*rootdir_get_fd)(struct afb_api_x3 *closure);

	/** opens a file of the install directory */
	int (*rootdir_open_locale)(struct afb_api_x3 *closure, const char *filename, int flags, const char *locale);

	/** queue a job */
	int (*queue_job)(struct afb_api_x3 *closure, void (*callback)(int signum, void *arg), void *argument, void *group, int timeout);

	/** logging messages */
	void (*vverbose_v2)(struct afb_api_x3*closure, int level, const char *file, int line, const char * func, const char *fmt, va_list args);

	/** retrieve a stored request */
	struct afb_req_x1 (*unstore_req)(struct afb_api_x3*closure, struct afb_stored_req *sreq);

	/** require an api */
	int (*require_api)(struct afb_api_x3*closure, const char *name, int initialized);

	/** aliases an api */
	int (*add_alias)(struct afb_api_x3*closure, const char *name, const char *as_name);

	/** creates a new api */
	struct afb_api_x3 *(*new_api)(struct afb_api_x3 *closure, const char *api, const char *info, int noconcurrency, int (*preinit)(void*, struct afb_api_x3 *), void *preinit_closure);
};

/**
 * @deprecated use bindings version 3
 *
 * Structure for accessing daemon.
 * See also: afb_daemon_get_event_sender, afb_daemon_get_event_loop, afb_daemon_get_user_bus, afb_daemon_get_system_bus
 */
struct afb_daemon_x1
{
	const struct afb_daemon_itf_x1 *itf;    /**< the interfacing functions */
	struct afb_api_x3 *closure;             /**< the closure when calling these functions */
};

/** @} */
