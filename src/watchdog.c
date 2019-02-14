/*
 * Copyright (C) 2016-2019 "IoT.bzh"
 * Author José Bollo <jose.bollo@iot.bzh>
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

#include "watchdog.h"

#if HAS_WATCHDOG

#include <stdlib.h>

#include <systemd/sd-event.h>
#include <systemd/sd-daemon.h>

#include "jobs.h"
#include "systemd.h"

int watchdog_activate()
{
	/* set the watchdog */
	if (sd_watchdog_enabled(0, NULL)) {
		jobs_acquire_event_manager();
		sd_event_set_watchdog(systemd_get_event_loop(), 1);
	}
	return 0;
}

#endif