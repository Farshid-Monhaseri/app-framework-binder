/*
 * Copyright (C) 2015-2019 "IoT.bzh"
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

#include <unistd.h>
#include <errno.h>

#include <systemd/sd-event.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-daemon.h>

#include "systemd.h"
#include "jobs.h"

static struct sd_bus *sdbusopen(struct sd_bus **p, int (*f)(struct sd_bus **))
{
	if (*p == NULL) {
		int rc = f(p);
		if (rc < 0) {
			errno = -rc;
			*p = NULL;
		} else {
			rc = sd_bus_attach_event(*p, systemd_get_event_loop(), 0);
			if (rc < 0) {
				sd_bus_unref(*p);
				errno = -rc;
				*p = NULL;
			}
		}
	}
	return *p;
}

struct sd_event *systemd_get_event_loop()
{
	return jobs_get_sd_event();
}

struct sd_bus *systemd_get_user_bus()
{
	static struct sd_bus *result = NULL;
	return sdbusopen((void*)&result, (void*)sd_bus_open_user);
}

struct sd_bus *systemd_get_system_bus()
{
	static struct sd_bus *result = NULL;
	return sdbusopen((void*)&result, (void*)sd_bus_open_system);
}

static char **fds_names()
{
	static char *null;
	static char **names;

	int rc;

	if (!names) {
		rc = sd_listen_fds_with_names(1, &names);
		if (rc <= 0) {
			errno = -rc;
			names = &null;
		}
	}
	return names;
}

int systemd_fds_init()
{
	errno = 0;
	fds_names();
	return -!!errno;
}

int systemd_fds_for(const char *name)
{
	int idx;
	char **names;

	names = fds_names();
	for (idx = 0 ; names[idx] != NULL ; idx++)
		if (!strcmp(name, names[idx]))
			return idx + SD_LISTEN_FDS_START;

	errno = ENOENT;
	return -1;
}

