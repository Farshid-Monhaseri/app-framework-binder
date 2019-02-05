/*
 * Copyright (C) 2018, 2019 "IoT.bzh"
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

#include <errno.h>

#include <systemd/sd-event.h>

#define FDEV_PROVIDER
#include "fdev.h"
#include "fdev-systemd.h"

static int handler(sd_event_source *s, int fd, uint32_t revents, void *userdata)
{
	struct fdev *fdev = userdata;
	fdev_dispatch(fdev, revents);
	return 0;
}

static void unref(void *closure)
{
	sd_event_source *source = closure;
	sd_event_source_unref(source);
}

static void disable(void *closure, const struct fdev *fdev)
{
	sd_event_source *source = closure;
	sd_event_source_set_enabled(source, SD_EVENT_OFF);
}

static void enable(void *closure, const struct fdev *fdev)
{
	sd_event_source *source = closure;
	sd_event_source_set_io_events(source, fdev_events(fdev));
	sd_event_source_set_enabled(source, SD_EVENT_ON);
}

static struct fdev_itf itf =
{
	.unref = unref,
	.disable = disable,
	.enable = enable,
	.update = enable
};

struct fdev *fdev_systemd_create(struct sd_event *eloop, int fd)
{
	int rc;
	sd_event_source *source;
	struct fdev *fdev;

	fdev = fdev_create(fd);
	if (fdev) {
		rc = sd_event_add_io(eloop, &source, fd, 0, handler, fdev);
		if (rc < 0) {
			fdev_unref(fdev);
			fdev = 0;
			errno = -rc;
		} else {
			sd_event_source_set_enabled(source, SD_EVENT_OFF);
			fdev_set_itf(fdev, &itf, source);
		}
	}
	return fdev;
}

