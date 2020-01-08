/*
 * Copyright (C) 2015-2020 "IoT.bzh"
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

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#define FDEV_PROVIDER
#include "fdev.h"

struct fdev
{
	int fd;
	uint32_t events;
	unsigned refcount;
	struct fdev_itf *itf;
	void *closure_itf;
	void (*callback)(void*,uint32_t,struct fdev*);
	void *closure_callback;
};

struct fdev *fdev_create(int fd)
{
	struct fdev *fdev;

	fdev = calloc(1, sizeof *fdev);
	if (!fdev)
		errno = ENOMEM;
	else {
		fdev->fd = fd;
		fdev->refcount = 3; /* set autoclose by default */
	}
	return fdev;
}

void fdev_set_itf(struct fdev *fdev, struct fdev_itf *itf, void *closure_itf)
{
	fdev->itf = itf;
	fdev->closure_itf = closure_itf;
}

void fdev_dispatch(struct fdev *fdev, uint32_t events)
{
	if (fdev->callback)
		fdev->callback(fdev->closure_callback, events, fdev);
}

struct fdev *fdev_addref(struct fdev *fdev)
{
	if (fdev)
		__atomic_add_fetch(&fdev->refcount, 2, __ATOMIC_RELAXED);
	return fdev;
}

void fdev_unref(struct fdev *fdev)
{
	if (fdev && __atomic_sub_fetch(&fdev->refcount, 2, __ATOMIC_RELAXED) <= 1) {
		if (fdev->itf) {
			fdev->itf->disable(fdev->closure_itf, fdev);
			if (fdev->itf->unref)
				fdev->itf->unref(fdev->closure_itf);
		}
		if (fdev->refcount)
			close(fdev->fd);
		free(fdev);
	}
}

int fdev_fd(const struct fdev *fdev)
{
	return fdev->fd;
}

uint32_t fdev_events(const struct fdev *fdev)
{
	return fdev->events;
}

int fdev_autoclose(const struct fdev *fdev)
{
	return 1 & fdev->refcount;
}

static inline int is_active(struct fdev *fdev)
{
	return !!fdev->callback;
}

static inline void update_activity(struct fdev *fdev, int old_active)
{
	if (is_active(fdev)) {
		if (!old_active)
			fdev->itf->enable(fdev->closure_itf, fdev);
	} else {
		if (old_active)
			fdev->itf->disable(fdev->closure_itf, fdev);
	}
}

void fdev_set_callback(struct fdev *fdev, void (*callback)(void*,uint32_t,struct fdev*), void *closure)
{
	int oa;

	oa = is_active(fdev);
	fdev->callback = callback;
	fdev->closure_callback = closure;
	update_activity(fdev, oa);
}

void fdev_set_events(struct fdev *fdev, uint32_t events)
{
	if (events != fdev->events) {
		fdev->events = events;
		if (is_active(fdev))
			fdev->itf->update(fdev->closure_itf, fdev);
	}
}

void fdev_set_autoclose(struct fdev *fdev, int autoclose)
{
	if (autoclose)
		fdev->refcount |= (unsigned)1;
	else
		fdev->refcount &= ~(unsigned)1;
}

