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

#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <errno.h>
#include <assert.h>
#include <sys/eventfd.h>

#include <systemd/sd-event.h>

#include "evmgr.h"
#include "verbose.h"
#include "systemd.h"

/** Description of handled event loops */
struct evmgr
{
	unsigned state;        /**< encoded state */
	int efd;               /**< event notification */
	void *holder;          /**< holder of the evmgr */
	struct sd_event *sdev; /**< the systemd event loop */
};

#define EVLOOP_STATE_WAIT           1U
#define EVLOOP_STATE_RUN            2U

/**
 * Run the event loop is set.
 */
void evmgr_run(struct evmgr *evmgr)
{
	int rc;
	struct sd_event *se;

	evmgr->state = EVLOOP_STATE_WAIT|EVLOOP_STATE_RUN;
	se = evmgr->sdev;
	rc = sd_event_prepare(se);
	if (rc < 0) {
		errno = -rc;
		CRITICAL("sd_event_prepare returned an error (state: %d): %m", sd_event_get_state(se));
		abort();
	} else {
		if (rc == 0) {
			rc = sd_event_wait(se, (uint64_t)(int64_t)-1);
			if (rc < 0) {
				errno = -rc;
				ERROR("sd_event_wait returned an error (state: %d): %m", sd_event_get_state(se));
			}
		}
		evmgr->state = EVLOOP_STATE_RUN;
		if (rc > 0) {
			rc = sd_event_dispatch(se);
			if (rc < 0) {
				errno = -rc;
				ERROR("sd_event_dispatch returned an error (state: %d): %m", sd_event_get_state(se));
			}
		}
	}
	evmgr->state = 0;
}

void evmgr_job_run(int signum, struct evmgr *evmgr)
{
	if (signum)
		evmgr->state = 0;
	else
		evmgr_run(evmgr);
}

int evmgr_can_run(struct evmgr *evmgr)
{
	return !evmgr->state;
}

/**
 * Internal callback for evmgr management.
 * The effect of this function is hidden: it exits
 * the waiting poll if any.
 */
static void evmgr_on_efd_event(struct evmgr *evmgr)
{
	uint64_t x;
	read(evmgr->efd, &x, sizeof x);
}

/**
 * wakeup the event loop if needed by sending
 * an event.
 */
void evmgr_wakeup(struct evmgr *evmgr)
{
	uint64_t x;

	if (evmgr->state & EVLOOP_STATE_WAIT) {
		x = 1;
		write(evmgr->efd, &x, sizeof x);
	}
}

/**
 */
void *evmgr_holder(struct evmgr *evmgr)
{
	return evmgr->holder;
}

/**
 */
int evmgr_release_if(struct evmgr *evmgr, void *holder)
{
	if (evmgr->holder != holder)
		return 0;
	evmgr->holder = 0;
	return 1;
}

/**
 */
int evmgr_try_hold(struct evmgr *evmgr, void *holder)
{
	if (!evmgr->holder)
		evmgr->holder = holder;
	return evmgr->holder == holder;
}

/******************************************************************************/
/******************************************************************************/
/******  SYSTEM D                                                        ******/
/******************************************************************************/
/******************************************************************************/

/**
 * Internal callback for evmgr management.
 * The effect of this function is hidden: it exits
 * the waiting poll if any. Then it wakes up a thread
 * awaiting the evmgr using signal.
 */
static int on_evmgr_efd(sd_event_source *s, int fd, uint32_t revents, void *userdata)
{
	struct evmgr *evmgr = userdata;
	evmgr_on_efd_event(evmgr);
	return 1;
}

/**
 * Gets a sd_event item for the current thread.
 * @return a sd_event or NULL in case of error
 */
int evmgr_create(struct evmgr **result)
{
	int rc;
	struct evmgr *evmgr;

	/* creates the evmgr on need */
	evmgr = malloc(sizeof *evmgr);
	if (!evmgr) {
		ERROR("out of memory");
		rc = -ENOMEM;
		goto error;
	}

	/* creates the eventfd for waking up polls */
	evmgr->efd = eventfd(0, EFD_CLOEXEC|EFD_SEMAPHORE);
	if (evmgr->efd < 0) {
		ERROR("can't make eventfd for events");
		rc = -errno;
		goto error1;
	}
	/* create the systemd event loop */
	evmgr->sdev = systemd_get_event_loop();
	if (!evmgr->sdev) {
		ERROR("can't make new event loop");
		goto error2;
	}
	/* put the eventfd in the event loop */
	rc = sd_event_add_io(evmgr->sdev, NULL, evmgr->efd, EPOLLIN, on_evmgr_efd, evmgr);
	if (rc < 0) {
		ERROR("can't register eventfd");
		goto error2;
	}

	/* start the creation */
	evmgr->state = 0;
	evmgr->holder = 0;
	*result = evmgr;
	return 0;


error2:
	close(evmgr->efd);
error1:
	free(evmgr);
error:
	*result = 0;
	return rc;
}

