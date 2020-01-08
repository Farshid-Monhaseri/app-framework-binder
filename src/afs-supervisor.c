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

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <json-c/json.h>

#define AFB_BINDING_VERSION 3
#include <afb/afb-binding.h>

#include "afb-cred.h"
#include "afb-stub-ws.h"
#include "afb-api.h"
#include "afb-xreq.h"
#include "afb-api-v3.h"
#include "afb-apiset.h"
#include "afb-fdev.h"
#include "afb-socket.h"

#include "fdev.h"
#include "verbose.h"
#include "wrap-json.h"

#include "afs-supervision.h"
#include "afs-supervisor.h"
#include "afs-discover.h"

/* supervised items */
struct supervised
{
	/* link to the next supervised */
	struct supervised *next;

	/* credentials of the supervised */
	struct afb_cred *cred;

	/* connection with the supervised */
	struct afb_stub_ws *stub;
};

/* api and apiset name */
static const char supervision_apiname[] = AFS_SUPERVISION_APINAME;
static const char supervisor_apiname[] = AFS_SUPERVISOR_APINAME;

/* the empty apiset */
static struct afb_apiset *empty_apiset;

/* supervision socket path */
static const char supervision_socket_path[] = AFS_SUPERVISION_SOCKET;
static struct fdev *supervision_fdev;

/* global mutex */
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

/* list of supervised daemons */
static struct supervised *superviseds;

/* events */
static afb_event_t event_add_pid;
static afb_event_t event_del_pid;

/*************************************************************************************/


/*************************************************************************************/

/**
 * send on 'fd' an initiator with 'command'
 * return 0 on success or -1 on failure
 */
static int send_initiator(int fd, const char *command)
{
	int rc;
	ssize_t swr;
	struct afs_supervision_initiator asi;

	/* set  */
	memset(&asi, 0, sizeof asi);
	strcpy(asi.interface, AFS_SUPERVISION_INTERFACE_1);
	if (command)
		strncpy(asi.extra, command, sizeof asi.extra - 1);

	/* send the initiator */
	swr = write(fd, &asi, sizeof asi);
	if (swr < 0) {
		ERROR("Can't send initiator: %m");
		rc = -1;
	} else if (swr < sizeof asi) {
		ERROR("Sending incomplete initiator: %m");
		rc = -1;
	} else
		rc = 0;
	return rc;
}

/*
 * checks whether the incoming supervised represented by its creds
 * is to be accepted or not.
 * return 1 if yes or 0 otherwise.
 */
static int should_accept(struct afb_cred *cred)
{
	return cred && cred->pid != getpid(); /* not me! */
}

static void on_supervised_hangup(struct afb_stub_ws *stub)
{
	struct supervised *s, **ps;

	/* Search the supervised of the ws-stub */
	pthread_mutex_lock(&mutex);
	ps = &superviseds;
	while ((s = *ps) && s->stub != stub)
		ps = &s->next;

	/* unlink the supervised if found */
	if (s)
		*ps = s->next;
	pthread_mutex_unlock(&mutex);

	/* forgive the ws-stub */
	afb_stub_ws_unref(stub);

	/* forgive the supervised */
	if (s) {
		afb_event_push(event_del_pid, json_object_new_int((int)s->cred->pid));
		afb_cred_unref(s->cred);
		free(s);
	}
}

/*
 * create a supervised for socket 'fd' and 'cred'
 * return 0 in case of success or -1 in case of error
 */
static int make_supervised(int fd, struct afb_cred *cred)
{
	struct supervised *s;
	struct fdev *fdev;

	s = malloc(sizeof *s);
	if (!s)
		return -1;

	fdev = afb_fdev_create(fd);
	if (!fdev) {
		free(s);
		return -1;
	}

	s->cred = cred;
	s->stub = afb_stub_ws_create_client(fdev, supervision_apiname, empty_apiset);
	if (!s->stub) {
		free(s);
		return -1;
	}
	pthread_mutex_lock(&mutex);
	s->next = superviseds;
	superviseds = s;
	pthread_mutex_unlock(&mutex);
	afb_stub_ws_set_on_hangup(s->stub, on_supervised_hangup);
	return 0;
}

/**
 * Search the supervised of 'pid', return it or NULL.
 */
static struct supervised *supervised_of_pid(pid_t pid)
{
	struct supervised *s;

	pthread_mutex_lock(&mutex);
	s = superviseds;
	while (s && pid != s->cred->pid)
		s = s->next;
	pthread_mutex_unlock(&mutex);

	return s;
}

/*
 * handles incoming connection on 'sock'
 */
static void accept_supervision_link(int sock)
{
	int rc, fd;
	struct sockaddr addr;
	socklen_t lenaddr;
	struct afb_cred *cred;

	lenaddr = (socklen_t)sizeof addr;
	fd = accept(sock, &addr, &lenaddr);
	if (fd >= 0) {
		cred = afb_cred_create_for_socket(fd);
		rc = should_accept(cred);
		if (rc) {
			rc = send_initiator(fd, NULL);
			if (!rc) {
				rc = make_supervised(fd, cred);
				if (!rc) {
					afb_event_push(event_add_pid, json_object_new_int((int)cred->pid));
					return;
				}
			}
		}
		afb_cred_unref(cred);
		close(fd);
	}
}

/*
 * handle even on server socket
 */
static void listening(void *closure, uint32_t revents, struct fdev *fdev)
{
	if ((revents & EPOLLHUP) != 0) {
		ERROR("supervision socket closed");
		exit(1);
	}
	if ((revents & EPOLLIN) != 0)
		accept_supervision_link((int)(intptr_t)closure);
}

/*
 */
static void discovered_cb(void *closure, pid_t pid)
{
	struct supervised *s;

	s = supervised_of_pid(pid);
	if (!s) {
		(*(int*)closure)++;
		kill(pid, SIGHUP);
	}
}

int afs_supervisor_discover()
{
	int n = 0;
	afs_discover("afb-daemon", discovered_cb, &n);
	return n;
}

/*************************************************************************************/

static void f_subscribe(afb_req_t req)
{
	struct json_object *args = afb_req_json(req);
	int revoke, ok;

	revoke = json_object_is_type(args, json_type_boolean)
		&& !json_object_get_boolean(args);

	ok = 1;
	if (!revoke) {
		ok = !afb_req_subscribe(req, event_add_pid)
			&& !afb_req_subscribe(req, event_del_pid);
	}
	if (revoke || !ok) {
		afb_req_unsubscribe(req, event_add_pid);
		afb_req_unsubscribe(req, event_del_pid);
	}
	afb_req_reply(req, NULL, ok ? NULL : "error", NULL);
}

static void f_list(afb_req_t req)
{
	char pid[50];
	struct json_object *resu, *item;
	struct supervised *s;

	resu = json_object_new_object();
	s = superviseds;
	while (s) {
		sprintf(pid, "%d", (int)s->cred->pid);
		item = NULL;
		wrap_json_pack(&item, "{si si si ss ss ss}",
				"pid", (int)s->cred->pid,
				"uid", (int)s->cred->uid,
				"gid", (int)s->cred->gid,
				"id", s->cred->id,
				"label", s->cred->label,
				"user", s->cred->user
				);
		json_object_object_add(resu, pid, item);
		s = s->next;
	}
	afb_req_success(req, resu, NULL);
}

static void f_discover(afb_req_t req)
{
	afs_supervisor_discover();
	afb_req_success(req, NULL, NULL);
}

static void propagate(afb_req_t req, const char *verb)
{
	struct afb_xreq *xreq;
	struct json_object *args, *item;
	struct supervised *s;
	struct afb_api_item api;
	int p;

	xreq = xreq_from_req_x2(req);
	args = afb_xreq_json(xreq);

	/* extract the pid */
	if (!json_object_object_get_ex(args, "pid", &item)) {
		afb_xreq_reply(xreq, NULL, "no-pid", NULL);
		return;
	}
	errno = 0;
	p = json_object_get_int(item);
	if (!p && errno) {
		afb_xreq_reply(xreq, NULL, "bad-pid", NULL);
		return;
	}

	/* get supervised of pid */
	s = supervised_of_pid((pid_t)p);
	if (!s) {
		afb_req_reply(req, NULL, "unknown-pid", NULL);
		return;
	}
	json_object_object_del(args, "pid");

	/* replace the verb to call if needed */
	if (verb)
		xreq->request.called_verb = verb;

	/* call it now */
	api = afb_stub_ws_client_api(s->stub);
	api.itf->call(api.closure, xreq);
}

static void f_do(afb_req_t req)
{
	propagate(req, NULL);
}

static void f_config(afb_req_t req)
{
	propagate(req, NULL);
}

static void f_trace(afb_req_t req)
{
	propagate(req, NULL);
}

static void f_sessions(afb_req_t req)
{
	propagate(req, "slist");
}

static void f_session_close(afb_req_t req)
{
	propagate(req, "sclose");
}

static void f_exit(afb_req_t req)
{
	propagate(req, NULL);
	afb_req_success(req, NULL, NULL);
}

static void f_debug_wait(afb_req_t req)
{
	propagate(req, "wait");
	afb_req_success(req, NULL, NULL);
}

static void f_debug_break(afb_req_t req)
{
	propagate(req, "break");
	afb_req_success(req, NULL, NULL);
}

/*************************************************************************************/

/**
 * initialize the supervisor
 */
static int init_supervisor(afb_api_t api)
{
	event_add_pid = afb_api_make_event(api, "add-pid");
	if (!afb_event_is_valid(event_add_pid)) {
		ERROR("Can't create added event");
		return -1;
	}

	event_del_pid = afb_api_make_event(api, "del-pid");
	if (!afb_event_is_valid(event_del_pid)) {
		ERROR("Can't create deleted event");
		return -1;
	}

	/* create an empty set for superviseds */
	empty_apiset = afb_apiset_create(supervision_apiname, 0);
	if (!empty_apiset) {
		ERROR("Can't create supervision apiset");
		return -1;
	}

	/* create the supervision socket */
	supervision_fdev = afb_socket_open_fdev(supervision_socket_path, 1);
	if (!supervision_fdev)
		return -1;

	fdev_set_events(supervision_fdev, EPOLLIN);
	fdev_set_callback(supervision_fdev, listening,
			  (void*)(intptr_t)fdev_fd(supervision_fdev));

	return 0;
}

/*************************************************************************************/

static const struct afb_auth _afb_auths_v2_supervisor[] = {
	/* 0 */
	{
		.type = afb_auth_Permission,
		.text = "urn:AGL:permission:#supervision:platform:access"
	}
};

static const struct afb_verb_v3 _afb_verbs_supervisor[] = {
    {
        .verb = "subscribe",
        .callback = f_subscribe,
        .auth = &_afb_auths_v2_supervisor[0],
        .info = NULL,
        .session = AFB_SESSION_CHECK_X2
    },
    {
        .verb = "list",
        .callback = f_list,
        .auth = &_afb_auths_v2_supervisor[0],
        .info = NULL,
        .session = AFB_SESSION_CHECK_X2
    },
    {
        .verb = "config",
        .callback = f_config,
        .auth = &_afb_auths_v2_supervisor[0],
        .info = NULL,
        .session = AFB_SESSION_CHECK_X2
    },
    {
        .verb = "do",
        .callback = f_do,
        .auth = &_afb_auths_v2_supervisor[0],
        .info = NULL,
        .session = AFB_SESSION_CHECK_X2
    },
    {
        .verb = "trace",
        .callback = f_trace,
        .auth = &_afb_auths_v2_supervisor[0],
        .info = NULL,
        .session = AFB_SESSION_CHECK_X2
    },
    {
        .verb = "sessions",
        .callback = f_sessions,
        .auth = &_afb_auths_v2_supervisor[0],
        .info = NULL,
        .session = AFB_SESSION_CHECK_X2
    },
    {
        .verb = "session-close",
        .callback = f_session_close,
        .auth = &_afb_auths_v2_supervisor[0],
        .info = NULL,
        .session = AFB_SESSION_CHECK_X2
    },
    {
        .verb = "exit",
        .callback = f_exit,
        .auth = &_afb_auths_v2_supervisor[0],
        .info = NULL,
        .session = AFB_SESSION_CHECK_X2
    },
    {
        .verb = "debug-wait",
        .callback = f_debug_wait,
        .auth = &_afb_auths_v2_supervisor[0],
        .info = NULL,
        .session = AFB_SESSION_CHECK_X2
    },
    {
        .verb = "debug-break",
        .callback = f_debug_break,
        .auth = &_afb_auths_v2_supervisor[0],
        .info = NULL,
        .session = AFB_SESSION_CHECK_X2
    },
    {
        .verb = "discover",
        .callback = f_discover,
        .auth = &_afb_auths_v2_supervisor[0],
        .info = NULL,
        .session = AFB_SESSION_CHECK_X2
    },
    { .verb = NULL }
};

static const struct afb_binding_v3 _afb_binding_supervisor = {
    .api = supervisor_apiname,
    .specification = NULL,
    .info = NULL,
    .verbs = _afb_verbs_supervisor,
    .preinit = NULL,
    .init = init_supervisor,
    .onevent = NULL,
    .noconcurrency = 0
};

int afs_supervisor_add(
		struct afb_apiset *declare_set,
		struct afb_apiset * call_set)
{
	return -!afb_api_v3_from_binding(&_afb_binding_supervisor, declare_set, call_set);
}

