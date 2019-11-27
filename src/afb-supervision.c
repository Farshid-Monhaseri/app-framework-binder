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

#if WITH_SUPERVISION

#define _GNU_SOURCE

#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <json-c/json.h>

#define AFB_BINDING_VERSION 3
#include <afb/afb-binding.h>

#include "afb-cred.h"
#include "afb-api.h"
#include "afb-apiset.h"
#include "afb-api-so-v2.h"
#include "afb-xreq.h"
#include "afb-trace.h"
#include "afb-session.h"
#include "afb-args.h"
#include "afb-supervision.h"
#include "afs-supervision.h"
#include "afb-stub-ws.h"
#include "afb-debug.h"
#include "afb-fdev.h"
#include "afb-error-text.h"
#include "verbose.h"
#include "wrap-json.h"
#include "jobs.h"

/* api and apiset name */
static const char supervision_apiname[] = AFS_SUPERVISION_APINAME;
#if WITH_AFB_TRACE
static const char supervisor_apiname[] = AFS_SUPERVISOR_APINAME;
#endif

/* path of the supervision socket */
static const char supervisor_socket_path[] = AFS_SUPERVISION_SOCKET;

/* mutual exclusion */
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

/* the standard apiset */
static struct {
	struct afb_apiset *apiset;
	struct json_object *config;
} global;

/* the supervision apiset (not exported) */
static struct afb_apiset *supervision_apiset;

/* local api implementation */
static void on_supervision_call(void *closure, struct afb_xreq *xreq);
static struct afb_api_itf supervision_api_itf =
{
	.call = on_supervision_call
};

/* the supervisor link */
static struct afb_stub_ws *supervisor;

#if WITH_AFB_TRACE
/* the trace api */
static struct afb_trace *trace;
#endif

/* open the socket */
static int open_supervisor_socket(const char *path)
{
	int fd, rc;
	struct sockaddr_un addr;
	size_t length;

	/* check path length */
	length = strlen(path);
	if (length >= 108) {
		errno = ENAMETOOLONG;
		return -1;
	}

	/* create the unix socket */
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return fd;

	/* prepare the connection address */
	memset(&addr, 0, sizeof addr);
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, path);
	if (addr.sun_path[0] == '@')
		addr.sun_path[0] = 0; /* implement abstract sockets */

	/* connect the socket */
	rc = connect(fd, (struct sockaddr *) &addr, (socklen_t)(sizeof addr));
	if (rc < 0) {
		close(fd);
		return rc;
	}
	return fd;
}

static void disconnect_supervisor()
{
	struct afb_stub_ws *s;

	INFO("Disconnecting supervision");
	s = __atomic_exchange_n(&supervisor, NULL, __ATOMIC_RELAXED);
	if (s)
		afb_stub_ws_unref(s);

#if WITH_AFB_TRACE
	struct afb_trace *t = __atomic_exchange_n(&trace, NULL, __ATOMIC_RELAXED);
	if (t)
		afb_trace_unref(t);
#endif
}

static void on_supervisor_hangup(struct afb_stub_ws *s)
{
	if (s && s == supervisor)
		disconnect_supervisor();
}

/* try to connect to supervisor */
static void try_connect_supervisor()
{
	int fd;
	ssize_t srd;
	struct afs_supervision_initiator initiator;
	struct fdev *fdev;

	/* get the mutex */
	pthread_mutex_lock(&mutex);

	/* needs to connect? */
	if (supervisor || !supervision_apiset)
		goto end;

	/* check existing path */
	if (supervisor_socket_path[0] != '@' && access(supervisor_socket_path, F_OK)) {
		NOTICE("Can't acces socket path %s: %m", supervisor_socket_path);
		goto end;
	}

	/* socket connection */
	fd = open_supervisor_socket(supervisor_socket_path);
	if (fd < 0) {
		NOTICE("Can't connect supervision socket to %s: %m", supervisor_socket_path);
		goto end;
	}

	/* negotiation */
	do { srd = read(fd, &initiator, sizeof initiator); } while(srd < 0 && errno == EINTR);
	if (srd < 0) {
		NOTICE("Can't read supervisor %s: %m", supervisor_socket_path);
		goto end2;
	}
	if ((size_t)srd != sizeof initiator) {
		ERROR("When reading supervisor %s: %m", supervisor_socket_path);
		goto end2;
	}
	if (strnlen(initiator.interface, sizeof initiator.interface) == sizeof initiator.interface) {
		ERROR("Bad interface of supervisor %s", supervisor_socket_path);
		goto end2;
	}
	if (strcmp(initiator.interface, AFS_SUPERVISION_INTERFACE_1)) {
		ERROR("Unknown interface %s for supervisor %s", initiator.interface, supervisor_socket_path);
		goto end2;
	}
	if (strnlen(initiator.extra, sizeof initiator.extra) == sizeof initiator.extra) {
		ERROR("Bad extra of supervisor %s", supervisor_socket_path);
		goto end2;
	}

	/* interprets extras */
	if (!strcmp(initiator.extra, "CLOSE")) {
		INFO("Supervisor asks to CLOSE");
		goto end2;
	}
	if (!strcmp(initiator.extra, "WAIT")) {
		afb_debug_wait("supervisor");
	}
	if (!strcmp(initiator.extra, "BREAK")) {
		afb_debug_break("supervisor");
	}

	/* make the supervisor link */
	fdev = afb_fdev_create(fd);
	if (!fdev) {
		ERROR("Creation of fdev failed: %m");
		goto end2;
	}
	supervisor = afb_stub_ws_create_server(fdev, supervision_apiname, supervision_apiset);
	if (!supervisor) {
		ERROR("Creation of supervisor failed: %m");
		goto end;
	}
	afb_stub_ws_set_on_hangup(supervisor, on_supervisor_hangup);

	/* successful termination */
	goto end;

end2:
	close(fd);
end:
	pthread_mutex_unlock(&mutex);
}

static void try_connect_supervisor_job(int signum, void *args)
{
	INFO("Try to connect supervisor after SIGHUP");
	try_connect_supervisor();
}

static void on_sighup(int signum)
{
	INFO("Supervision received a SIGHUP");
	jobs_queue(NULL, 0, try_connect_supervisor_job, NULL);
}

/**
 * initialize the supervision
 */
int afb_supervision_init(struct afb_apiset *apiset, struct json_object *config)
{
	int rc;
	struct sigaction sa;

	/* don't reinit */
	if (supervision_apiset)
		return 0;

	/* create the apiset */
	supervision_apiset = afb_apiset_create(supervision_apiname, 0);
	if (!supervision_apiset) {
		ERROR("Can't create supervision's apiset");
		return -1;
	}

	/* init the apiset */
	rc = afb_apiset_add(supervision_apiset, supervision_apiname,
			(struct afb_api_item){ .itf = &supervision_api_itf, .closure = NULL});
	if (rc < 0) {
		ERROR("Can't create supervision's apiset: %m");
		afb_apiset_unref(supervision_apiset);
		supervision_apiset = NULL;
		return rc;
	}

	/* init the globals */
	global.apiset = apiset;
	global.config = config;

	/* get SIGHUP */
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = on_sighup;
	rc = sigaction(SIGHUP, &sa, NULL);
	if (rc < 0)
		ERROR("Can't connect supervision to SIGHUP: %m");

	/* connect to supervision */
	try_connect_supervisor();
	return 0;
}

/******************************************************************************
**** Implementation monitoring verbs
******************************************************************************/
static void slist(void *closure, struct afb_session *session)
{
	struct json_object *list = closure;

	json_object_object_add(list, afb_session_uuid(session), NULL);
}

/******************************************************************************
**** Implementation monitoring verbs
******************************************************************************/

static const char *verbs[] = {
	"break", "config", "do", "exit", "sclose", "slist", "trace", "wait" };
enum  {  Break ,  Config ,  Do ,  Exit ,  Sclose ,  Slist ,  Trace ,  Wait  };

static void on_supervision_call(void *closure, struct afb_xreq *xreq)
{
	int i;
	struct json_object *args, *sub, *list;
	const char *api, *verb, *uuid;
	struct afb_session *session;
	const struct afb_api_item *xapi;
	afb_req_t req;
#if WITH_AFB_TRACE
	struct json_object *drop, *add;
	int rc;
#endif

	/* search the verb */
	i = (int)(sizeof verbs / sizeof *verbs);
	while(--i >= 0 && strcasecmp(verbs[i], xreq->request.called_verb));
	if (i < 0) {
		afb_xreq_reply_unknown_verb(xreq);
		return;
	}

	/* process */
	args = afb_xreq_json(xreq);
	switch(i) {
	case Exit:
		i = 0;
		if (wrap_json_unpack(args, "i", &i))
			wrap_json_unpack(args, "{si}", "code", &i);
		ERROR("exiting from supervision with code %d -> %d", i, i & 127);
		exit(i & 127);
		break;
	case Sclose:
		uuid = NULL;
		if (wrap_json_unpack(args, "s", &uuid))
			wrap_json_unpack(args, "{ss}", "uuid", &uuid);
		if (!uuid)
			afb_xreq_reply(xreq, NULL, afb_error_text_invalid_request, NULL);
		else {
			session = afb_session_search(uuid);
			if (!session)
				afb_xreq_reply(xreq, NULL, afb_error_text_unknown_session, NULL);
			else {
				afb_session_close(session);
				afb_session_unref(session);
				afb_session_purge();
				afb_xreq_reply(xreq, NULL, NULL, NULL);
			}
		}
		break;
	case Slist:
		list = json_object_new_object();
		afb_session_foreach(slist, list);
		afb_xreq_reply(xreq, list, NULL, NULL);
		break;
	case Config:
		afb_xreq_reply(xreq, json_object_get(global.config), NULL, NULL);
		break;
	case Trace:
		req = xreq_to_req_x2(xreq);
#if WITH_AFB_TRACE
		if (!trace)
			trace = afb_trace_create(supervisor_apiname, NULL /* not bound to any session */);

		add = drop = NULL;
		wrap_json_unpack(args, "{s?o s?o}", "add", &add, "drop", &drop);
		if (add) {
			rc = afb_trace_add(req, add, trace);
			if (rc)
				return;
		}
		if (drop) {
			rc = afb_trace_drop(req, drop, trace);
			if (rc)
				return;
		}
		afb_req_success(req, NULL, NULL);
#else
		afb_req_reply(req, NULL, afb_error_text_not_available, NULL);
#endif
		break;
	case Do:
		sub = NULL;
		if (wrap_json_unpack(args, "{ss ss s?o*}", "api", &api, "verb", &verb, "args", &sub))
			afb_xreq_reply(xreq, NULL, afb_error_text_invalid_request, NULL);
		else {
			xapi = afb_apiset_lookup_started(global.apiset, api, 1);
			if (!xapi)
				afb_xreq_reply_unknown_api(xreq);
			else {
				afb_cred_unref(xreq->cred);
				xreq->cred = NULL;
				xreq->request.called_api = api;
				xreq->request.called_verb = verb;
				xreq->json = json_object_get(sub);
				xapi->itf->call(xapi->closure, xreq);
				json_object_put(args);
			}
		}
		break;
	case Wait:
		afb_xreq_reply(xreq, NULL, NULL, NULL);
		afb_debug_wait("supervisor");
		break;
	case Break:
		afb_xreq_reply(xreq, NULL, NULL, NULL);
		afb_debug_break("supervisor");
		break;
	}
}

#endif
