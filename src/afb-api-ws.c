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

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <endian.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "afb-api.h"
#include "afb-apiset.h"
#include "afb-api-ws.h"
#include "afb-fdev.h"
#include "afb-socket.h"
#include "afb-stub-ws.h"
#include "verbose.h"
#include "fdev.h"

struct api_ws_server
{
	struct afb_apiset *apiset;	/* the apiset for calling */
	struct fdev *fdev;		/* fdev handler */
	uint16_t offapi;		/* api name of the interface */
	char uri[];			/* the uri of the server socket */
};

/******************************************************************************/
/***       C L I E N T                                                      ***/
/******************************************************************************/

static struct fdev *reopen_client(void *closure)
{
	const char *uri = closure;
	return afb_socket_open_fdev(uri, 0);
}

int afb_api_ws_add_client(const char *uri, struct afb_apiset *declare_set, struct afb_apiset *call_set, int strong)
{
	struct afb_stub_ws *stubws;
	struct fdev *fdev;
	const char *api;

	/* check the api name */
	api = afb_socket_api(uri);
	if (api == NULL || !afb_api_is_valid_name(api)) {
		ERROR("invalid (too long) ws client uri %s", uri);
		errno = EINVAL;
		goto error;
	}

	/* open the socket */
	fdev = afb_socket_open_fdev(uri, 0);
	if (fdev) {
		/* create the client stub */
		stubws = afb_stub_ws_create_client(fdev, api, call_set);
		if (!stubws) {
			ERROR("can't setup client ws service to %s", uri);
			fdev_unref(fdev);
		} else {
			if (afb_stub_ws_client_add(stubws, declare_set) >= 0) {
#if 1
				/* it is asserted here that uri is never released */
				afb_stub_ws_client_robustify(stubws, reopen_client, (void*)uri, NULL);
#else
				/* it is asserted here that uri is released, so use a copy */
				afb_stub_ws_client_robustify(stubws, reopen_client, strdup(uri), free);
#endif
				return 0;
			}
			ERROR("can't add the client to the apiset for service %s", uri);
			afb_stub_ws_unref(stubws);
		}
	}
error:
	return -!!strong;
}

int afb_api_ws_add_client_strong(const char *uri, struct afb_apiset *declare_set, struct afb_apiset *call_set)
{
	return afb_api_ws_add_client(uri, declare_set, call_set, 1);
}

int afb_api_ws_add_client_weak(const char *uri, struct afb_apiset *declare_set, struct afb_apiset *call_set)
{
	return afb_api_ws_add_client(uri, declare_set, call_set, 0);
}

/*****************************************************************************/
/***       S E R V E R                                                      ***/
/******************************************************************************/

static void api_ws_server_accept(struct api_ws_server *apiws)
{
	int fd;
	struct sockaddr addr;
	socklen_t lenaddr;
	struct fdev *fdev;
	struct afb_stub_ws *server;

	lenaddr = (socklen_t)sizeof addr;
	fd = accept(fdev_fd(apiws->fdev), &addr, &lenaddr);
	if (fd < 0) {
		ERROR("can't accept connection to %s: %m", apiws->uri);
	} else {
		fdev = afb_fdev_create(fd);
		if (!fdev) {
			ERROR("can't hold accepted connection to %s: %m", apiws->uri);
			close(fd);
		} else {
			server = afb_stub_ws_create_server(fdev, &apiws->uri[apiws->offapi], apiws->apiset);
			if (!server)
				ERROR("can't serve accepted connection to %s: %m", apiws->uri);
		}
	}
}

static int api_ws_server_connect(struct api_ws_server *apiws);

static void api_ws_server_listen_callback(void *closure, uint32_t revents, struct fdev *fdev)
{
	struct api_ws_server *apiws = closure;

	if ((revents & EPOLLIN) != 0)
		api_ws_server_accept(apiws);
	if ((revents & EPOLLHUP) != 0)
		api_ws_server_connect(apiws);
}

static void api_ws_server_disconnect(struct api_ws_server *apiws)
{
	fdev_unref(apiws->fdev);
	apiws->fdev = 0;
}

static int api_ws_server_connect(struct api_ws_server *apiws)
{
	/* ensure disconnected */
	api_ws_server_disconnect(apiws);

	/* request the service object name */
	apiws->fdev = afb_socket_open_fdev(apiws->uri, 1);
	if (!apiws->fdev)
		ERROR("can't create socket %s", apiws->uri);
	else {
		/* listen for service */
		fdev_set_events(apiws->fdev, EPOLLIN);
		fdev_set_callback(apiws->fdev, api_ws_server_listen_callback, apiws);
		return 0;
	}
	return -1;
}

/* create the service */
int afb_api_ws_add_server(const char *uri, struct afb_apiset *declare_set, struct afb_apiset *call_set)
{
	int rc;
	const char *api;
	struct api_ws_server *apiws;
	size_t luri, lapi, extra;

	/* check the size */
	luri = strlen(uri);
	if (luri > 4000) {
		ERROR("can't create socket %s", uri);
		errno = E2BIG;
		return -1;
	}

	/* check the api name */
	api = afb_socket_api(uri);
	if (api == NULL || !afb_api_is_valid_name(api)) {
		ERROR("invalid api name in ws uri %s", uri);
		errno = EINVAL;
		goto error;
	}

	/* check api name */
	if (!afb_apiset_lookup(call_set, api, 1)) {
		ERROR("Can't provide ws-server for URI %s: API %s doesn't exist", uri, api);
		errno = ENOENT;
		goto error;
	}

	/* make the structure */
	lapi = strlen(api);
	extra = luri == (api - uri) + lapi ? 0 : lapi + 1;
	apiws = malloc(sizeof * apiws + 1 + luri + extra);
	if (!apiws) {
		ERROR("out of memory");
		errno = ENOMEM;
		goto error;
	}

	apiws->apiset = afb_apiset_addref(call_set);
	apiws->fdev = 0;
	strcpy(apiws->uri, uri);
	if (!extra)
		apiws->offapi = (uint16_t)(api - uri);
	else {
		apiws->offapi = (uint16_t)(luri + 1);
		strcpy(&apiws->uri[apiws->offapi], api);
	}

	/* connect for serving */
	rc = api_ws_server_connect(apiws);
	if (rc >= 0)
		return 0;

	afb_apiset_unref(apiws->apiset);
	free(apiws);
error:
	return -1;
}
