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

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include <systemd/sd-daemon.h>

#include "afb-common.h"
#include "afb-hsrv.h"
#include "afb-hswitch.h"
#include "afb-hreq.h"
#include "afb-apiset.h"
#include "afb-api-ws.h"
#include "afb-session.h"

#include "afs-supervisor.h"
#include "afs-args.h"

#include "verbose.h"
#include "jobs.h"
#include "process-name.h"
#include "watchdog.h"

#if !defined(DEFAULT_SUPERVISOR_INTERFACE)
#  define DEFAULT_SUPERVISOR_INTERFACE NULL
#endif

/* the main config */
struct afs_args *main_config;

/* the main apiset */
struct afb_apiset *main_apiset;

/*************************************************************************************/

static int init_http_server(struct afb_hsrv *hsrv)
{
	if (!afb_hsrv_add_handler
	    (hsrv, main_config->rootapi, afb_hswitch_websocket_switch, main_apiset, 20))
		return 0;

	if (!afb_hsrv_add_handler
	    (hsrv, main_config->rootapi, afb_hswitch_apis, main_apiset, 10))
		return 0;

	if (main_config->roothttp != NULL) {
		if (!afb_hsrv_add_alias
		    (hsrv, "", afb_common_rootdir_get_fd(), main_config->roothttp,
		     -10, 1))
			return 0;
	}

	if (!afb_hsrv_add_handler
	    (hsrv, main_config->rootbase, afb_hswitch_one_page_api_redirect, NULL,
	     -20))
		return 0;

	return 1;
}

static struct afb_hsrv *start_http_server()
{
	int rc;
	struct afb_hsrv *hsrv;

	if (afb_hreq_init_download_path(main_config->uploaddir)) {
		ERROR("unable to set the upload directory %s", main_config->uploaddir);
		return NULL;
	}

	hsrv = afb_hsrv_create();
	if (hsrv == NULL) {
		ERROR("memory allocation failure");
		return NULL;
	}

	if (!afb_hsrv_set_cache_timeout(hsrv, main_config->cacheTimeout)
	    || !init_http_server(hsrv)) {
		ERROR("initialisation of httpd failed");
		afb_hsrv_put(hsrv);
		return NULL;
	}

	NOTICE("Waiting port=%d rootdir=%s", main_config->httpdPort, main_config->rootdir);
	NOTICE("Browser URL= http://localhost:%d", main_config->httpdPort);

	rc = afb_hsrv_start(hsrv, 15);
	if (!rc) {
		ERROR("starting of httpd failed");
		afb_hsrv_put(hsrv);
		return NULL;
	}

	rc = afb_hsrv_add_interface_tcp(hsrv, DEFAULT_SUPERVISOR_INTERFACE, (uint16_t) main_config->httpdPort);
	if (!rc) {
		ERROR("setting interface failed");
		afb_hsrv_put(hsrv);
		return NULL;
	}

	return hsrv;
}

static void start(int signum, void *arg)
{
	struct afb_hsrv *hsrv;
	int rc;

	/* check illness */
	if (signum) {
		ERROR("start aborted: received signal %s", strsignal(signum));
		exit(1);
	}

	/* set the directories */
	mkdir(main_config->workdir, S_IRWXU | S_IRGRP | S_IXGRP);
	if (chdir(main_config->workdir) < 0) {
		ERROR("Can't enter working dir %s", main_config->workdir);
		goto error;
	}
	if (afb_common_rootdir_set(main_config->rootdir) < 0) {
		ERROR("failed to set common root directory");
		goto error;
	}

	/* configure the daemon */
	if (afb_session_init(main_config->nbSessionMax, main_config->cntxTimeout)) {
		ERROR("initialisation of session manager failed");
		goto error;
	}

	main_apiset = afb_apiset_create("main", main_config->apiTimeout);
	if (!main_apiset) {
		ERROR("can't create main apiset");
		goto error;
	}

	/* init the main apiset */
	rc = afs_supervisor_add(main_apiset, main_apiset);
	if (rc < 0) {
		ERROR("Can't create supervision's apiset: %m");
		goto error;
	}

	/* export the service if required */
	if (main_config->ws_server) {
		rc = afb_api_ws_add_server(main_config->ws_server, main_apiset, main_apiset);
		if (rc < 0) {
			ERROR("Can't export (ws-server) api %s: %m", main_config->ws_server);
			goto error;
		}
	}

	/* start the services */
	if (afb_apiset_start_all_services(main_apiset) < 0)
		goto error;

	/* start the HTTP server */
	if (main_config->httpdPort <= 0) {
		ERROR("no port is defined");
		goto error;
	}

	if (!afb_hreq_init_cookie(main_config->httpdPort, main_config->rootapi, main_config->cntxTimeout)) {
		ERROR("initialisation of HTTP cookies failed");
		goto error;
	}

	hsrv = start_http_server();
	if (hsrv == NULL)
		goto error;

	/* ready */
	sd_notify(1, "READY=1");

	/* activate the watchdog */
#if HAS_WATCHDOG
	if (watchdog_activate() < 0)
		ERROR("can't start the watchdog");
#endif

	/* discover binders */
	afs_supervisor_discover();
	return;
error:
	exit(1);
}

/**
 * initialize the supervision
 */
int main(int ac, char **av)
{
	/* scan arguments */
	main_config = afs_args_parse(ac, av);
	if (main_config->name) {
		verbose_set_name(main_config->name, 0);
		process_name_set_name(main_config->name);
		process_name_replace_cmdline(av, main_config->name);
	}
	/* enter job processing */
	jobs_start(3, 0, 10, start, av[1]);
	WARNING("hoops returned from jobs_enter! [report bug]");
	return 1;
}

