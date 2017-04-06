/*
 * Copyright (C) 2015, 2016, 2017 "IoT.bzh"
 * Author "Fulup Ar Foll"
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
#define NO_BINDING_VERBOSE_MACRO

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <systemd/sd-event.h>
#include <systemd/sd-daemon.h>

#include <afb/afb-binding.h>

#include "afb-config.h"
#include "afb-hswitch.h"
#include "afb-apis.h"
#include "afb-api-so.h"
#include "afb-api-dbus.h"
#include "afb-api-ws.h"
#include "afb-hsrv.h"
#include "afb-context.h"
#include "afb-hreq.h"
#include "jobs.h"
#include "afb-session.h"
#include "verbose.h"
#include "afb-common.h"
#include "afb-hook.h"
#include "sd-fds.h"

/*
   if SELF_PGROUP == 0 the launched command is the group leader
   if SELF_PGROUP != 0 afb-daemon is the group leader
*/
#define SELF_PGROUP 1

static struct afb_config *config;
static pid_t childpid;

/*----------------------------------------------------------
 |   helpers for handling list of arguments
 +--------------------------------------------------------- */

/*
 * Calls the callback 'run' for each value of the 'list'
 * until the callback returns 0 or the end of the list is reached.
 * Returns either NULL if the end of the list is reached or a pointer
 * to the item whose value made 'run' return 0.
 * 'closure' is used for passing user data.
 */
static struct afb_config_list *run_for_list(struct afb_config_list *list,
					    int (*run) (void *closure, char *value),
					    void *closure)
{
	while (list && run(closure, list->value))
		list = list->next;
	return list;
}

static int run_start(void *closure, char *value)
{
	int (*starter) (const char *value) = closure;
	return starter(value) >= 0;
}

static void start_list(struct afb_config_list *list,
		       int (*starter) (const char *value), const char *message)
{
	list = run_for_list(list, run_start, starter);
	if (list) {
		ERROR("can't start %s %s", message, list->value);
		exit(1);
	}
}

/*----------------------------------------------------------
 | exit_handler
 |   Handles on exit specific actions
 +--------------------------------------------------------- */
static void exit_handler()
{
	if (SELF_PGROUP)
		killpg(0, SIGHUP);
	else if (childpid > 0)
		killpg(childpid, SIGHUP);
}

/*----------------------------------------------------------
 | daemonize
 |   set the process in background
 +--------------------------------------------------------- */
static void daemonize()
{
	int consoleFD;
	int pid;

	// open /dev/console to redirect output messAFBes
	consoleFD = open(config->console, O_WRONLY | O_APPEND | O_CREAT, 0640);
	if (consoleFD < 0) {
		ERROR("AFB-daemon cannot open /dev/console (use --foreground)");
		exit(1);
	}
	// fork process when running background mode
	pid = fork();

	// if fail nothing much to do
	if (pid == -1) {
		ERROR("AFB-daemon Failed to fork son process");
		exit(1);
	}
	// if in father process, just leave
	if (pid != 0)
		_exit(0);

	// son process get all data in standalone mode
	NOTICE("background mode [pid:%d console:%s]", getpid(),
	       config->console);

	// redirect default I/O on console
	close(2);
	dup(consoleFD);		// redirect stderr
	close(1);
	dup(consoleFD);		// redirect stdout
	close(0);		// no need for stdin
	close(consoleFD);

#if 0
	setsid();		// allow father process to fully exit
	sleep(2);		// allow main to leave and release port
#endif
}

/*---------------------------------------------------------
 | http server
 |   Handles the HTTP server
 +--------------------------------------------------------- */
static int init_alias(void *closure, char *spec)
{
	struct afb_hsrv *hsrv = closure;
	char *path = strchr(spec, ':');

	if (path == NULL) {
		ERROR("Missing ':' in alias %s. Alias ignored", spec);
		return 1;
	}
	*path++ = 0;
	INFO("Alias for url=%s to path=%s", spec, path);
	return afb_hsrv_add_alias(hsrv, spec, afb_common_rootdir_get_fd(), path,
				  0, 0);
}

static int init_http_server(struct afb_hsrv *hsrv)
{
	if (!afb_hsrv_add_handler
	    (hsrv, config->rootapi, afb_hswitch_websocket_switch, NULL, 20))
		return 0;

	if (!afb_hsrv_add_handler
	    (hsrv, config->rootapi, afb_hswitch_apis, NULL, 10))
		return 0;

	if (run_for_list(config->aliases, init_alias, hsrv))
		return 0;

	if (config->roothttp != NULL) {
		if (!afb_hsrv_add_alias
		    (hsrv, "", afb_common_rootdir_get_fd(), config->roothttp,
		     -10, 1))
			return 0;
	}

	if (!afb_hsrv_add_handler
	    (hsrv, config->rootbase, afb_hswitch_one_page_api_redirect, NULL,
	     -20))
		return 0;

	return 1;
}

static struct afb_hsrv *start_http_server()
{
	int rc;
	struct afb_hsrv *hsrv;

	if (afb_hreq_init_download_path(config->uploaddir)) {
		ERROR("unable to set the upload directory %s", config->uploaddir);
		return NULL;
	}

	hsrv = afb_hsrv_create();
	if (hsrv == NULL) {
		ERROR("memory allocation failure");
		return NULL;
	}

	if (!afb_hsrv_set_cache_timeout(hsrv, config->cacheTimeout)
	    || !init_http_server(hsrv)) {
		ERROR("initialisation of httpd failed");
		afb_hsrv_put(hsrv);
		return NULL;
	}

	NOTICE("Waiting port=%d rootdir=%s", config->httpdPort, config->rootdir);
	NOTICE("Browser URL= http:/*localhost:%d", config->httpdPort);

	rc = afb_hsrv_start(hsrv, (uint16_t) config->httpdPort, 15);
	if (!rc) {
		ERROR("starting of httpd failed");
		afb_hsrv_put(hsrv);
		return NULL;
	}

	return hsrv;
}

/*---------------------------------------------------------
 | execute_command
 |   
 +--------------------------------------------------------- */

static void on_sigchld(int signum, siginfo_t *info, void *uctx)
{
	if (info->si_pid == childpid) {
		switch (info->si_code) {
		case CLD_EXITED:
		case CLD_KILLED:
		case CLD_DUMPED:
			childpid = 0;
			if (!SELF_PGROUP)
				killpg(info->si_pid, SIGKILL);
			waitpid(info->si_pid, NULL, 0);
			exit(0);
		}
	}
}

/*
# @@ @
# @p port
# @t token
*/

#define SUBST_CHAR  '@'
#define SUBST_STR   "@"

static char *instanciate_string(char *arg, const char *port, const char *token)
{
	char *resu, *it, *wr;
	int chg, dif;

	/* get the changes */
	chg = 0;
	dif = 0;
	it = strchrnul(arg, SUBST_CHAR);
	while (*it) {
		switch(*++it) {
		case 'p': chg++; dif += (int)strlen(port) - 2; break;
		case 't': chg++; dif += (int)strlen(token) - 2; break;
		case SUBST_CHAR: it++; chg++; dif--; break;
		default: break;
		}
		it = strchrnul(it, SUBST_CHAR);
	}

	/* return arg when no change */
	if (!chg)
		return arg;

	/* allocates the result */
	resu = malloc((it - arg) + dif + 1);
	if (!resu) {
		ERROR("out of memory");
		return NULL;
	}

	/* instanciate the arguments */
	wr = resu;
	for (;;) {
		it = strchrnul(arg, SUBST_CHAR);
		wr = mempcpy(wr, arg, it - arg);
		if (!*it)
			break;
		switch(*++it) {
		case 'p': wr = stpcpy(wr, port); break;
		case 't': wr = stpcpy(wr, token); break;
		default: *wr++ = SUBST_CHAR;
		case SUBST_CHAR: *wr++ = *it;
		}
		arg = ++it;
	}

	*wr = 0;
	return resu;
}

static int instanciate_environ(const char *port, const char *token)
{
	extern char **environ;
	char *repl;
	int i;

	/* instanciate the environment */
	for (i = 0 ; environ[i] ; i++) {
		repl = instanciate_string(environ[i], port, token);
		if (!repl)
			return -1;
		environ[i] = repl;
	}
	return 0;
}

static int instanciate_command_args(const char *port, const char *token)
{
	char *repl;
	int i;

	/* instanciate the arguments */
	for (i = 0 ; config->exec[i] ; i++) {
		repl = instanciate_string(config->exec[i], port, token);
		if (!repl)
			return -1;
		config->exec[i] = repl;
	}
	return 0;
}

static int execute_command()
{
	struct sigaction siga;
	char port[20];
	int rc;

	/* check whether a command is to execute or not */
	if (!config->exec || !config->exec[0])
		return 0;

	if (SELF_PGROUP)
		setpgid(0, 0);

	/* install signal handler */
	memset(&siga, 0, sizeof siga);
	siga.sa_sigaction = on_sigchld;
	siga.sa_flags = SA_SIGINFO;
	sigaction(SIGCHLD, &siga, NULL);

	/* fork now */
	childpid = fork();
	if (childpid)
		return 0;

	/* compute the string for port */
	if (config->httpdPort)
		rc = snprintf(port, sizeof port, "%d", config->httpdPort);
	else
		rc = snprintf(port, sizeof port, "%cp", SUBST_CHAR);
	if (rc < 0 || rc >= (int)(sizeof port)) {
		ERROR("port->txt failed");
	}
	else {
		/* instanciate arguments and environment */
		if (instanciate_command_args(port, config->token) >= 0
		 && instanciate_environ(port, config->token) >= 0) {
			/* run */
			if (!SELF_PGROUP)
				setpgid(0, 0);
			execv(config->exec[0], config->exec);
			ERROR("can't launch %s: %m", config->exec[0]);
		}
	}
	exit(1);
	return -1;
}

/*---------------------------------------------------------
 | job for starting the daemon
 +--------------------------------------------------------- */

static void start()
{
	struct afb_hsrv *hsrv;

	// ------------------ sanity check ----------------------------------------
	if (config->httpdPort <= 0) {
		ERROR("no port is defined");
		goto error;
	}

	mkdir(config->workdir, S_IRWXU | S_IRGRP | S_IXGRP);
	if (chdir(config->workdir) < 0) {
		ERROR("Can't enter working dir %s", config->workdir);
		goto error;
	}

	afb_apis_set_timeout(config->apiTimeout);
	start_list(config->dbus_clients, afb_api_dbus_add_client, "the afb-dbus client");
	start_list(config->ws_clients, afb_api_ws_add_client, "the afb-websocket client");
	start_list(config->ldpaths, afb_api_so_add_pathset, "the binding path set");
	start_list(config->so_bindings, afb_api_so_add_binding, "the binding");

	afb_session_init(config->nbSessionMax, config->cntxTimeout, config->token);

	start_list(config->dbus_servers, afb_api_dbus_add_server, "the afb-dbus service");
	start_list(config->ws_servers, afb_api_ws_add_server, "the afb-websocket service");

	if (!afb_hreq_init_cookie(config->httpdPort, config->rootapi, config->cntxTimeout)) {
		ERROR("initialisation of cookies failed");
		goto error;
	}

	// set the root dir
	if (afb_common_rootdir_set(config->rootdir) < 0) {
		ERROR("failed to set common root directory");
		goto error;
	}

	DEBUG("Init config done");

	/* install trace of requests */
	if (config->tracereq)
		afb_hook_xreq_create(NULL, NULL, NULL, config->tracereq, NULL, NULL);

	/* start the services */
	if (afb_apis_start_all_services(1) < 0)
		goto error;

	/* start the HTTP server */
	if (!config->noHttpd) {
		hsrv = start_http_server();
		if (hsrv == NULL)
			goto error;
	}

	/* run the command */
	if (execute_command() < 0)
		goto error;

	/* ready */
	sd_notify(1, "READY=1");
	return;
error:
	exit(1);
}
/*---------------------------------------------------------
 | main
 |   Parse option and launch action
 +--------------------------------------------------------- */

int main(int argc, char *argv[])
{
	// let's run this program with a low priority
	nice(20);

	LOGAUTH("afb-daemon");

	sd_fds_init();

	// ------------- Build session handler & init config -------
	config = afb_config_parse_arguments(argc, argv);
	INFO("running with pid %d", getpid());

	// --------- run -----------
	if (config->background) {
		// --------- in background mode -----------
		INFO("entering background mode");
		daemonize();
	} else {
		// ---- in foreground mode --------------------
		INFO("entering foreground mode");
	}

	/* handle groups */
	atexit(exit_handler);

	/* ignore any SIGPIPE */
	signal(SIGPIPE, SIG_IGN);

	/* enter job processing */
	jobs_start(3, 0, 50, start);
	WARNING("hoops returned from jobs_enter! [report bug]");
	return 1;
}

