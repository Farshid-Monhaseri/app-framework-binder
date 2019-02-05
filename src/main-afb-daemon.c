/*
 * Copyright (C) 2015-2019 "IoT.bzh"
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

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>

#if !defined(NO_CALL_PERSONALITY)
#include <sys/personality.h>
#endif

#include <json-c/json.h>

#include <systemd/sd-daemon.h>

#include "afb-config.h"
#include "afb-hswitch.h"
#include "afb-apiset.h"
#include "afb-autoset.h"
#include "afb-api-so.h"
#if defined(WITH_DBUS_TRANSPARENCY)
#   include "afb-api-dbus.h"
#endif
#include "afb-api-ws.h"
#include "afb-hsrv.h"
#include "afb-hreq.h"
#include "afb-xreq.h"
#include "afb-session.h"
#include "verbose.h"
#include "afb-common.h"
#include "afb-export.h"
#include "afb-monitor.h"
#include "afb-hook.h"
#include "afb-hook-flags.h"
#include "afb-debug.h"
#if defined(WITH_SUPERVISION)
#   include "afb-supervision.h"
#endif

#include "process-name.h"
#include "wrap-json.h"
#include "jobs.h"
#include "sig-monitor.h"

#if !defined(DEFAULT_BINDER_INTERFACE)
#  define DEFAULT_BINDER_INTERFACE NULL
#endif

/*
   if SELF_PGROUP == 0 the launched command is the group leader
   if SELF_PGROUP != 0 afb-daemon is the group leader
*/
#define SELF_PGROUP 0

struct afb_apiset *main_apiset;
struct json_object *main_config;

static pid_t childpid;

/**
 * Tiny helper around putenv: add the variable name=value
 *
 * @param name name of the variable to set
 * @param value value to set to the variable
 *
 * @return 0 in case of success or -1 in case of error (with errno set to ENOMEM)
 */
static int addenv(const char *name, const char *value)
{
	char *head, *middle;

	head = malloc(2 + strlen(name) + strlen(value));
	if (head == NULL) {
		errno = ENOMEM;
		return -1;
	}
	middle = stpcpy(head, name);
	middle[0] = '=';
	strcpy(&middle[1], value);
	return putenv(head);
}

/**
 * Tiny helper around addenv that export the real path
 *
 * @param name name of the variable to set
 * @param path the path value to export to the variable
 *
 * @return 0 in case of success or -1 in case of error (with errno set to ENOMEM)
 */
static int addenv_realpath(const char *name, const char *path)
{
	char buffer[PATH_MAX];
	char *p = realpath(path, buffer);
	return p ? addenv(name, p) : -1;
}

/**
 * Tiny helper around addenv that export an integer
 *
 * @param name name of the variable to set
 * @param value the integer value to export
 *
 * @return 0 in case of success or -1 in case of error (with errno set to ENOMEM)
 */
static int addenv_int(const char *name, int value)
{
	char buffer[64];
	snprintf(buffer, sizeof buffer, "%d", value);
	return addenv(name, buffer);
}

/*----------------------------------------------------------
 |   helpers for handling list of arguments
 +--------------------------------------------------------- */

static const char *run_for_config_array_opt(const char *name,
					    int (*run) (void *closure, const char *value),
					    void *closure)
{
	int i, n, rc;
	struct json_object *array, *value;

	if (json_object_object_get_ex(main_config, name, &array)) {
		if (!json_object_is_type(array, json_type_array))
			return json_object_get_string(array);
		n = (int)json_object_array_length(array);
		for (i = 0 ; i < n ; i++) {
			value = json_object_array_get_idx(array, i);
			rc = run(closure, json_object_get_string(value));
			if (!rc)
				return json_object_get_string(value);
		}
	}
	return NULL;
}

static int run_start(void *closure, const char *value)
{
	int (*starter) (const char *value, struct afb_apiset *declare_set, struct afb_apiset *call_set) = closure;
	return starter(value, main_apiset, main_apiset) >= 0;
}

static void apiset_start_list(const char *name,
			int (*starter) (const char *value, struct afb_apiset *declare_set, struct afb_apiset *call_set),
			const char *message)
{
	const char *item = run_for_config_array_opt(name, run_start, starter);
	if (item) {
		ERROR("can't start %s %s", message, item);
		exit(1);
	}
}

/*----------------------------------------------------------
 | exit_handler
 |   Handles on exit specific actions
 +--------------------------------------------------------- */
static void exit_handler()
{
	struct sigaction siga;

	memset(&siga, 0, sizeof siga);
	siga.sa_handler = SIG_IGN;
	sigaction(SIGTERM, &siga, NULL);

	if (SELF_PGROUP)
		killpg(0, SIGTERM);
	else if (childpid > 0)
		killpg(childpid, SIGTERM);
}

static void on_sigterm(int signum, siginfo_t *info, void *uctx)
{
	NOTICE("Received SIGTERM");
	exit(0);
}

static void on_sighup(int signum, siginfo_t *info, void *uctx)
{
	NOTICE("Received SIGHUP");
	/* TODO */
}

static void setup_daemon()
{
	struct sigaction siga;

	/* install signal handlers */
	memset(&siga, 0, sizeof siga);
	siga.sa_flags = SA_SIGINFO;

	siga.sa_sigaction = on_sigterm;
	sigaction(SIGTERM, &siga, NULL);

	siga.sa_sigaction = on_sighup;
	sigaction(SIGHUP, &siga, NULL);

	/* handle groups */
	atexit(exit_handler);

	/* ignore any SIGPIPE */
	signal(SIGPIPE, SIG_IGN);
}

/*----------------------------------------------------------
 | daemonize
 |   set the process in background
 +--------------------------------------------------------- */
static void daemonize()
{
	int fd = 0, daemon, nostdin;
	const char *output;
	pid_t pid;

	daemon = 0;
	output = NULL;
	wrap_json_unpack(main_config, "{s?b s?s}", "daemon", &daemon, "output", &output);
	nostdin = 0;

	if (output) {
		fd = open(output, O_WRONLY | O_APPEND | O_CREAT, 0640);
		if (fd < 0) {
			ERROR("Can't open output %s", output);
			exit(1);
		}
	}

	if (daemon) {
		INFO("entering background mode");

		pid = fork();
		if (pid == -1) {
			ERROR("Failed to fork daemon process");
			exit(1);
		}
		if (pid != 0)
			_exit(0);

		nostdin = 1;
	}

	/* closes the input */
	if (output) {
		NOTICE("Redirecting output to %s", output);
		close(2);
		dup(fd);
		close(1);
		dup(fd);
		close(fd);
	}

	if (nostdin)
		close(0); /* except if 'daemon', ctrl+C still works after that */
}

/*---------------------------------------------------------
 | http server
 |   Handles the HTTP server
 +--------------------------------------------------------- */
static int init_alias(void *closure, const char *spec)
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
	int rc;
	const char *rootapi, *roothttp, *rootbase;

	roothttp = NULL;
	rc = wrap_json_unpack(main_config, "{ss ss s?s}",
				"rootapi", &rootapi,
				"rootbase", &rootbase,
				"roothttp", &roothttp);
	if (rc < 0) {
		ERROR("Can't get HTTP server config");
		exit(1);
	}

	if (!afb_hsrv_add_handler(hsrv, rootapi,
			afb_hswitch_websocket_switch, main_apiset, 20))
		return 0;

	if (!afb_hsrv_add_handler(hsrv, rootapi,
			afb_hswitch_apis, main_apiset, 10))
		return 0;

	if (run_for_config_array_opt("alias", init_alias, hsrv))
		return 0;

	if (roothttp != NULL) {
		if (!afb_hsrv_add_alias(hsrv, "",
			afb_common_rootdir_get_fd(), roothttp, -10, 1))
			return 0;
	}

	if (!afb_hsrv_add_handler(hsrv, rootbase,
			afb_hswitch_one_page_api_redirect, NULL, -20))
		return 0;

	return 1;
}

static struct afb_hsrv *start_http_server()
{
	int rc;
	const char *uploaddir, *rootdir;
	struct afb_hsrv *hsrv;
	int cache_timeout, http_port;

	rc = wrap_json_unpack(main_config, "{ss ss si si}",
				"uploaddir", &uploaddir,
				"rootdir", &rootdir,
				"cache-eol", &cache_timeout,
				"port", &http_port);
	if (rc < 0) {
		ERROR("Can't get HTTP server start config");
		exit(1);
	}

	if (afb_hreq_init_download_path(uploaddir)) {
		ERROR("unable to set the upload directory %s", uploaddir);
		return NULL;
	}

	hsrv = afb_hsrv_create();
	if (hsrv == NULL) {
		ERROR("memory allocation failure");
		return NULL;
	}

	if (!afb_hsrv_set_cache_timeout(hsrv, cache_timeout)
	    || !init_http_server(hsrv)) {
		ERROR("initialisation of httpd failed");
		afb_hsrv_put(hsrv);
		return NULL;
	}

	NOTICE("Waiting port=%d rootdir=%s", http_port, rootdir);
	NOTICE("Browser URL= http://localhost:%d", http_port);

	rc = afb_hsrv_start(hsrv, 15);
	if (!rc) {
		ERROR("starting of httpd failed");
		afb_hsrv_put(hsrv);
		return NULL;
	}

	rc = afb_hsrv_add_interface_tcp(hsrv, DEFAULT_BINDER_INTERFACE, (uint16_t) http_port);
	if (!rc) {
		ERROR("setting interface failed");
		afb_hsrv_put(hsrv);
		return NULL;
	}

	return hsrv;
}

/*---------------------------------------------------------
 | execute_command
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

static char *instanciate_string(const char *arg, const char *port, const char *token)
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
		return strdup(arg);

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
		default: *wr++ = SUBST_CHAR; /*@fallthrough@*/
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

	/* instantiate the environment */
	for (i = 0 ; environ[i] ; i++) {
		repl = instanciate_string(environ[i], port, token);
		if (!repl)
			return -1;
		environ[i] = repl;
	}
	return 0;
}

static char **instanciate_command_args(struct json_object *exec, const char *port, const char *token)
{
	char **result;
	char *repl;
	int i, n;

	/* allocates the result */
	n = (int)json_object_array_length(exec);
	result = malloc((n + 1) * sizeof * result);
	if (!result) {
		ERROR("out of memory");
		return NULL;
	}

	/* instanciate the arguments */
	for (i = 0 ; i < n ; i++) {
		repl = instanciate_string(json_object_get_string(json_object_array_get_idx(exec, i)), port, token);
		if (!repl) {
			while(i)
				free(result[--i]);
			free(result);
			return NULL;
		}
		result[i] = repl;
	}
	result[i] = NULL;
	return result;
}

static int execute_command()
{
	struct json_object *exec, *oport;
	struct sigaction siga;
	char port[20];
	const char *token;
	char **args;
	int rc;

	/* check whether a command is to execute or not */
	if (!json_object_object_get_ex(main_config, "exec", &exec))
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
	if (json_object_object_get_ex(main_config, "port", &oport))
		rc = snprintf(port, sizeof port, "%s", json_object_get_string(oport));
	else
		rc = snprintf(port, sizeof port, "%cp", SUBST_CHAR);
	if (rc < 0 || rc >= (int)(sizeof port)) {
		ERROR("port->txt failed");
	}
	else {
		/* instantiate arguments and environment */
		token = afb_session_initial_token();
		args = instanciate_command_args(exec, port, token);
		if (args && instanciate_environ(port, token) >= 0) {
			/* run */
			if (!SELF_PGROUP)
				setpgid(0, 0);
			execv(args[0], args);
			ERROR("can't launch %s: %m", args[0]);
		}
	}
	exit(1);
	return -1;
}

/*---------------------------------------------------------
 | startup calls
 +--------------------------------------------------------- */

struct startup_req
{
	struct afb_xreq xreq;
	char *api;
	char *verb;
	struct json_object *calls;
	int index;
	int count;
	const char *callspec;
	struct afb_session *session;
};

static void startup_call_reply(struct afb_xreq *xreq, struct json_object *object, const char *error, const char *info)
{
	struct startup_req *sreq = CONTAINER_OF_XREQ(struct startup_req, xreq);

	info = info ?: "";
	if (!error) {
		NOTICE("startup call %s returned %s (%s)", sreq->callspec, json_object_get_string(object), info);
		json_object_put(object);
	} else {
		ERROR("startup call %s ERROR! %s (%s)", sreq->callspec, error, info);
		exit(1);
	}
}

static void startup_call_current(struct startup_req *sreq);

static void startup_call_unref(struct afb_xreq *xreq)
{
	struct startup_req *sreq = CONTAINER_OF_XREQ(struct startup_req, xreq);

	free(sreq->api);
	free(sreq->verb);
	json_object_put(sreq->xreq.json);
	if (++sreq->index < sreq->count)
		startup_call_current(sreq);
	else {
		afb_session_close(sreq->session);
		afb_session_unref(sreq->session);
		free(sreq);
	}
}

static struct afb_xreq_query_itf startup_xreq_itf =
{
	.reply = startup_call_reply,
	.unref = startup_call_unref
};

static void startup_call_current(struct startup_req *sreq)
{
	const char *api, *verb, *json;
	enum json_tokener_error jerr;

	sreq->callspec = json_object_get_string(json_object_array_get_idx(sreq->calls, sreq->index)),
	api = sreq->callspec;
	verb = strchr(api, '/');
	if (verb) {
		json = strchr(verb, ':');
		if (json) {
			afb_xreq_init(&sreq->xreq, &startup_xreq_itf);
			afb_context_init(&sreq->xreq.context, sreq->session, NULL);
			sreq->xreq.context.validated = 1;
			sreq->api = strndup(api, verb - api);
			sreq->verb = strndup(verb + 1, json - verb - 1);
			sreq->xreq.request.called_api = sreq->api;
			sreq->xreq.request.called_verb = sreq->verb;
			sreq->xreq.json = json_tokener_parse_verbose(json + 1, &jerr);
			if (sreq->api && sreq->verb && jerr == json_tokener_success) {
				afb_xreq_process(&sreq->xreq, main_apiset);
				return;
			}
		}
	}
	ERROR("Bad call specification %s", sreq->callspec);
	exit(1);
}

static void run_startup_calls()
{
	struct json_object *calls;
	struct startup_req *sreq;
	int count;

	if (json_object_object_get_ex(main_config, "call", &calls)
	 && json_object_is_type(calls, json_type_array)
	 && (count = (int)json_object_array_length(calls))) {
		sreq = calloc(1, sizeof *sreq);
		sreq->session = afb_session_create(3600);
		sreq->calls = calls;
		sreq->index = 0;
		sreq->count = count;
		startup_call_current(sreq);
	}
}

/*---------------------------------------------------------
 | job for starting the daemon
 +--------------------------------------------------------- */

static void start(int signum, void *arg)
{
	const char *tracereq, *traceapi, *traceevt, *traceses, *tracesvc, *traceditf, *traceglob;
	const char *workdir, *rootdir, *token, *rootapi;
	struct json_object *settings;
	struct afb_hsrv *hsrv;
	int max_session_count, session_timeout, api_timeout;
	int no_httpd, http_port;
	int rc;


	afb_debug("start-entry");

	if (signum) {
		ERROR("start aborted: received signal %s", strsignal(signum));
		exit(1);
	}

	settings = NULL;
	token = rootapi = tracesvc = traceditf = tracereq =
		traceapi = traceevt = traceses = traceglob = NULL;
	no_httpd = 0;
	http_port = -1;
	rc = wrap_json_unpack(main_config, "{"
			"ss ss s?s"
			"si si si"
			"s?b s?i s?s"
			"s?o"
#if !defined(REMOVE_LEGACY_TRACE)
			"s?s s?s"
#endif
			"s?s s?s s?s s?s s?s"
			"}",

			"rootdir", &rootdir,
			"workdir", &workdir,
			"token", &token,

			"apitimeout", &api_timeout,
			"cntxtimeout", &session_timeout,
			"session-max", &max_session_count,

			"no-httpd", &no_httpd,
			"port", &http_port,
			"rootapi", &rootapi,

			"set", &settings,
#if !defined(REMOVE_LEGACY_TRACE)
			"tracesvc", &tracesvc,
			"traceditf", &traceditf,
#endif
			"tracereq", &tracereq,
			"traceapi", &traceapi,
			"traceevt", &traceevt,
			"traceses",  &traceses,
			"traceglob", &traceglob
			);
	if (rc < 0) {
		ERROR("Unable to get start config");
		exit(1);
	}

	/* initialize session handling */
	if (afb_session_init(max_session_count, session_timeout, token)) {
		ERROR("initialisation of session manager failed");
		goto error;
	}

	/* set the directories */
	mkdir(workdir, S_IRWXU | S_IRGRP | S_IXGRP);
	if (chdir(workdir) < 0) {
		ERROR("Can't enter working dir %s", workdir);
		goto error;
	}
	if (afb_common_rootdir_set(rootdir) < 0) {
		ERROR("failed to set common root directory %s", rootdir);
		goto error;
	}
	if (addenv_realpath("AFB_WORKDIR", "."     /* resolved by realpath */)
	 || addenv_realpath("AFB_ROOTDIR", rootdir /* relative to current directory */)) {
		ERROR("can't set DIR environment");
		goto error;
	}

	/* setup HTTP */
	if (!no_httpd) {
		if (http_port < 0) {
			ERROR("no port is defined");
			goto error;
		}
		if (http_port == 0) {
			ERROR("random port is not implemented");
			goto error;
		}
		if (addenv_int("AFB_PORT", http_port)
		 || addenv("AFB_TOKEN", afb_session_initial_token())) {
			ERROR("can't set HTTP environment");
			goto error;
		}
	}

	/* configure the daemon */
	afb_export_set_config(settings);
	main_apiset = afb_apiset_create("main", api_timeout);
	if (!main_apiset) {
		ERROR("can't create main api set");
		goto error;
	}
	if (afb_monitor_init(main_apiset, main_apiset) < 0) {
		ERROR("failed to setup monitor");
		goto error;
	}
#if defined(WITH_SUPERVISION)
	if (afb_supervision_init(main_apiset, main_config) < 0) {
		ERROR("failed to setup supervision");
		goto error;
	}
#endif

	/* install hooks */
	if (tracereq)
		afb_hook_create_xreq(NULL, NULL, NULL, afb_hook_flags_xreq_from_text(tracereq), NULL, NULL);
#if !defined(REMOVE_LEGACY_TRACE)
	if (traceapi || tracesvc || traceditf)
		afb_hook_create_api(NULL, afb_hook_flags_api_from_text(traceapi)
			| afb_hook_flags_legacy_ditf_from_text(traceditf)
			| afb_hook_flags_legacy_svc_from_text(tracesvc), NULL, NULL);
#else
	if (traceapi)
		afb_hook_create_api(NULL, afb_hook_flags_api_from_text(traceapi), NULL, NULL);
#endif
	if (traceevt)
		afb_hook_create_evt(NULL, afb_hook_flags_evt_from_text(traceevt), NULL, NULL);
	if (traceses)
		afb_hook_create_session(NULL, afb_hook_flags_session_from_text(traceses), NULL, NULL);
	if (traceglob)
		afb_hook_create_global(afb_hook_flags_global_from_text(traceglob), NULL, NULL);

	/* load bindings and apis */
	afb_debug("start-load");
	apiset_start_list("binding", afb_api_so_add_binding, "the binding");
	apiset_start_list("ldpaths", afb_api_so_add_pathset_fails, "the binding path set");
	apiset_start_list("weak-ldpaths", afb_api_so_add_pathset_nofails, "the weak binding path set");
	apiset_start_list("auto-api", afb_autoset_add_any, "the automatic api path set");
#if defined(WITH_DBUS_TRANSPARENCY)
	apiset_start_list("dbus-client", afb_api_dbus_add_client, "the afb-dbus client");
#endif
	apiset_start_list("ws-client", afb_api_ws_add_client_weak, "the afb-websocket client");

	DEBUG("Init config done");

	/* start the services */
	afb_debug("start-start");
#if !defined(NO_CALL_PERSONALITY)
	personality((unsigned long)-1L);
#endif
	if (afb_apiset_start_all_services(main_apiset) < 0)
		goto error;

	/* export started apis */
	apiset_start_list("ws-server", afb_api_ws_add_server, "the afb-websocket service");
#if defined(WITH_DBUS_TRANSPARENCY)
	apiset_start_list("dbus-server", afb_api_dbus_add_server, "the afb-dbus service");
#endif

	/* start the HTTP server */
	afb_debug("start-http");
	if (!no_httpd) {
		if (!afb_hreq_init_cookie(http_port, rootapi, session_timeout)) {
			ERROR("initialisation of HTTP cookies failed");
			goto error;
		}

		hsrv = start_http_server();
		if (hsrv == NULL)
			goto error;
	}

	/* run the startup calls */
	afb_debug("start-call");
	run_startup_calls();

	/* run the command */
	afb_debug("start-exec");
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
	struct json_object *obj;
	afb_debug("main-entry");

	// ------------- Build session handler & init config -------
	main_config = afb_config_parse_arguments(argc, argv);
	if (sig_monitor_init(
		!json_object_object_get_ex(main_config, "trap-faults", &obj)
			|| json_object_get_boolean(obj)) < 0) {
		ERROR("failed to initialise signal handlers");
		return 1;
	}


	if (json_object_object_get_ex(main_config, "name", &obj)) {
		verbose_set_name(json_object_get_string(obj), 0);
		process_name_set_name(json_object_get_string(obj));
		process_name_replace_cmdline(argv, json_object_get_string(obj));
	}
	afb_debug("main-args");

	// --------- run -----------
	daemonize();
	INFO("running with pid %d", getpid());

	/* set the daemon environment */
	setup_daemon();

	afb_debug("main-start");

	/* enter job processing */
	jobs_start(3, 0, 50, start, NULL);
	WARNING("hoops returned from jobs_enter! [report bug]");
	return 1;
}

