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
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <limits.h>
#include <unistd.h>
#include <ctype.h>

#include <json-c/json.h>
#if !defined(JSON_C_TO_STRING_NOSLASHESCAPE)
#define JSON_C_TO_STRING_NOSLASHESCAPE 0
#endif

#include "verbose.h"
#include "afb-args.h"
#include "afb-hook-flags.h"
#include "wrap-json.h"

#define _d2s_(x)  #x
#define d2s(x)    _d2s_(x)

#if !defined(AFB_VERSION)
#error "you should define AFB_VERSION"
#endif

/**
 * The default timeout of sessions in seconds
 */
#define DEFAULT_SESSION_TIMEOUT		32000000

/**
 * The default timeout of api calls in seconds
 */
#define DEFAULT_API_TIMEOUT		20

/**
 * The default timeout of cache in seconds
 */
#define DEFAULT_CACHE_TIMEOUT		100000

/**
 * The default maximum count of sessions
 */
#define DEFAULT_MAX_SESSION_COUNT       200

/**
 * The default HTTP port to serve
 */
#define DEFAULT_HTTP_PORT		1234

// Define command line option
#define SET_BACKGROUND       1
#define SET_FOREGROUND       2
#define SET_ROOT_DIR         3
#define SET_ROOT_BASE        4
#define SET_ROOT_API         5
#define ADD_ALIAS            6

#define SET_CACHE_TIMEOUT    7

#if WITH_DYNAMIC_BINDING
#define ADD_LDPATH          10
#define ADD_WEAK_LDPATH     11
#define SET_NO_LDPATH       12
#endif
#define SET_API_TIMEOUT     13
#define SET_SESSION_TIMEOUT 14

#define SET_SESSIONMAX      15

#define ADD_WS_CLIENT       16
#define ADD_WS_SERVICE      17

#define SET_ROOT_HTTP       18

#define SET_NO_HTTPD        19

#define SET_TRACEEVT        20
#define SET_TRACESES        21
#define SET_TRACEREQ        22
#define SET_TRACEAPI        23
#define SET_TRACEGLOB       24
#if !defined(REMOVE_LEGACY_TRACE)
#define SET_TRACEDITF       25
#define SET_TRACESVC        26
#endif
#define SET_TRAP_FAULTS     27
#define ADD_CALL            28
#if WITH_DBUS_TRANSPARENCY
#   define ADD_DBUS_CLIENT  30
#   define ADD_DBUS_SERVICE 31
#endif

#define ADD_AUTO_API       'A'
#if WITH_DYNAMIC_BINDING
#define ADD_BINDING        'b'
#endif
#define SET_CONFIG         'C'
#define SET_COLOR          'c'
#define SET_DAEMON         'D'
#define SET_EXEC           'e'
#define GET_HELP           'h'
#define SET_LOG            'l'
#if defined(WITH_MONITORING_OPTION)
#define SET_MONITORING     'M'
#endif
#define SET_NAME           'n'
#define SET_OUTPUT         'o'
#define SET_PORT           'p'
#define SET_QUIET          'q'
#define SET_RANDOM_TOKEN   'r'
#define ADD_SET            's'
#define SET_TOKEN          't'
#define SET_UPLOAD_DIR     'u'
#define GET_VERSION        'V'
#define SET_VERBOSE        'v'
#define SET_WORK_DIR       'w'
#define DUMP_CONFIG        'Z'

/* structure for defining of options */
struct option_desc {
	int id;		/* id of the option         */
	int has_arg;	/* is a value required      */
	char *name;	/* long name of the option  */
	char *help;	/* help text                */
};

/* definition of options */
static struct option_desc optdefs[] = {
/* *INDENT-OFF* */
	{SET_VERBOSE,         0, "verbose",     "Verbose Mode, repeat to increase verbosity"},
	{SET_COLOR,           0, "color",       "Colorize the ouput"},
	{SET_QUIET,           0, "quiet",       "Quiet Mode, repeat to decrease verbosity"},
	{SET_LOG,             1, "log",         "Tune log level"},

	{SET_FOREGROUND,      0, "foreground",  "Get all in foreground mode"},
	{SET_BACKGROUND,      0, "background",  "Get all in background mode"},
	{SET_DAEMON,          0, "daemon",      "Get all in background mode"},

	{SET_NAME,            1, "name",        "Set the visible name"},

	{SET_PORT,            1, "port",        "HTTP listening TCP port  [default " d2s(DEFAULT_HTTP_PORT) "]"},
	{SET_ROOT_HTTP,       1, "roothttp",    "HTTP Root Directory [default no root http (files not served but apis still available)]"},
	{SET_ROOT_BASE,       1, "rootbase",    "Angular Base Root URL [default /opa]"},
	{SET_ROOT_API,        1, "rootapi",     "HTML Root API URL [default /api]"},
	{ADD_ALIAS,           1, "alias",       "Multiple url map outside of rootdir [eg: --alias=/icons:/usr/share/icons]"},

	{SET_API_TIMEOUT,     1, "apitimeout",  "Binding API timeout in seconds [default " d2s(DEFAULT_API_TIMEOUT) "]"},
	{SET_SESSION_TIMEOUT, 1, "cntxtimeout", "Client Session Context Timeout [default " d2s(DEFAULT_SESSION_TIMEOUT) "]"},
	{SET_CACHE_TIMEOUT,   1, "cache-eol",   "Client cache end of live [default " d2s(DEFAULT_CACHE_TIMEOUT) "]"},

	{SET_WORK_DIR,        1, "workdir",     "Set the working directory [default: $PWD or current working directory]"},
	{SET_UPLOAD_DIR,      1, "uploaddir",   "Directory for uploading files [default: workdir] relative to workdir"},
	{SET_ROOT_DIR,        1, "rootdir",     "Root Directory of the application [default: workdir] relative to workdir"},

#if WITH_DYNAMIC_BINDING

	{ADD_LDPATH,          1, "ldpaths",     "Load bindings from dir1:dir2:..."
#if defined(INTRINSIC_BINDING_DIR)
	                                        "[default = " INTRINSIC_BINDING_DIR "]"
#endif
	                                        },
	{ADD_BINDING,         1, "binding",     "Load the binding of path"},
	{ADD_WEAK_LDPATH,     1, "weak-ldpaths","Same as --ldpaths but ignore errors"},
	{SET_NO_LDPATH,       0, "no-ldpaths",  "Discard default ldpaths loading"},
#endif
	{SET_TOKEN,           1, "token",       "Initial Secret [default=random, use --token="" to allow any token]"},
	{SET_RANDOM_TOKEN,    0, "random-token","Enforce a random token"},

	{GET_VERSION,         0, "version",     "Display version and copyright"},
	{GET_HELP,            0, "help",        "Display this help"},

#if WITH_DBUS_TRANSPARENCY
	{ADD_DBUS_CLIENT,     1, "dbus-client", "Bind to an afb service through dbus"},
	{ADD_DBUS_SERVICE,    1, "dbus-server", "Provide an afb service through dbus"},
#endif
	{ADD_WS_CLIENT,       1, "ws-client",   "Bind to an afb service through websocket"},
	{ADD_WS_SERVICE,      1, "ws-server",   "Provide an afb service through websockets"},

	{ADD_AUTO_API,        1, "auto-api",    "Automatic load of api of the given directory"},

	{SET_SESSIONMAX,      1, "session-max", "Max count of session simultaneously [default " d2s(DEFAULT_MAX_SESSION_COUNT) "]"},

#if WITH_AFB_HOOK
	{SET_TRACEREQ,        1, "tracereq",    "Log the requests: none, common, extra, all"},
	{SET_TRACEEVT,        1, "traceevt",    "Log the events: none, common, extra, all"},
	{SET_TRACESES,        1, "traceses",    "Log the sessions: none, all"},
	{SET_TRACEAPI,        1, "traceapi",    "Log the apis: none, common, api, event, all"},
	{SET_TRACEGLOB,       1, "traceglob",   "Log the globals: none, all"},
#if !defined(REMOVE_LEGACY_TRACE)
	{SET_TRACEDITF,       1, "traceditf",   "Log the daemons: no, common, all"},
	{SET_TRACESVC,        1, "tracesvc",    "Log the services: no, all"},
#endif
#endif

	{ADD_CALL,            1, "call",        "Call at start, format of val: API/VERB:json-args"},

	{SET_NO_HTTPD,        0, "no-httpd",    "Forbid HTTP service"},
	{SET_EXEC,            0, "exec",        "Execute the remaining arguments"},

#if defined(WITH_MONITORING_OPTION)
	{SET_MONITORING,      0, "monitoring",  "Enable HTTP monitoring at <ROOT>/monitoring/"},
#endif

	{SET_CONFIG,          1, "config",      "Load options from the given config file"},
	{DUMP_CONFIG,         0, "dump-config", "Dump the config to stdout and exit"},

	{ADD_SET,             1, "set",         "Set parameters ([API]/[KEY]:JSON or {\"API\":{\"KEY\":JSON}}" },
	{SET_OUTPUT,          1, "output",      "Redirect stdout and stderr to output file (when --daemon)"},

	{SET_TRAP_FAULTS,     1, "trap-faults", "Trap faults: on, off, yes, no, true, false, 1, 0 (default: true)"},

	{0, 0, NULL, NULL}
/* *INDENT-ON* */
};

#if defined(WITH_MONITORING_OPTION)
static const char MONITORING_ALIAS[] = "/monitoring:"INTRINSIC_BINDING_DIR"/monitoring";
#endif

static const struct {
	int optid;
	int valdef;
} default_optint_values[] = {
	{ SET_PORT,		DEFAULT_HTTP_PORT },
	{ SET_API_TIMEOUT,	DEFAULT_API_TIMEOUT },
	{ SET_CACHE_TIMEOUT,	DEFAULT_CACHE_TIMEOUT },
	{ SET_SESSION_TIMEOUT,	DEFAULT_SESSION_TIMEOUT },
	{ SET_SESSIONMAX,	DEFAULT_MAX_SESSION_COUNT }
};

static const struct {
	int optid;
	const char *valdef;
} default_optstr_values[] = {
	{ SET_WORK_DIR,		"." },
	{ SET_ROOT_DIR,		"." },
	{ SET_UPLOAD_DIR,	"." },
	{ SET_ROOT_BASE,	"/opa" },
	{ SET_ROOT_API,		"/api" }
};

/**********************************
* preparing items
***********************************/

static char *shortopts = NULL;
static int *id2idx = NULL;

static void *oomchk(void *ptr)
{
	if (!ptr) {
		ERROR("Out of memory");
		exit(1);
	}
	return ptr;
}

static char is_short_option(int val)
{
	return (val >= 'a' && val <= 'z') || (val >= 'A' && val <= 'Z') || (val >= '0' && val <= '9');
}

static void init_options()
{
	int i, ns, mi, id;

	if (!shortopts) {
		ns = 2;
		mi = -1;
		for (i = 0 ; optdefs[i].name ; i++) {
			id = optdefs[i].id;
			if (id > mi)
				mi = id;
			if (is_short_option(id))
				ns += 1 + !!optdefs[i].has_arg;
		}
		shortopts = oomchk(malloc(2 + ns));
		id2idx = oomchk(calloc(1 + mi, sizeof *id2idx));
		shortopts[ns = 0] = ':';
		for (i = 0 ; optdefs[i].name ; i++) {
			id = optdefs[i].id;
			id2idx[id] = i;
			if (is_short_option(id)) {
				shortopts[++ns] = (char)id;
				if (optdefs[i].has_arg)
					shortopts[++ns] = ':';
			}
		}
		shortopts[++ns] = 0;
	}
}

static const char *name_of_optid(int optid)
{
	return optdefs[id2idx[optid]].name;
}

static int get_enum_val(const char *name, int optid, int (*func)(const char*))
{
	int i;

	i = func(name);
	if (i < 0) {
		ERROR("option [--%s] bad value (found %s)",
			name_of_optid(optid), name);
		exit(1);
	}
	return i;
}


/*----------------------------------------------------------
 | printversion
 |   print version and copyright
 +--------------------------------------------------------- */
static void printVersion(FILE * file)
{
	fprintf(file,
		"\n"
		"  AGL Framework Binder [AFB %s] "

#if WITH_DBUS_TRANSPARENCY
		"+"
#else
		"-"
#endif
		"DBUS "

#if defined(WITH_MONITORING_OPTION)
		"+"
#else
		"-"
#endif
		"MONITOR "
#if WITH_SUPERVISION
		"+"
#else
		"-"
#endif
		"SUPERVISION "

#if WITH_AFB_HOOK
		"+"
#else
		"-"
#endif
		"HOOK "

#if WITH_TRACE
		"+"
#else
		"-"
#endif
		"TRACE "

		"["
#if WITH_DYNAMIC_BINDING
		"BINDINGS "
		"+"
#else
		"-"
#endif
#if WITH_LEGACY_BINDING_V1
		"+"
#else
		"-"
#endif
		"V1 "
#if WITH_LEGACY_BINDING_VDYN
		"+"
#else
		"-"
#endif
		"VDYN "
#if WITH_LEGACY_BINDING_V2
		"+"
#else
		"-"
#endif
		"V2 +V3]\n"
		"\n",
		AFB_VERSION
	);
	fprintf(file,
		"  Copyright (C) 2015-2019 \"IoT.bzh\"\n"
		"  AFB comes with ABSOLUTELY NO WARRANTY.\n"
		"  Licence Apache 2\n"
		"\n");
}

/*----------------------------------------------------------
 | printHelp
 |   print information from long option array
 +--------------------------------------------------------- */

static void printHelp(FILE * file, const char *name)
{
	int ind;
	char command[50], sht[4];

	fprintf(file, "%s:\nallowed options\n", strrchr(name, '/') ? strrchr(name, '/') + 1 : name);
	sht[3] = 0;
	for (ind = 0; optdefs[ind].name != NULL; ind++) {
		if (is_short_option(optdefs[ind].id)) {
			sht[0] = '-';
			sht[1] = (char)optdefs[ind].id;
			sht[2] = ',';
		} else {
			sht[0] = sht[1] = sht[2] = ' ';
		}
		strcpy(command, optdefs[ind].name);
		if (optdefs[ind].has_arg)
			strcat(command, "=xxxx");
		fprintf(file, " %s --%-17s %s\n", sht, command, optdefs[ind].help);
	}
	fprintf(file,
		"Example:\n  %s  --verbose --port="
		d2s(DEFAULT_HTTP_PORT)
		" --token='azerty'"
#if WITH_DYNAMIC_BINDING
		" --ldpaths=build/bindings:/usr/lib64/agl/bindings"
#endif
		"\n",
		name);
}

static void dump(struct json_object *config, FILE *file, const char *prefix, const char *title)
{
	const char *head, *tail;

	if (title)
		fprintf(file, "%s----BEGIN OF %s-----\n", prefix ?: "", title);

	head = json_object_to_json_string_ext(config, JSON_C_TO_STRING_PRETTY
		|JSON_C_TO_STRING_SPACED|JSON_C_TO_STRING_NOSLASHESCAPE);

	if (!prefix)
		fprintf(file, "%s\n", head);
	else {
		while(*head) {
			for (tail = head ; *tail && *tail != '\n' ; tail++);
			fprintf(file, "%s %.*s\n", prefix, (int)(tail - head), head);
			head = tail + !!*tail;
		}
	}

	if (title)
		fprintf(file, "%s----END OF %s-----\n", prefix ?: "", title);
}

/**********************************
* json helpers
***********************************/

static struct json_object *joomchk(struct json_object *value)
{
	return oomchk(value);
}

static struct json_object *to_jstr(const char *value)
{
	return joomchk(json_object_new_string(value));
}

static struct json_object *to_jint(int value)
{
	return joomchk(json_object_new_int(value));
}

static struct json_object *to_jbool(int value)
{
	return joomchk(json_object_new_boolean(value));
}

/**********************************
* arguments helpers
***********************************/

static int string_to_bool(const char *value)
{
	static const char true_names[] = "1\0yes\0true\0on";
	static const char false_names[] = "0\0no\0false\0off";
	size_t pos;

	pos = 0;
	while (pos < sizeof true_names)
		if (strcasecmp(value, &true_names[pos]))
			pos += 1 + strlen(&true_names[pos]);
		else
			return 1;

	pos = 0;
	while (pos < sizeof false_names)
		if (strcasecmp(value, &false_names[pos]))
			pos += 1 + strlen(&false_names[pos]);
		else
			return 0;

	return -1;
}

static void noarg(int optid)
{
	if (optarg) {
		ERROR("option [--%s] need no value (found %s)", name_of_optid(optid), optarg);
		exit(1);
	}
}

static const char *get_arg(int optid)
{
	if (optarg == 0) {
		ERROR("option [--%s] needs a value i.e. --%s=xxx",
				name_of_optid(optid), name_of_optid(optid));
		exit(1);
	}
	return optarg;
}

static int get_arg_bool(int optid)
{
	int value = string_to_bool(get_arg(optid));
	if (value < 0) {
		ERROR("option [--%s] needs a boolean value: yes/no, true/false, on/off, 1/0",
				name_of_optid(optid));
		exit(1);
	}
	return value;
}

static void config_del(struct json_object *config, int optid)
{
	return json_object_object_del(config, name_of_optid(optid));
}

static int config_has(struct json_object *config, int optid)
{
	return json_object_object_get_ex(config, name_of_optid(optid), NULL);
}

static int config_has_bool(struct json_object *config, int optid)
{
	struct json_object *x;
	return json_object_object_get_ex(config, name_of_optid(optid), &x)
		&& json_object_get_boolean(x);
}

__attribute__((unused))
static int config_has_str(struct json_object *config, int optid, const char *val)
{
	int i, n;
	struct json_object *a;

	if (!json_object_object_get_ex(config, name_of_optid(optid), &a))
		return 0;

	if (!json_object_is_type(a, json_type_array))
		return !strcmp(val, json_object_get_string(a));

	n = (int)json_object_array_length(a);
	for (i = 0 ; i < n ; i++) {
		if (!strcmp(val, json_object_get_string(json_object_array_get_idx(a, i))))
			return 1;
	}
	return 0;
}

static void config_set(struct json_object *config, int optid, struct json_object *val)
{
	json_object_object_add(config, name_of_optid(optid), val);
}

static void config_set_str(struct json_object *config, int optid, const char *val)
{
	config_set(config, optid, to_jstr(val));
}

static void config_set_optstr(struct json_object *config, int optid)
{
	config_set_str(config, optid, get_arg(optid));
}

static void config_set_int(struct json_object *config, int optid, int value)
{
	config_set(config, optid, to_jint(value));
}

static void config_set_bool(struct json_object *config, int optid, int value)
{
	config_set(config, optid, to_jbool(value));
}

static void config_set_optint_base(struct json_object *config, int optid, int mini, int maxi, int base)
{
	const char *beg, *end;
	long int val;

	beg = get_arg(optid);
	val = strtol(beg, (char**)&end, base);
	if (*end || end == beg) {
		ERROR("option [--%s] requires a valid integer (found %s)",
			name_of_optid(optid), beg);
		exit(1);
	}
	if (val < (long int)mini || val > (long int)maxi) {
		ERROR("option [--%s] value %ld out of bounds (not in [%d , %d])",
			name_of_optid(optid), val, mini, maxi);
		exit(1);
	}
	config_set_int(config, optid, (int)val);
}

static void config_set_optint(struct json_object *config, int optid, int mini, int maxi)
{
	return config_set_optint_base(config, optid, mini, maxi, 10);
}

__attribute__((unused))
static void config_set_optenum(struct json_object *config, int optid, int (*func)(const char*))
{
	const char *name = get_arg(optid);
	get_enum_val(name, optid, func);
	config_set_str(config, optid, name);
}

static void config_add(struct json_object *config, int optid, struct json_object *val)
{
	struct json_object *a;
	if (!json_object_object_get_ex(config, name_of_optid(optid), &a)) {
		a = joomchk(json_object_new_array());
		json_object_object_add(config, name_of_optid(optid), a);
	}
	json_object_array_add(a, val);
}

static void config_add_str(struct json_object *config, int optid, const char *val)
{
	config_add(config, optid, to_jstr(val));
}

static void config_add_optstr(struct json_object *config, int optid)
{
	config_add_str(config, optid, get_arg(optid));
}

static void config_mix2_cb(void *closure, struct json_object *obj, const char *name)
{
	struct json_object *dest, *base = closure;

	if (!name)
		name = "";

	if (!json_object_object_get_ex(base, name, &dest)) {
		dest = joomchk(json_object_new_object());
		json_object_object_add(base, name, dest);
	}
	if (json_object_is_type(obj, json_type_object))
		wrap_json_object_add(dest, obj);
	else
		json_object_object_add(dest, "", json_object_get(obj));
}

static void config_mix2(struct json_object *config, int optid, struct json_object *val)
{
	struct json_object *obj;

	if (!json_object_object_get_ex(config, name_of_optid(optid), &obj)) {
		obj = joomchk(json_object_new_object());
		json_object_object_add(config, name_of_optid(optid), obj);
	}
	wrap_json_for_all(val, config_mix2_cb, obj);
}

static void config_mix2_str(struct json_object *config, int optid, const char *val)
{
	size_t st1, st2;
	const char *api, *key;
	struct json_object *obj, *sub;
	enum json_tokener_error jerr;

	st1 = strcspn(val, "/:{[\"");
	st2 = strcspn(&val[st1], ":{[\"");
	if (val[st1] != '/' || val[st1 + st2] != ':') {
		obj = json_tokener_parse_verbose(val, &jerr);
		if (jerr != json_tokener_success)
			obj = json_object_new_string(val);
	} else {
		api = st1 == 0 ? "*" : strndupa(val, st1);
		val += st1 + 1;
		key = st2 <= 1 || (st2 == 2 && *val == '*') ? NULL : strndupa(val, st2 - 1);
		val += st2;
		sub = json_tokener_parse_verbose(val, &jerr);
		if (jerr != json_tokener_success)
			sub = json_object_new_string(val);

		if (key) {
			obj = json_object_new_object();
			json_object_object_add(obj, key, sub);
			sub = obj;
		}
		obj = json_object_new_object();
		json_object_object_add(obj, api, sub);
	}
	config_mix2(config, optid, obj);
	json_object_put(obj);
}

static void config_mix2_optstr(struct json_object *config, int optid)
{
	config_mix2_str(config, optid, get_arg(optid));
}

/*---------------------------------------------------------
 |   set the log levels
 +--------------------------------------------------------- */

static void set_log(const char *args)
{
	char o = 0, s, *p, *i = strdupa(args);
	int lvl;

	for(;;) switch (*i) {
	case 0:
		return;
	case '+':
	case '-':
		o = *i;
		/*@fallthrough@*/
	case ' ':
	case ',':
		i++;
		break;
	default:
		p = i;
		while (isalpha(*p)) p++;
		s = *p;
		*p = 0;
		lvl = verbose_level_of_name(i);
		if (lvl < 0) {
			i = strdupa(i);
			*p = s;
			ERROR("Bad log name '%s' in %s", i, args);
			exit(1);
		}
		*p = s;
		i = p;
		if (o == '-')
			verbose_sub(lvl);
		else {
			if (!o) {
				verbose_clear();
				o = '+';
			}
			verbose_add(lvl);
		}
		break;
	}
}

/*---------------------------------------------------------
 |   Parse option and launch action
 +--------------------------------------------------------- */

static void parse_arguments_inner(int argc, char **argv, struct json_object *config, struct option *options)
{
	struct json_object *conf;
	int optid, cind, dodump = 0;

	for (;;) {
		cind = optind;
		optid = getopt_long(argc, argv, shortopts, options, NULL);
		if (optid < 0) {
			/* end of options */
			break;
		}
		switch (optid) {
		case SET_VERBOSE:
			verbose_inc();
			break;

		case SET_COLOR:
			verbose_colorize();
			break;

		case SET_QUIET:
			verbose_dec();
			break;

		case SET_LOG:
			set_log(get_arg(optid));
			break;

		case SET_PORT:
			config_set_optint(config, optid, 1024, 32767);
			break;

		case SET_API_TIMEOUT:
		case SET_SESSION_TIMEOUT:
		case SET_CACHE_TIMEOUT:
			config_set_optint(config, optid, 0, INT_MAX);
			break;

		case SET_SESSIONMAX:
			config_set_optint(config, optid, 1, INT_MAX);
			break;

		case SET_ROOT_DIR:
		case SET_ROOT_HTTP:
		case SET_ROOT_BASE:
		case SET_ROOT_API:
		case SET_TOKEN:
		case SET_UPLOAD_DIR:
		case SET_WORK_DIR:
		case SET_NAME:
			config_set_optstr(config, optid);
			break;

#if WITH_DBUS_TRANSPARENCY
		case ADD_DBUS_CLIENT:
		case ADD_DBUS_SERVICE:
#endif
		case ADD_ALIAS:
#if WITH_DYNAMIC_BINDING
		case ADD_LDPATH:
		case ADD_WEAK_LDPATH:
		case ADD_BINDING:
#endif
		case ADD_CALL:
		case ADD_WS_CLIENT:
		case ADD_WS_SERVICE:
		case ADD_AUTO_API:
			config_add_optstr(config, optid);
			break;

		case ADD_SET:
			config_mix2_optstr(config, optid);
			break;

#if defined(WITH_MONITORING_OPTION)
		case SET_MONITORING:
#endif
		case SET_RANDOM_TOKEN:
		case SET_NO_HTTPD:
#if WITH_DYNAMIC_BINDING
		case SET_NO_LDPATH:
#endif
			noarg(optid);
			config_set_bool(config, optid, 1);
			break;


		case SET_FOREGROUND:
		case SET_BACKGROUND:
		case SET_DAEMON:
			noarg(optid);
			config_set_bool(config, SET_DAEMON, optid != SET_FOREGROUND);
			break;

		case SET_TRAP_FAULTS:
			config_set_bool(config, optid, get_arg_bool(optid));
			break;


#if WITH_AFB_HOOK
		case SET_TRACEREQ:
			config_set_optenum(config, optid, afb_hook_flags_xreq_from_text);
			break;

		case SET_TRACEEVT:
			config_set_optenum(config, optid, afb_hook_flags_evt_from_text);
			break;

		case SET_TRACESES:
			config_set_optenum(config, optid, afb_hook_flags_session_from_text);
			break;

		case SET_TRACEAPI:
			config_set_optenum(config, optid, afb_hook_flags_api_from_text);
			break;

		case SET_TRACEGLOB:
			config_set_optenum(config, optid, afb_hook_flags_global_from_text);
			break;

#if !defined(REMOVE_LEGACY_TRACE)
		case SET_TRACEDITF:
			config_set_optenum(config, optid, afb_hook_flags_legacy_ditf_from_text);
			break;

		case SET_TRACESVC:
			config_set_optenum(config, optid, afb_hook_flags_legacy_svc_from_text);
			break;
#endif
#endif

		case SET_EXEC:
			if (optind == argc) {
				ERROR("The option --exec requires arguments");
				exit(1);
			}
			while (optind != argc)
				config_add_str(config, optid, argv[optind++]);
			break;

		case SET_CONFIG:
			conf = json_object_from_file(get_arg(optid));
			if (!conf) {
				ERROR("Can't read config file %s", get_arg(optid));
				exit(1);
			}
			wrap_json_object_add(config, conf);
			json_object_put(conf);
			break;

		case DUMP_CONFIG:
			noarg(optid);
			dodump = 1;
			break;

		case GET_VERSION:
			noarg(optid);
			printVersion(stdout);
			exit(0);

		case GET_HELP:
			printHelp(stdout, argv[0]);
			exit(0);

		default:
			ERROR("Bad option detected, check %s", argv[cind]);
			exit(1);
		}
	}
	/* TODO: check for extra value */

	if (dodump) {
		dump(config, stdout, NULL, NULL);
		exit(0);
	}
}

static void parse_arguments(int argc, char **argv, struct json_object *config)
{
	int ind;
	struct option *options;

	/* create GNU getopt options from optdefs */
	options = malloc((sizeof optdefs / sizeof * optdefs) * sizeof * options);
	for (ind = 0; optdefs[ind].name; ind++) {
		options[ind].name = optdefs[ind].name;
		options[ind].has_arg = optdefs[ind].has_arg;
		options[ind].flag = NULL;
		options[ind].val = optdefs[ind].id;
	}
	memset(&options[ind], 0, sizeof options[ind]);

	/* parse the arguments */
	parse_arguments_inner(argc, argv, config, options);

	/* release the memory of options */
	free(options);
}

static void fulfill_config(struct json_object *config)
{
	int i;

	for (i = 0 ; i < sizeof default_optint_values / sizeof * default_optint_values ; i++)
		if (!config_has(config, default_optint_values[i].optid))
			config_set_int(config, default_optint_values[i].optid, default_optint_values[i].valdef);

	for (i = 0 ; i < sizeof default_optstr_values / sizeof * default_optstr_values ; i++)
		if (!config_has(config, default_optstr_values[i].optid))
			config_set_str(config, default_optstr_values[i].optid, default_optstr_values[i].valdef);

	// default AUTH_TOKEN
	if (config_has_bool(config, SET_RANDOM_TOKEN))
		config_del(config, SET_TOKEN);

#if WITH_DYNAMIC_BINDING && defined(INTRINSIC_BINDING_DIR)
	if (!config_has(config, ADD_LDPATH) && !config_has(config, ADD_WEAK_LDPATH) && !config_has_bool(config, SET_NO_LDPATH))
		config_add_str(config, ADD_LDPATH, INTRINSIC_BINDING_DIR);
#endif

#if defined(WITH_MONITORING_OPTION)
	if (config_has_bool(config, SET_MONITORING) && !config_has_str(config, ADD_ALIAS, MONITORING_ALIAS))
		config_add_str(config, ADD_ALIAS, MONITORING_ALIAS);
#endif

#if !defined(REMOVE_LEGACY_TRACE) && 0
	config->traceapi |= config->traceditf | config->tracesvc;
#endif
}

static void on_environment(struct json_object *config, int optid, const char *name, void (*func)(struct json_object*, int, const char*))
{
	char *value = secure_getenv(name);

	if (value && *value)
		func(config, optid, value);
}

__attribute__((unused))
static void on_environment_enum(struct json_object *config, int optid, const char *name, int (*func)(const char*))
{
	char *value = secure_getenv(name);

	if (value) {
		if (func(value) == -1)
			WARNING("Unknown value %s for environment variable %s, ignored", value, name);
		else
			config_set_str(config, optid, value);
	}
}

static void on_environment_bool(struct json_object *config, int optid, const char *name)
{
	char *value = secure_getenv(name);
	int asbool;

	if (value) {
		asbool = string_to_bool(value);
		if (asbool < 0)
			WARNING("Unknown value %s for environment variable %s, ignored", value, name);
		else
			config_set_bool(config, optid, asbool);
	}
}

static void parse_environment(struct json_object *config)
{
#if WITH_AFB_HOOK
	on_environment_enum(config, SET_TRACEREQ, "AFB_TRACEREQ", afb_hook_flags_xreq_from_text);
	on_environment_enum(config, SET_TRACEEVT, "AFB_TRACEEVT", afb_hook_flags_evt_from_text);
	on_environment_enum(config, SET_TRACESES, "AFB_TRACESES", afb_hook_flags_session_from_text);
	on_environment_enum(config, SET_TRACEAPI, "AFB_TRACEAPI", afb_hook_flags_api_from_text);
	on_environment_enum(config, SET_TRACEGLOB, "AFB_TRACEGLOB", afb_hook_flags_global_from_text);
#if !defined(REMOVE_LEGACY_TRACE)
	on_environment_enum(config, SET_TRACEDITF, "AFB_TRACEDITF", afb_hook_flags_legacy_ditf_from_text);
	on_environment_enum(config, SET_TRACESVC, "AFB_TRACESVC", afb_hook_flags_legacy_svc_from_text);
#endif
#endif
#if WITH_DYNAMIC_BINDING
	on_environment(config, ADD_LDPATH, "AFB_LDPATHS", config_add_str);
#endif
	on_environment(config, ADD_SET, "AFB_SET", config_mix2_str);
	on_environment_bool(config, SET_TRAP_FAULTS, "AFB_TRAP_FAULTS");
}

struct json_object *afb_args_parse(int argc, char **argv)
{
	struct json_object *result;

	init_options();

	result = json_object_new_object();

	parse_environment(result);
	parse_arguments(argc, argv, result);
	fulfill_config(result);
	if (verbose_wants(Log_Level_Info))
		dump(result, stderr, "--", "CONFIG");
	return result;
}


