/*
 * Copyright (C) 2015-2020 "IoT.bzh"
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

#pragma once

// main config structure
struct afs_args {
	char *rootdir;		// base dir for files
	char *roothttp;		// directory for http files
	char *rootbase;		// Angular HTML5 base URL
	char *rootapi;		// Base URL for REST APIs
	char *workdir;		// where to run the program
	char *uploaddir;	// where to store transient files
	char *token;		// initial authentication token [default NULL no session]
	char *name;		/* name to set to the daemon */
	char *ws_server;	/* exported api */

	/* integers */
	int httpdPort;
	int cacheTimeout;
	int apiTimeout;
	int cntxTimeout;	// Client Session Context timeout
	int nbSessionMax;	// max count of sessions
};

extern struct afs_args *afs_args_parse(int argc, char **argv);

