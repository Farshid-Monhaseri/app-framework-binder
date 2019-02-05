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

#pragma once

/*
 * CAUTION!
 * the default setting uses an abstract socket path
 * be aware that this setting doesn't allow to enforce
 * DAC for accessing the socket and then would allow
 * anyone to create a such socket and usurpate the
 * supervisor.
 */
#if !defined(AFS_SUPERVISION_SOCKET)
#  define AFS_SUPERVISION_SOCKET "@urn:AGL:afs:supervision:socket" /* abstract */
#endif

/*
 * generated using
 * uuid -v 5 ns:URL urn:AGL:afs:supervision:interface:1
 */
#define AFS_SUPERVISION_INTERFACE_1 "86040e8d-eee5-5900-a129-3edb8da3ed46"


/**
 * packet initially sent by monitor at start
 */
struct afs_supervision_initiator
{
	char interface[37];	/**< zero terminated interface uuid */
	char extra[27];		/**< zero terminated extra computed here to be 64-37 */
};

#define AFS_SUPERVISION_APINAME      "."
#define AFS_SUPERVISOR_APINAME       "supervisor"
