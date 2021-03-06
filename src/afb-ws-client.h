/*
 * Copyright (C) 2015-2020 "IoT.bzh"
 * Author: José Bollo <jose.bollo@iot.bzh>
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

struct afb_wsj1;
struct afb_wsj1_itf;
struct afb_proto_ws;
struct afb_proto_ws_client_itf;
struct sd_event;

/*
 * Makes the WebSocket handshake at the 'uri' and if successful
 * instantiate a wsj1 websocket for this connection using 'itf' and 'closure'.
 * (see afb_wsj1_create).
 * The systemd event loop 'eloop' is used to handle the websocket.
 * Returns NULL in case of failure with errno set appropriately.
 */
extern struct afb_wsj1 *afb_ws_client_connect_wsj1(struct sd_event *eloop, const char *uri, struct afb_wsj1_itf *itf, void *closure);

/*
 * Establish a websocket-like client connection to the API of 'uri' and if successful
 * instantiate a client afb_proto_ws websocket for this API using 'itf' and 'closure'.
 * (see afb_proto_ws_create_client).
 * The systemd event loop 'eloop' is used to handle the websocket.
 * Returns NULL in case of failure with errno set appropriately.
 */
extern struct afb_proto_ws *afb_ws_client_connect_api(struct sd_event *eloop, const char *uri, struct afb_proto_ws_client_itf *itf, void *closure);

