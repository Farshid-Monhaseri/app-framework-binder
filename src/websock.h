/*
 * Copyright 2016 iot.bzh
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * This work is a far adaptation of apache-websocket:
 *   origin:  https://github.com/disconnect/apache-websocket
 *   commit:  cfaef071223f11ba016bff7e1e4b7c9e5df45b50
 *   Copyright 2010-2012 self.disconnect (APACHE-2)
 */

struct iovec;

#define STATUS_CODE_UNSET                0
#define STATUS_CODE_OK                1000
#define STATUS_CODE_GOING_AWAY        1001
#define STATUS_CODE_PROTOCOL_ERROR    1002
#define STATUS_CODE_RESERVED          1004	/* Protocol 8: frame too large */
#define STATUS_CODE_INVALID_UTF8      1007
#define STATUS_CODE_POLICY_VIOLATION  1008
#define STATUS_CODE_MESSAGE_TOO_LARGE 1009
#define STATUS_CODE_INTERNAL_ERROR    1011

struct websock_itf {
	ssize_t (*writev) (void *, const struct iovec *, int);
	ssize_t (*readv) (void *, const struct iovec *, int);
	void (*disconnect) (void *);

	void (*on_ping) (void *);
	void (*on_pong) (void *);
	void (*on_close) (void *, uint16_t code, size_t size);
	void (*on_text) (void *, int last, size_t size);
	void (*on_binary) (void *, int last, size_t size);
	void (*on_continue) (void *, int last, size_t size);
};

struct websock;

void websock_close(struct websock *ws);
void websock_close_code(struct websock *ws, uint16_t code);

void websock_ping(struct websock *ws);
void websock_pong(struct websock *ws);
void websock_text(struct websock *ws, const char *text, size_t length);
void websock_binary(struct websock *ws, const void *data, size_t length);

ssize_t websock_read(struct websock *ws, void *buffer, size_t size);
void websock_drop(struct websock *ws);

int websock_dispatch(struct websock *ws);

struct websock *websock_create(const struct websock_itf *itf, void *closure);
void websock_destroy(struct websock *ws);