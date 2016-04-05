/*
 * Copyright 2016 IoT.bzh
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

struct upoll;

extern int upoll_is_valid(struct upoll *upoll);

extern struct upoll *upoll_open(int fd, uint32_t events, void (*process)(void *closure, int fd, uint32_t events), void *closure);

extern int upoll_update(struct upoll *upoll, uint32_t events);

extern void upoll_close(struct upoll *upoll);

extern void upoll_wait(int timeout);

