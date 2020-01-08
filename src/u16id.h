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

#pragma once

struct u16id2ptr;
struct u16id2bool;

/**********************************************************************/
/**        u16id2ptr                                                 **/
/**********************************************************************/

extern int u16id2ptr_create(struct u16id2ptr **pi2p);
extern void u16id2ptr_destroy(struct u16id2ptr **pi2p);
extern void u16id2ptr_dropall(struct u16id2ptr **pi2p);
extern int u16id2ptr_has(struct u16id2ptr *i2p, uint16_t id);
extern int u16id2ptr_add(struct u16id2ptr **pi2p, uint16_t id, void *ptr);
extern int u16id2ptr_set(struct u16id2ptr **pi2p, uint16_t id, void *ptr);
extern int u16id2ptr_put(struct u16id2ptr *i2p, uint16_t id, void *ptr);
extern int u16id2ptr_get(struct u16id2ptr *i2p, uint16_t id, void **ptr);
extern int u16id2ptr_drop(struct u16id2ptr **pi2p, uint16_t id, void **ptr);
extern int u16id2ptr_count(struct u16id2ptr *i2p);
extern int u16id2ptr_at(struct u16id2ptr *i2p, int index, uint16_t *pid, void **pptr);
extern void u16id2ptr_forall(
			struct u16id2ptr *i2p,
			void (*callback)(void*closure, uint16_t id, void *ptr),
			void *closure);

/**********************************************************************/
/**        u16id2bool                                                **/
/**********************************************************************/

extern int u16id2bool_create(struct u16id2bool **pi2b);
extern void u16id2bool_destroy(struct u16id2bool **pi2b);
extern void u16id2bool_clearall(struct u16id2bool **pi2b);
extern int u16id2bool_get(struct u16id2bool *i2b, uint16_t id);
extern int u16id2bool_set(struct u16id2bool **pi2b, uint16_t id, int value);
