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

#include <stdlib.h>
#include "afb-req-x1.h"

/** @addtogroup AFB_REQ
 *  @{ */

/**
 * @deprecated use bindings version 3
 *
 * Stores 'req' on heap for asynchrnous use.
 * Returns a pointer to the stored 'req' or NULL on memory depletion.
 * The count of reference to 'req' is incremented on success
 * (see afb_req_addref).
 */
static inline struct afb_req_x1 *afb_req_x1_store_v1(struct afb_req_x1 req)
{
	struct afb_req_x1 *result = (struct afb_req_x1*)malloc(sizeof *result);
	if (result) {
		*result = req;
		afb_req_x1_addref(req);
	}
	return result;
}

/**
 * @deprecated use bindings version 3
 *
 * Retrieves the afb_req stored at 'req' and frees the memory.
 * Returns the stored request.
 * The count of reference is UNCHANGED, thus, normally, the
 * function 'afb_req_unref' should be called on the result
 * after that the asynchronous reply if sent.
 */
static inline struct afb_req_x1 afb_req_unstore_x1_v1(struct afb_req_x1 *req)
{
	struct afb_req_x1 result = *req;
	free(req);
	return result;
}


/** @} */
