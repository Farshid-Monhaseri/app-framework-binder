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

/** @addtogroup AFB_REQ
 *  @{ */

/**
 * Describes an argument (or parameter) of a request.
 *
 * @see afb_req_get
 */
struct afb_arg
{
	const char *name;	/**< name of the argument or NULL if invalid */
	const char *value;	/**< string representation of the value of the argument */
				/**< original filename of the argument if path != NULL */
	const char *path;	/**< if not NULL, path of the received file for the argument */
				/**< when the request is finalized this file is removed */
};


/** @} */
