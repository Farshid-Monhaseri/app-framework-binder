/*
 * Copyright (C) 2016, 2017, 2018 "IoT.bzh"
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

/**
 * @mainpage
 *
 * @section brief Brief introduction
 *
 * This is part of the AGL framework micro-service binder and is provided as the
 * API for writing bindings.
 *
 * The normal usage is to include only one file as below:
 *
 * ```C
 * #define AFB_BINDING_VERSION 3
 * #include <afb/afb-binding.h>
 * ```
 *
 * @example tuto-1.c
 * @example tuto-2.c
 */
/**
 * @file afb/afb-binding.h
 */

#include <stdarg.h>
#include <stdint.h>
struct json_object;

/**
 * @def AFB_BINDING_INTERFACE_VERSION

 *  * Version of the binding interface.
 *
 * This is intended to be test for tuning condition code.
 * It is of the form MAJOR * 1000 + REVISION.
 *
 * @see AFB_BINDING_UPPER_VERSION that should match MAJOR
 */
#define AFB_BINDING_INTERFACE_VERSION 3000

/**
 * @def AFB_BINDING_LOWER_VERSION
 *
 * Lowest binding API version supported.
 *
 * @see AFB_BINDING_VERSION
 * @see AFB_BINDING_UPPER_VERSION
 */
#define AFB_BINDING_LOWER_VERSION     1

/**
 * @def AFB_BINDING_UPPER_VERSION
 *
 * Upper binding API version supported.
 *
 * @see AFB_BINDING_VERSION
 * @see AFB_BINDING_LOWER_VERSION
 */
#define AFB_BINDING_UPPER_VERSION     3

/**
 * @def AFB_BINDING_VERSION
 *
 * This macro must be defined before including <afb/afb-binding.h> to set
 * the required binding API.
 */

#ifndef AFB_BINDING_VERSION
#error "\
\n\
\n\
  AFB_BINDING_VERSION should be defined before including <afb/afb-binding.h>\n\
  AFB_BINDING_VERSION defines the version of binding that you use.\n\
  Currently the version to use is 3 (older versions: 1 is obsolete, 2 is legacy).\n\
  Consider to add one of the following define before including <afb/afb-binding.h>:\n\
\n\
    #define AFB_BINDING_VERSION 3\n\
\n\
"
#else
#  if AFB_BINDING_VERSION == 1
#    warning "Using binding version 1, consider to switch to version 3"
#  endif
#  if AFB_BINDING_VERSION == 2
#    warning "Using binding version 2, consider to switch to version 3"
#  endif
#endif

#if AFB_BINDING_VERSION != 0
# if AFB_BINDING_VERSION < AFB_BINDING_LOWER_VERSION || AFB_BINDING_VERSION > AFB_BINDING_UPPER_VERSION
#  error "Unsupported binding version AFB_BINDING_VERSION"
# endif
#endif

/***************************************************************************************************/
#include "afb-binding-predefs.h"
#include "afb-binding-v1.h"
#include "afb-binding-v2.h"
#include "afb-binding-v3.h"
#if defined(AFB_BINDING_WANT_DYNAPI)
#  include "afb-dynapi-legacy.h"
#endif
#include "afb-binding-postdefs.h"

