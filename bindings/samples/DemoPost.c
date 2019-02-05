/*
 * Copyright (C) 2015-2019 "IoT.bzh"
 * Author "Fulup Ar Foll"
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
#include <stdio.h>
#include <string.h>
#include <json-c/json.h>

#define AFB_BINDING_VERSION 3
#include <afb/afb-binding.h>


// Sample Generic Ping Debug API
static void getPingTest(afb_req_t request)
{
    static int pingcount = 0;
    json_object *query = afb_req_json(request);

    afb_req_success_f(request, query, "Ping Binder Daemon count=%d", ++pingcount);
}

// With content-type=json data are directly avaliable in request->post->data
static void GetJsonByPost (afb_req_t request)
{
    struct afb_arg arg;
    json_object* jresp;
    json_object *query = afb_req_json(request);

    arg = afb_req_get(request, "");
    jresp = arg.value ? json_tokener_parse(arg.value) : NULL;
    afb_req_success_f(request, jresp, "GetJsonByPost query={%s}", json_object_to_json_string(query));
}

// Upload a file and execute a function when upload is done
static void Uploads (afb_req_t request, const char *destination)
{
   struct afb_arg a = afb_req_get(request, "file");
   if (a.value == NULL || *a.value == 0)
     afb_req_fail(request, "failed", "no file selected");
   else
     afb_req_success_f(request, NULL, "uploaded file %s of path %s for destination %s", a.value, a.path, destination);
}

// Upload a file and execute a function when upload is done
static void UploadAppli (afb_req_t request)
{
    Uploads(request, "applications");
}

// Simples Upload case just upload a file
static void UploadMusic (afb_req_t request)
{
    Uploads(request, "musics");
}

// PostForm callback is called multiple times (one or each key within form, or once per file buffer)
// When file has been fully uploaded call is call with item==NULL
static void UploadImage (afb_req_t request)
{
    Uploads(request, "images");
}


// NOTE: this sample does not use session to keep test a basic as possible
//       in real application upload-xxx should be protected with AFB_SESSION_CHECK
static const struct afb_verb_v3 verbs[]= {
  {.verb="ping"         , .session=AFB_SESSION_NONE  , .callback=getPingTest    ,.info="Ping Rest Test Service"},
  {.verb="upload-json"  , .session=AFB_SESSION_NONE  , .callback=GetJsonByPost  ,.info="Demo for Json Buffer on Post"},
  {.verb="upload-image" , .session=AFB_SESSION_NONE  , .callback=UploadImage    ,.info="Demo for file upload"},
  {.verb="upload-music" , .session=AFB_SESSION_NONE  , .callback=UploadMusic    ,.info="Demo for file upload"},
  {.verb="upload-appli" , .session=AFB_SESSION_NONE  , .callback=UploadAppli    ,.info="Demo for file upload"},
  {.verb=NULL}
};

const struct afb_binding_v3 afbBindingV3 = {
	.info = "Sample with Post Upload Files",
	.api = "post",
	.verbs = verbs
};

