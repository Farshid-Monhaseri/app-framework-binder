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

/*
 * Enum for Session/Token/Assurance middleware.
 */
enum afb_session_flags_v2
{
       AFB_SESSION_LOA_MASK_V2 = 3,	/* mask for LOA */

       AFB_SESSION_LOA_0_V2 = 0,	/* value for LOA of 0 */
       AFB_SESSION_LOA_1_V2 = 1,	/* value for LOA of 1 */
       AFB_SESSION_LOA_2_V2 = 2,	/* value for LOA of 2 */
       AFB_SESSION_LOA_3_V2 = 3,	/* value for LOA of 3 */

       AFB_SESSION_CHECK_V2 = 4,	/* Requires token authentification */
       AFB_SESSION_REFRESH_V2 = 8,	/* After token authentification, refreshes the token at end */
       AFB_SESSION_CLOSE_V2 = 16,	/* After token authentification, closes the session at end */

       AFB_SESSION_NONE_V2 = 0		/* nothing required */
};

