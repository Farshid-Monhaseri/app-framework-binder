/*
 * Copyright (C) 2016-2019 "IoT.bzh"
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
 * @deprecated use bindings version 3
 *
 * Enum for Session/Token/Assurance of bindings version 1.
 */
enum afb_session_flags_x1
{
       AFB_SESSION_NONE_X1 = 0,   /**< nothing required */
       AFB_SESSION_CREATE_X1 = 1, /**< Obsolete */
       AFB_SESSION_CLOSE_X1 = 2,  /**< After token authentification, closes the session at end */
       AFB_SESSION_RENEW_X1 = 4,  /**< After token authentification, refreshes the token at end */
       AFB_SESSION_CHECK_X1 = 8,  /**< Requires token authentification */

       AFB_SESSION_LOA_GE_X1 = 16, /**< check that the LOA is greater or equal to the given value */
       AFB_SESSION_LOA_LE_X1 = 32, /**< check that the LOA is lesser or equal to the given value */
       AFB_SESSION_LOA_EQ_X1 = 48, /**< check that the LOA is equal to the given value */

       AFB_SESSION_LOA_SHIFT_X1 = 6, /**< shift for LOA */
       AFB_SESSION_LOA_MASK_X1 = 7,  /**< mask for LOA */

       AFB_SESSION_LOA_0_X1 = 0,   /**< value for LOA of 0 */
       AFB_SESSION_LOA_1_X1 = 64,  /**< value for LOA of 1 */
       AFB_SESSION_LOA_2_X1 = 128, /**< value for LOA of 2 */
       AFB_SESSION_LOA_3_X1 = 192, /**< value for LOA of 3 */
       AFB_SESSION_LOA_4_X1 = 256, /**< value for LOA of 4 */

       AFB_SESSION_LOA_LE_0_X1 = AFB_SESSION_LOA_LE_X1 | AFB_SESSION_LOA_0_X1, /**< check LOA <= 0 */
       AFB_SESSION_LOA_LE_1_X1 = AFB_SESSION_LOA_LE_X1 | AFB_SESSION_LOA_1_X1, /**< check LOA <= 1 */
       AFB_SESSION_LOA_LE_2_X1 = AFB_SESSION_LOA_LE_X1 | AFB_SESSION_LOA_2_X1, /**< check LOA <= 2 */
       AFB_SESSION_LOA_LE_3_X1 = AFB_SESSION_LOA_LE_X1 | AFB_SESSION_LOA_3_X1, /**< check LOA <= 3 */

       AFB_SESSION_LOA_EQ_0_X1 = AFB_SESSION_LOA_EQ_X1 | AFB_SESSION_LOA_0_X1, /**< check LOA == 0 */
       AFB_SESSION_LOA_EQ_1_X1 = AFB_SESSION_LOA_EQ_X1 | AFB_SESSION_LOA_1_X1, /**< check LOA == 1 */
       AFB_SESSION_LOA_EQ_2_X1 = AFB_SESSION_LOA_EQ_X1 | AFB_SESSION_LOA_2_X1, /**< check LOA == 2 */
       AFB_SESSION_LOA_EQ_3_X1 = AFB_SESSION_LOA_EQ_X1 | AFB_SESSION_LOA_3_X1, /**< check LOA == 3 */

       AFB_SESSION_LOA_GE_0_X1 = AFB_SESSION_LOA_GE_X1 | AFB_SESSION_LOA_0_X1, /**< check LOA >= 0 */
       AFB_SESSION_LOA_GE_1_X1 = AFB_SESSION_LOA_GE_X1 | AFB_SESSION_LOA_1_X1, /**< check LOA >= 1 */
       AFB_SESSION_LOA_GE_2_X1 = AFB_SESSION_LOA_GE_X1 | AFB_SESSION_LOA_2_X1, /**< check LOA >= 2 */
       AFB_SESSION_LOA_GE_3_X1 = AFB_SESSION_LOA_GE_X1 | AFB_SESSION_LOA_3_X1  /**< check LOA >= 3 */
};

