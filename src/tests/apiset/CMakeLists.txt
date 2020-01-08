###########################################################################
# Copyright (C) 2015-2020 "IoT.bzh"
#
# author: José Bollo <jose.bollo@iot.bzh>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
###########################################################################

add_definitions(
  -DAGL_DEVEL=$<BOOL:${AGL_DEVEL}>
  -DWITH_AFB_HOOK=$<BOOL:${WITH_AFB_HOOK}>
)
add_executable(test-apiset test-apiset.c)
target_include_directories(test-apiset PRIVATE ../..)
target_link_libraries(test-apiset afb-lib ${link_libraries})
add_test(NAME apiset COMMAND test-apiset)

