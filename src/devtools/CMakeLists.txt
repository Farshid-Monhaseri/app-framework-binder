###########################################################################
# Copyright (C) 2015-2019 "IoT.bzh"
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

ADD_EXECUTABLE(afb-genskel genskel.c)
ADD_EXECUTABLE(afb-exprefs exprefs.c)
ADD_EXECUTABLE(afb-json2c json2c.c)

TARGET_LINK_LIBRARIES(afb-genskel ${link_libraries})
TARGET_LINK_LIBRARIES(afb-exprefs ${link_libraries})
TARGET_LINK_LIBRARIES(afb-json2c ${link_libraries})

INSTALL(TARGETS afb-genskel RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
INSTALL(TARGETS afb-exprefs RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
INSTALL(TARGETS afb-json2c  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

