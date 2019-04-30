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


MACRO(tuto num ext)
  ADD_LIBRARY(tuto-${num} MODULE tuto-${num}.${ext})
  SET_TARGET_PROPERTIES(tuto-${num} PROPERTIES
	PREFIX ""
	LINK_FLAGS "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/export.map"
  )
  TARGET_LINK_LIBRARIES(tuto-${num}  ${json-c_LDFLAGS})
  install(TARGETS tuto-${num} LIBRARY DESTINATION ${SAMPLE_INSTALL_DIR}/bindings/tutorials)
ENDMACRO(tuto)


tuto(1 c)
tuto(2 c)
tuto(3 cpp)
tuto(4 c)
tuto(5 cpp)

tuto(app1 c)
