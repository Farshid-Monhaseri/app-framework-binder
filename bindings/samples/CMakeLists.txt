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

macro(sample name source)
  add_library(${name} MODULE ${source})
  set_target_properties(${name} PROPERTIES PREFIX "" LINK_FLAGS "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/export.map")
#  target_link_libraries(${name} ${link_libraries})
  target_link_libraries(${name} ${json-c_LDFLAGS} ${CMAKE_THREAD_LIBS_INIT})
  install(TARGETS ${name} LIBRARY DESTINATION ${SAMPLE_INSTALL_DIR}/bindings/samples)
endmacro(sample)

sample(authLogin    AuthLogin.c)
sample(demoContext  DemoContext.c)
sample(demoPost     DemoPost.c)
sample(tic-tac-toe  tic-tac-toe.c)
sample(hello2       hello2.c)
sample(hello3       hello3.c)

