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


INCLUDE_DIRECTORIES(${include_dirs})

##################################################
# DBus Binding
##################################################
ADD_LIBRARY(afb-dbus-binding MODULE afb-dbus-binding.c)
SET_TARGET_PROPERTIES(afb-dbus-binding PROPERTIES
	PREFIX ""
	LINK_FLAGS "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/export.map"
)
TARGET_LINK_LIBRARIES(afb-dbus-binding ${json-c_LDFLAGS} ${libsystemd_LDFLAGS})
INSTALL(TARGETS afb-dbus-binding
        LIBRARY DESTINATION ${binding_install_dir})

