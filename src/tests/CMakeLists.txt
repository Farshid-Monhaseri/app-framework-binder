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


PKG_CHECK_MODULES(check check)
if(check_FOUND)
	INCLUDE_DIRECTORIES(${INCLUDE_DIRS} ${check_INCLUDE_DIRS})
	SET(link_libraries ${link_libraries} ${check_LDFLAGS})
	add_subdirectory(session)
	add_subdirectory(apiset)
	add_subdirectory(apiv3)
	add_subdirectory(wrap-json)
	add_subdirectory(globset)
	add_subdirectory(u16id)
else(check_FOUND)
	MESSAGE(WARNING "check not found! no test!")
endif(check_FOUND)
