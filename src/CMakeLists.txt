###########################################################################
# Copyright (C) 2015-2018 "IoT.bzh"
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

if (CMAKE_C_COMPILER_VERSION VERSION_LESS 4.9)
    message(FATAL_ERROR "Require at least gcc-4.9")
endif(CMAKE_C_COMPILER_VERSION VERSION_LESS 4.9)

ADD_DEFINITIONS(-DBINDING_INSTALL_DIR="${binding_install_dir}")
# Always add INFER_EXTENSION (more details in afb-hreq.c)
ADD_DEFINITIONS(-DINFER_EXTENSION)

SET(AFB_LIB_SOURCES
	afb-api.c
	afb-api-so.c
	afb-api-so-v2.c
	afb-api-so-v3.c
	afb-api-so-vdyn.c
	afb-api-v3.c
	afb-api-ws.c
	afb-apiset.c
	afb-auth.c
	afb-autoset.c
	afb-calls.c
	afb-common.c
	afb-config.c
	afb-context.c
	afb-cred.c
	afb-debug.c
	afb-evt.c
	afb-export.c
	afb-fdev.c
	afb-hook.c
	afb-hook-flags.c
	afb-hreq.c
	afb-hsrv.c
	afb-hswitch.c
	afb-method.c
	afb-monitor.c
	afb-msg-json.c
	afb-proto-ws.c
	afb-session.c
	afb-socket.c
	afb-stub-ws.c
	afb-systemd.c
	afb-trace.c
	afb-websock.c
	afb-ws-client.c
	afb-ws-json1.c
	afb-ws.c
	afb-wsj1.c
	afb-xreq.c
	fdev.c
	fdev-epoll.c
	fdev-systemd.c
	globset.c
	jobs.c
	locale-root.c
	pearson.c
	process-name.c
	sig-monitor.c
	subpath.c
	verbose.c
	websock.c
	wrap-json.c
)

IF(INCLUDE_LEGACY_BINDING_V1)
	ADD_DEFINITIONS(-DWITH_LEGACY_BINDING_V1)
	SET(AFB_LIB_SOURCES ${AFB_LIB_SOURCES} afb-api-so-v1.c)
ENDIF(INCLUDE_LEGACY_BINDING_V1)
IF(INCLUDE_LEGACY_BINDING_VDYN)
	ADD_DEFINITIONS(-DWITH_LEGACY_BINDING_VDYN)
	SET(AFB_LIB_SOURCES ${AFB_LIB_SOURCES} afb-api-so-vdyn.c)
ENDIF(INCLUDE_LEGACY_BINDING_VDYN)

IF(INCLUDE_DBUS_TRANSPARENCY)
	ADD_DEFINITIONS(-DWITH_DBUS_TRANSPARENCY)
	SET(AFB_LIB_SOURCES ${AFB_LIB_SOURCES} afb-api-dbus.c)
ENDIF()
IF(INCLUDE_SUPERVISOR)
	ADD_DEFINITIONS(-DWITH_SUPERVISION)
	SET(AFB_LIB_SOURCES ${AFB_LIB_SOURCES} afb-supervision.c)
ENDIF()

ADD_LIBRARY(afb-lib STATIC ${AFB_LIB_SOURCES})

###########################################
# build and install afb-daemon
###########################################
ADD_EXECUTABLE(afb-daemon main-afb-daemon.c)
TARGET_LINK_LIBRARIES(afb-daemon
	afb-lib
	${link_libraries}
)
INSTALL(TARGETS afb-daemon
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

###########################################
# build and install afb-daemon
###########################################
IF(INCLUDE_SUPERVISOR)
	ADD_EXECUTABLE(afs-supervisor main-afs-supervisor.c afs-supervisor.c afs-discover.c afs-config.c)
	TARGET_LINK_LIBRARIES(afs-supervisor
		afb-lib
		${link_libraries}
	)
	INSTALL(TARGETS afs-supervisor
		RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
ENDIF()

###########################################
# build and install libafbwsc
###########################################
ADD_LIBRARY(afbwsc SHARED afb-ws.c afb-ws-client.c afb-wsj1.c websock.c afb-proto-ws.c fdev.c fdev-systemd.c)
SET_TARGET_PROPERTIES(afbwsc PROPERTIES
	VERSION ${LIBAFBWSC_VERSION}
	SOVERSION ${LIBAFBWSC_SOVERSION})
TARGET_LINK_LIBRARIES(afbwsc
	${libsystemd_LDFLAGS}
	${json-c_LDFLAGS}
	-lpthread
	-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/export-afbwsc.map
	-Wl,--as-needed
	-Wl,--gc-sections
)
INSTALL(TARGETS afbwsc LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
INSTALL(FILES afb-wsj1.h afb-ws-client.h afb-proto-ws.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/afb)

###########################################
# build and install afb-client-demo
###########################################
ADD_EXECUTABLE(afb-client-demo main-afb-client-demo.c)
TARGET_LINK_LIBRARIES(afb-client-demo
	afbwsc
	${link_libraries}
	${libsystemd_LDFLAGS}
)
INSTALL(TARGETS afb-client-demo
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

