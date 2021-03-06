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

CMAKE_MINIMUM_REQUIRED(VERSION 3.0)

PROJECT(afb-daemon C CXX)

SET(PROJECT_NAME "AFB Daemon")
SET(PROJECT_PRETTY_NAME "Application Framework Binder Daemon")
SET(PROJECT_DESCRIPTION "Secured binder of API for clients of the Application framework")
set(AGLVERSION "8.0.0" CACHE STRING "Version of AGL")
set(PROJECT_VERSION ${AGLVERSION} CACHE STRING "Version of the project can override AGLVERSION")
set(PROJECT_URL "https://gerrit.automotivelinux.org/gerrit/gitweb?p=src/app-framework-binder.git;a=summary")

SET(LIBAFBWSC_VERSION "1.1")
SET(LIBAFBWSC_SOVERSION "1")

INCLUDE(FindPkgConfig)
INCLUDE(CheckIncludeFiles)
INCLUDE(CheckLibraryExists)
INCLUDE(GNUInstallDirs)
INCLUDE(CTest)

###########################################################################
# possible settings

option(AGL_DEVEL                   "Activates developping features" OFF)
option(INCLUDE_MONITORING          "Activates installation of monitoring" OFF)

option(INCLUDE_SUPERVISOR          "Activates installation of supervisor" OFF)
option(INCLUDE_DBUS_TRANSPARENCY   "Allows API transparency over DBUS" OFF)
option(INCLUDE_LEGACY_BINDING_V1   "Includes the legacy Binding API version 1" OFF)
option(INCLUDE_LEGACY_BINDING_VDYN "Includes the legacy Binding API version dynamic" OFF)

set(AFS_SUPERVISION_SOCKET "@urn:AGL:afs:supervision:socket" CACHE STRING "Internal socket for supervision")
set(AFS_SUPERVISOR_PORT 1619 CACHE STRING "Port of service for the supervisor")
set(AFS_SUPERVISOR_TOKEN HELLO CACHE STRING "Secret token for the supervisor")
set(UNITDIR_SYSTEM ${CMAKE_INSTALL_LIBDIR}/systemd/system CACHE STRING "Path to systemd system unit files")
set(INTRINSIC_BINDING_DIR ${CMAKE_INSTALL_FULL_LIBDIR}/afb CACHE STRING "Path to install intrinsic bindings")
set(SAMPLE_INSTALL_DIR ${CMAKE_INSTALL_FULL_DATADIR}/af-binder CACHE STRING "Path to install samples")

###########################################################################

link_libraries(-Wl,--as-needed -Wl,--gc-sections -Wl,--no-undefined)

add_compile_options(-Wall -Wextra -Wconversion)
add_compile_options(-Wno-unused-parameter) # frankly not using a parameter does it care?
add_compile_options(-Wno-sign-compare -Wno-sign-conversion)
if (${CMAKE_C_COMPILER_ID} STREQUAL "GNU" OR ${CMAKE_CXX_COMPILER_ID} STREQUAL "GNU")
	add_compile_options(-Werror=maybe-uninitialized)
elseif(${CMAKE_C_COMPILER_ID} STREQUAL "Clang" OR ${CMAKE_CXX_COMPILER_ID} STREQUAL "Clang")
	add_compile_options(-Werror=sometimes-uninitialized)
endif()
add_compile_options(-Werror=implicit-function-declaration)
add_compile_options(-ffunction-sections -fdata-sections)
add_compile_options(-fPIC)
add_compile_options(-g -O2)
set (CMAKE_CXX_STANDARD 14)

set(CMAKE_C_FLAGS_PROFILING    "-g -O2 -pg -U_FORTIFY_SOURCE")
set(CMAKE_C_FLAGS_DEBUG        "-g -O2 -ggdb -U_FORTIFY_SOURCE")
set(CMAKE_C_FLAGS_RELEASE      "-g -O3")
set(CMAKE_C_FLAGS_CCOV         "-g -O2 --coverage")

###########################################################################

INCLUDE(FindThreads)
FIND_PACKAGE(Threads)

PKG_CHECK_MODULES(json-c REQUIRED json-c)

CHECK_INCLUDE_FILES(magic.h HAVE_MAGIC_H)
CHECK_LIBRARY_EXISTS(magic magic_load "" HAVE_LIBMAGIC_SO)
IF(HAVE_MAGIC_H)
  IF(HAVE_LIBMAGIC_SO)
    SET(HAVE_LIBMAGIC "1")
    SET(LIBMAGIC_LDFLAGS -lmagic)
  ENDIF(HAVE_LIBMAGIC_SO)
ENDIF(HAVE_MAGIC_H)

PKG_CHECK_MODULES(libsystemd libsystemd>=222)
PKG_CHECK_MODULES(libmicrohttpd libmicrohttpd>=0.9.60)
PKG_CHECK_MODULES(openssl openssl)
PKG_CHECK_MODULES(uuid uuid)
PKG_CHECK_MODULES(cynara cynara-client)

ADD_DEFINITIONS("-DAFS_SUPERVISION_SOCKET=\"${AFS_SUPERVISION_SOCKET}\"")
ADD_DEFINITIONS("-DAFS_SUPERVISOR_TOKEN=\"${AFS_SUPERVISOR_TOKEN}\"")
ADD_DEFINITIONS("-DAFS_SUPERVISOR_PORT=${AFS_SUPERVISOR_PORT}")

IF(cynara_FOUND)
	ADD_DEFINITIONS(-DBACKEND_PERMISSION_IS_CYNARA)
ENDIF(cynara_FOUND)

IF(HAVE_LIBMAGIC AND libsystemd_FOUND AND libmicrohttpd_FOUND AND openssl_FOUND AND uuid_FOUND)
  ADD_DEFINITIONS(-DUSE_MAGIC_MIME_TYPE)
ELSE()
  IF(NOT HAVE_LIBMAGIC)
    MESSAGE(WARNING "\"magic.h\" or \"libmagic.so\" missing.
    Please install the \"file-devel\" or \"libmagic-dev\" package !")
  ENDIF(NOT HAVE_LIBMAGIC)
  IF(NOT libsystemd_FOUND)
    MESSAGE(WARNING "Dependency to 'libsystemd' is missing")
  ENDIF()
  IF(NOT libmicrohttpd_FOUND)
    MESSAGE(WARNING "Dependency to 'libmicrohttpd' is missing")
  ENDIF()
  IF(NOT openssl_FOUND)
    MESSAGE(WARNING "Dependency to 'openssl' is missing")
  ENDIF()
  IF(NOT uuid_FOUND)
    MESSAGE(WARNING "Dependency to 'uuid' is missing")
  ENDIF()
  IF(NOT ONLY_DEVTOOLS)
    MESSAGE(FATAL_ERROR "Can't compile the binder, either define ONLY_DEVTOOLS or install dependencies")
  ENDIF()
ENDIF()

ADD_DEFINITIONS(-DAFB_VERSION="${PROJECT_VERSION}")

INCLUDE_DIRECTORIES(
	${INCLUDE_DIRS}
	${CMAKE_SOURCE_DIR}/include
	${json-c_INCLUDE_DIRS}
	${libsystemd_INCLUDE_DIRS}
	${libmicrohttpd_INCLUDE_DIRS}
	${uuid_INCLUDE_DIRS}
	${openssl_INCLUDE_DIRS}
	${cynara_INCLUDE_DIRS}
)

SET(link_libraries
	${CMAKE_THREAD_LIBS_INIT}
	${json-c_LDFLAGS}
	${libsystemd_LDFLAGS}
	${libmicrohttpd_LDFLAGS}
	${uuid_LDFLAGS}
	${openssl_LDFLAGS}
	${cynara_LDFLAGS}
	${LIBMAGIC_LDFLAGS}
	-ldl
	-lrt
	-latomic
	)

ADD_SUBDIRECTORY(src/devtools)

IF(ONLY_DEVTOOLS)
	MESSAGE(WARNING "Only DEVTOOLS are compiled, not the binder!")
ELSE()

	###########################################################################
	# activates the monitoring by default
	if(INCLUDE_MONITORING AND NOT ONLY_DEVTOOLS)
		add_definitions(-DWITH_MONITORING_OPTION)
		INSTALL(DIRECTORY
			${CMAKE_CURRENT_SOURCE_DIR}/test/monitoring
			DESTINATION
			${INTRINSIC_BINDING_DIR}
		)
	endif()

	###########################################################################

	ADD_SUBDIRECTORY(src)
	ADD_SUBDIRECTORY(src/tests)
	ADD_SUBDIRECTORY(include)
	ADD_SUBDIRECTORY(bindings)

	############################################################
	# installs the pkgconfig files
	CONFIGURE_FILE(afb-daemon.pc.in afb-daemon.pc @ONLY)
	CONFIGURE_FILE(libafbwsc.pc.in libafbwsc.pc @ONLY)

	INSTALL(FILES
	    ${CMAKE_CURRENT_BINARY_DIR}/afb-daemon.pc
	    ${CMAKE_CURRENT_BINARY_DIR}/libafbwsc.pc
	    DESTINATION
	    ${CMAKE_INSTALL_LIBDIR}/pkgconfig
	)

ENDIF()

IF(INCLUDE_SUPERVISOR)
	CONFIGURE_FILE(afs-supervisor.service.in afs-supervisor.service @ONLY)
	INSTALL(FILES
	    ${CMAKE_CURRENT_SOURCE_DIR}/afm-api-supervisor.service
	    ${CMAKE_CURRENT_SOURCE_DIR}/afm-api-supervisor.socket
	    ${CMAKE_CURRENT_BINARY_DIR}/afs-supervisor.service
	    DESTINATION
	    ${UNITDIR_SYSTEM}
	)
ENDIF()

