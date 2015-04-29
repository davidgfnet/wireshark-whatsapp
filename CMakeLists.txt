# CMakeLists.txt
#
# $Id: CMakeLists.txt 31995 2010-02-24 22:32:10Z jmayer $
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#

project(whatsapp C CXX)

cmake_minimum_required(VERSION 2.6)
set(CMAKE_BACKWARDS_COMPATIBILITY 2.6)
set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)
IF(EXISTS /usr/lib/wireshark/libwireshark1/plugins/)
set(CMAKE_INSTALL_LIBDIR /usr/lib/wireshark/libwireshark1/plugins/)
ELSE()
set(CMAKE_INSTALL_LIBDIR ~/.wireshark)
ENDIF()

INCLUDE(UseMakeDissectorReg)
include(CMakeForceCompiler)
  
set(GLIB2_MIN_VERSION 2.4.0)

IF(NOT DEFINED ENV{GLIB2_INCLUDE_DIRS})
find_package(GLIB2)
ELSE()
SET(GLIB2_INCLUDE_DIRS $ENV{GLIB2_INCLUDE_DIRS})
ENDIF()
include_directories (${GLIB2_INCLUDE_DIRS})

IF(NOT DEFINED WIRESHARK_INCLUDE_DIRS)
find_package(Wireshark)
ELSE()
SET(GLIB2_INCLUDE_DIRS $ENV{WIRESHARK_INCLUDE_DIRS})
ENDIF()
include_directories (${WIRESHARK_INCLUDE_DIRS})

IF(NOT DEFINED GCRYPT_INCLUDE_DIR)
find_package(Gcrypt)
ELSE()
SET(GLIB2_INCLUDE_DIRS $ENV{GCRYPT_INCLUDE_DIR})
ENDIF()
include_directories (${GCRYPT_INCLUDE_DIR})

set(LINK_MODE_LIB SHARED)
set(LINK_MODE_MODULE MODULE)


set(DISSECTOR_SRC
	packet-whatsapp.c
	whatsapp-proto.cc
	tinfl.c
)

set(PLUGIN_FILES
	plugin.c
	${DISSECTOR_SRC}
)

set(CLEAN_FILES
	${PLUGIN_FILES}
)

if (WERROR)
	set_source_files_properties(
		${CLEAN_FILES}
		PROPERTIES
		COMPILE_FLAGS -Werror
	)
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

register_dissector_files(plugin.c
	plugin
	${DISSECTOR_SRC}
)

add_library(whatsapp ${LINK_MODE_MODULE}
	${PLUGIN_FILES}
)
set_target_properties(whatsapp PROPERTIES PREFIX "")
set_target_properties(whatsapp PROPERTIES LINK_FLAGS "${WS_LINK_FLAGS}")

IF(DEFINED MANUAL_LINK)
target_link_libraries(whatsapp)
ELSE()
target_link_libraries(whatsapp gcrypt)
ENDIF()

install(TARGETS whatsapp
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/plugins NAMELINK_SKIP
)

IF(DEFINED GNU_HOST)
 CMAKE_FORCE_C_COMPILER(  ${GNU_HOST}-gcc GNU)
 CMAKE_FORCE_CXX_COMPILER(${GNU_HOST}-g++ GNU)
 set(CMAKE_STRIP "${GNU_HOST}-strip")
ENDIF()

IF(DEFINED STATIC_GCC_BUILD)
 set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} -static-libgcc -static-libstdc++")
ENDIF()

add_custom_command(TARGET whatsapp
 POST_BUILD
 COMMAND ${CMAKE_STRIP} --strip-debug --strip-unneeded whatsapp.so
)


