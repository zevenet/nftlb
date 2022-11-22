###############################################################################
#
#    Zevenet zproxy Load Balancer Software License
#    This file is part of the Zevenet zproxy Load Balancer software package.
#
#    Copyright (C) 2019-today ZEVENET SL, Sevilla (Spain)
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
###############################################################################
cmake_minimum_required(VERSION 3.6)
set(CMAKE_CXX_STANDARD 17)

if(EXISTS CMakeLists.txt)
    message(FATAL_ERROR"Please create a cmake build directory, running cmake form source tree root is not allowed\n")
endif()

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif ()

set (CMAKE_ENABLE_EXPORTS TRUE)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(MAINFOLDER ${PROJECT_SOURCE_DIR})

set(PROJECT_VERSION "0.0.1")
set(PROJECT_DESCRIPTION "Zevenet core utils library")
set(PROJECT_CODENAME "zcutils")

# get current git info
if (EXISTS "${PROJECT_SOURCE_DIR}/.git/HEAD")
    file(READ "${PROJECT_SOURCE_DIR}/.git/HEAD"
        PROJECT_SOURCE_VERSION)
    if ("${PROJECT_SOURCE_VERSION}" MATCHES "^ref:")
        string(REGEX REPLACE "^ref: *([^ \n\r]*).*" "\\1"
            PROJECT_GIT_REF "${PROJECT_SOURCE_VERSION}")
        file(READ "${PROJECT_SOURCE_DIR}/.git/${PROJECT_GIT_REF}"
            PROJECT_SOURCE_VERSION)
    endif ()
    string(STRIP "${PROJECT_SOURCE_VERSION}"
        PROJECT_SOURCE_VERSION)
endif ()

add_definitions(-DPROJECT_NAME="zcutils")
add_definitions(-DPROJECT_VERSION="${PROJECT_VERSION}")

if (UNIQUE_BUILD_DIRECTORY)
	set(EXECUTABLE_OUTPUT_PATH "${MAINFOLDER}/build/bin")
endif ()

set(sources
	## sources
	src/zcu_log.c
	src/zcu_network.c
	src/zcu_backtrace.c
	src/zcu_sbuffer.c
	src/zcu_string.c

	## libs
	include/zcu_log.h
	include/zcu_common.h
	include/zcu_backtrace.h
	include/zcu_environment.h
	include/zcu_time.h
	include/zcu_network.h
	include/zcu_sbuffer.h
	include/zcu_string.h
)

include_directories(${PROJECT_SOURCE_DIR}/zcutils/include)

add_library(zcutils ${sources})

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m64 -pipe -g -Wno-unused-function -Wall")

include_directories(${PROJECT_SOURCE_DIR}/include)
