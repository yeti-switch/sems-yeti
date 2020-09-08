cmake_minimum_required(VERSION 3.0)
project(yeti)

# Don't do automatic escaping of variables
cmake_policy(SET CMP0005 OLD)

if(NOT EXISTS ${CMAKE_SOURCE_DIR}/.git)
	MESSAGE(FATAL_ERROR "git repository required")
endif(NOT EXISTS ${CMAKE_SOURCE_DIR}/.git)

find_package(Git REQUIRED)

list(APPEND CMAKE_MODULE_PATH "/usr/share/cmake/sems")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

find_package(PQXX REQUIRED)
find_package(Hiredis REQUIRED)
find_package(SEMS REQUIRED)

list(APPEND CMAKE_CXX_FLAGS_DEBUG -D_DEBUG)
list(APPEND CMAKE_C_FLAGS_DEBUG -D_DEBUG)

add_definitions("-D__FILENAME__='\"yeti:$(subst ${CMAKE_CURRENT_SOURCE_DIR}/src/,,$(abspath $<))\"'")
add_definitions(${SEMS_CFLAGS})
add_definitions(-std=c++2a -Wno-deprecated)

execute_process(
	COMMAND bash "-c" "head -n 1 changelog | sed -e 's/^[^(]*(\\([^)]*\\)).*/\\1/'"
	WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/debian
	OUTPUT_VARIABLE PKG_VERSION
	OUTPUT_STRIP_TRAILING_WHITESPACE
)
message(STATUS "pkg version: " ${PKG_VERSION})

execute_process(
	COMMAND ${GIT_EXECUTABLE} describe HEAD --tags
	WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
	OUTPUT_VARIABLE TAG_VERSION
	OUTPUT_STRIP_TRAILING_WHITESPACE
)
message(STATUS "git tags: " ${TAG_VERSION})
set(BUILD_VERSION ${TAG_VERSION})

execute_process(
	COMMAND ${GIT_EXECUTABLE} rev-parse HEAD
	WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
	OUTPUT_VARIABLE "COMMIT_HASH"
	ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE
)
message(STATUS "git commit: " ${COMMIT_HASH})
set(BUILD_COMMIT ${COMMIT_HASH})

execute_process(
	COMMAND "date"
	OUTPUT_VARIABLE "BUILD_DATE"
	ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE
)
message(STATUS "build date: " ${BUILD_DATE})

execute_process(
	COMMAND "whoami"
	OUTPUT_VARIABLE "BUILD_USER"
	ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE
)
message(STATUS "build user: " ${BUILD_USER})

string(REGEX REPLACE "[-\\.]" ";" TAG_VERSION_LIST ${TAG_VERSION})
list(GET TAG_VERSION_LIST 0 YETI_MAJOR_VERSION)
list(GET TAG_VERSION_LIST 1 YETI_MINOR_VERSION)
list(GET TAG_VERSION_LIST 2 YETI_PATCH_VERSION)

#sources
configure_file(${CMAKE_SOURCE_DIR}/src/yeti_version.h.cmake ${CMAKE_SOURCE_DIR}/src/yeti_version.h)

set(yeti_config_files "")
set(yeti_config_dist_files yeti)

set(sems_module_name yeti)

file(GLOB_RECURSE yeti_SRCS "src/*.cpp")

include_directories(${HIREDIS_INCLUDE_DIR} ${PQXX_INCLUDE_DIRECTORIES} ${SEMS_INCLUDE_DIRS} ${CMAKE_CURRENT_BINARY_DIR})
set(sems_module_libs ${HIREDIS_LIBRARIES} ${PQXX_LIBRARIES} ${SEMS_LIBRARIES})

include(${SEMS_CMAKE_DIR}/module.rules.txt)

add_subdirectory(etc)
