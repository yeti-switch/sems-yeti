cmake_minimum_required(VERSION 3.0)

set(CMAKE_C_COMPILER clang-14 CACHE STRING "c compiler" FORCE)
set(CMAKE_CXX_COMPILER clang++-14 CACHE STRING "c++ compiler" FORCE)

project(yeti)

if(NOT EXISTS ${CMAKE_SOURCE_DIR}/.git)
	MESSAGE(FATAL_ERROR "git repository required")
endif(NOT EXISTS ${CMAKE_SOURCE_DIR}/.git)

find_package(Git REQUIRED)

list(APPEND CMAKE_MODULE_PATH "/usr/share/cmake/sems")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

find_package(Hiredis REQUIRED)
find_package(SEMS REQUIRED)

list(APPEND CMAKE_CXX_FLAGS_DEBUG -D_DEBUG)
list(APPEND CMAKE_C_FLAGS_DEBUG -D_DEBUG)

add_compile_options(${SEMS_CFLAGS})
add_compile_options(-std=c++2a -Wall -Werror -g)

if(EXISTS ${CMAKE_SOURCE_DIR}/debian/changelog)
    file(STRINGS ${CMAKE_SOURCE_DIR}/debian/changelog CHANGELOG_LINE LIMIT_COUNT 1)
    string(REGEX REPLACE "^[^(]*\\(([0-9]+)\\.([0-9]+)\\.([0-9a-z]+)\\).*" "\\1.\\2.\\3" BUILD_VERSION ${CHANGELOG_LINE})
    set(YETI_MAJOR_VERSION ${CMAKE_MATCH_1})
    set(YETI_MINOR_VERSION ${CMAKE_MATCH_2})
    set(YETI_PATCH_VERSION ${CMAKE_MATCH_3})
    set(SEMS_VERSION ${BUILD_VERSION})

    message(STATUS "Version from changelog: " ${SEMS_VERSION})
else(EXISTS ${CMAKE_SOURCE_DIR}/debian/changelog)
    message(FATAL_ERROR "debian/changelog not found")
endif(EXISTS ${CMAKE_SOURCE_DIR}/debian/changelog)

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

add_subdirectory(src)
add_subdirectory(etc)

add_custom_target(test USES_TERMINAL COMMAND /bin/bash ${CMAKE_SOURCE_DIR}/run_unit_test.sh YetiTest.*:YetiTest/*-YetiTest.Redis*:YetiTest.Resource*)
