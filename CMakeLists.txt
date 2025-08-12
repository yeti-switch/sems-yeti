cmake_minimum_required(VERSION 3.22)

set(CMAKE_C_COMPILER clang CACHE STRING "c compiler" FORCE)
set(CMAKE_CXX_COMPILER clang++ CACHE STRING "c++ compiler" FORCE)
set(CMAKE_CXX_STANDARD 20)

project(yeti)

include(CTest)

if(NOT EXISTS ${CMAKE_SOURCE_DIR}/.git)
	MESSAGE(FATAL_ERROR "git repository required")
endif(NOT EXISTS ${CMAKE_SOURCE_DIR}/.git)

find_package(Git REQUIRED)

list(APPEND CMAKE_MODULE_PATH "/usr/share/cmake/sems")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

option(ENABLE_LLVM_COVERAGE "Enable coverage with LLVM" OFF)
find_package(SEMS REQUIRED)

list(APPEND CMAKE_CXX_FLAGS_DEBUG -D_DEBUG)
list(APPEND CMAKE_C_FLAGS_DEBUG -D_DEBUG)

add_compile_options(${SEMS_CFLAGS})
add_compile_options(-Wall -Werror -g)
add_compile_options(-Wno-unknown-warning-option)
add_compile_options(-Wno-vla-cxx-extension)

if(ENABLE_LLVM_COVERAGE)
    add_definitions("-fprofile-instr-generate -fcoverage-mapping")
endif()

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

add_subdirectory(unit_tests)

add_custom_target(print_paths ALL
    COMMAND ${CMAKE_COMMAND} -E echo "$<TARGET_FILE:sems_${PROJECT_NAME}_unit> $<TARGET_FILE:sems-tester>"
)

if(ENABLE_LLVM_COVERAGE)
	add_custom_target(coverage
    COMMAND LLVM_PROFILE_FILE=coverage_gtest.profraw
			$<TARGET_FILE:sems-tester>
			-c ./unit_tests/etc/sems_test.cfg
			--gtest_filter=YetiTest.*
    COMMAND llvm-profdata merge -sparse coverage_gtest.profraw -o coverage.profdata
    COMMAND llvm-cov show $<TARGET_FILE:sems_${PROJECT_NAME}_unit>
            -instr-profile=coverage.profdata
            --ignore-filename-regex=\"\(/usr/include/*\)\"
            --object=$<TARGET_FILE:sems_${PROJECT_NAME}_unit>
            -format=html
            -output-dir=html
    COMMAND llvm-cov export $<TARGET_FILE:sems_${PROJECT_NAME}_unit>
            -instr-profile=coverage.profdata
            --object=$<TARGET_FILE:sems_${PROJECT_NAME}_unit>
            --ignore-filename-regex=\"\(/usr/include/*\)\" |
            jq \"{
                data: [
                    {
                        files:[(
                            .data[0].files[] | del(.segments, .expansions, .branches)
                        )],
                        totals: (.data[0].totals)
                        }
                ]
            }\" > coverage.json

    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    )
endif()
