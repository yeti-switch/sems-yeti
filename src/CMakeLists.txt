configure_file(yeti_version.h.cmake yeti_version.h)

set(yeti_config_files "")
set(yeti_config_dist_files yeti)

set(sems_module_name yeti)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")

file(GLOB_RECURSE yeti_SRCS "*.cpp")
file(GLOB yeti_UNIT_SRCS "../unit_tests/*.cpp")

include_directories(${SEMS_INCLUDE_DIRS} ${CMAKE_CURRENT_BINARY_DIR})
set(sems_module_libs ${SEMS_LIBRARIES})

add_definitions("-fmacro-prefix-map=${CMAKE_CURRENT_SOURCE_DIR}/=${sems_module_name}:")

include(${SEMS_CMAKE_DIR}/module.rules.txt)
