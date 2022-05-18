configure_file(yeti_version.h.cmake yeti_version.h)

set(yeti_config_files "")
set(yeti_config_dist_files yeti)

set(sems_module_name yeti)

file(GLOB_RECURSE yeti_SRCS "*.cpp")

include_directories(${HIREDIS_INCLUDE_DIR} ${PQXX_INCLUDE_DIRECTORIES} ${SEMS_INCLUDE_DIRS} ${CMAKE_CURRENT_BINARY_DIR})
set(sems_module_libs ${HIREDIS_LIBRARIES} ${PQXX_LIBRARIES} ${SEMS_LIBRARIES})

add_definitions("-fmacro-prefix-map=${CMAKE_CURRENT_SOURCE_DIR}/=${sems_module_name}:")

include(${SEMS_CMAKE_DIR}/module.rules.txt)
