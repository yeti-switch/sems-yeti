configure_file(yeti_version.h.cmake yeti_version.h)

set(yeti_config_files "")
set(yeti_config_dist_files ${PROJECT_NAME})

set(sems_module_name ${PROJECT_NAME})

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")

file(GLOB_RECURSE ${PROJECT_NAME}_SRCS "*.cpp")
file(GLOB ${PROJECT_NAME}_UNIT_SRCS "../unit_tests/*.cpp")

include_directories(${SEMS_INCLUDE_DIRS} ${CMAKE_CURRENT_BINARY_DIR})
set(sems_module_libs ${SEMS_LIBRARIES})

add_definitions("-fmacro-prefix-map=${CMAKE_CURRENT_SOURCE_DIR}/=${sems_module_name}:")

include(${SEMS_CMAKE_DIR}/module.rules.txt)

if(ENABLE_LLVM_COVERAGE)
    target_link_options(sems_${sems_module_name}_unit PRIVATE -fprofile-instr-generate -fcoverage-mapping)
endif()
