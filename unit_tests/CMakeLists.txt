find_package(GTest REQUIRED)

add_executable(sems-tester IMPORTED GLOBAL)
set_property(TARGET sems-tester PROPERTY
             IMPORTED_LOCATION /usr/bin/sems-tester)

gtest_discover_tests(sems-tester
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    TEST_FILTER "YetiTest.*:YetiTest/*"
    DISCOVERY_MODE PRE_TEST
)

file(MAKE_DIRECTORY
    ${CMAKE_CURRENT_BINARY_DIR}/rsr
    ${CMAKE_CURRENT_BINARY_DIR}/logs
    ${CMAKE_CURRENT_BINARY_DIR}/dump
    ${CMAKE_CURRENT_BINARY_DIR}/record
)
