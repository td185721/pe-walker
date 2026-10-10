cmake_minimum_required(VERSION 3.15)
project(pe_walker CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(pe-walker src/main.cpp)

if(MSVC)
    target_compile_options(pe-walker PRIVATE /W4 /permissive-)
else()
    target_compile_options(pe-walker PRIVATE -Wall -Wextra -Wpedantic)
endif()

# Tests: golden-file comparisons against fixture DLLs built from
# tests/fixtures/sample.cpp (see tests/fixtures/build.cmd).
if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR AND NOT CMAKE_CROSSCOMPILING)
    enable_testing()
    function(golden_test name expected_rc args)
        add_test(NAME ${name}
                 COMMAND ${CMAKE_COMMAND}
                         -DTOOL=$<TARGET_FILE:pe-walker>
                         "-DARGS=${args}"
                         -DWORKDIR=${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures
                         -DEXPECTED=${CMAKE_CURRENT_SOURCE_DIR}/tests/expected/${name}.txt
                         -DEXPECTED_RC=${expected_rc}
                         -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_golden.cmake)
    endfunction()
    golden_test(x64-full 0 "sample64.dll")
    golden_test(x64-summary 0 "--summary|sample64.dll")
    golden_test(x86-full 0 "sample32.dll")
    golden_test(missing-file 1 "does-not-exist.dll")
    golden_test(usage 2 "")
    golden_test(color-summary 0 "--color=always|--summary|sample64.dll")
    golden_test(bad-color 2 "--color=rainbow|sample64.dll")
endif()
