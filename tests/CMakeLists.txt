enable_testing()

find_package(GTest CONFIG)
if(NOT GTest_FOUND)
  FetchContent_Declare(
    GTest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.16.0
  )
  FetchContent_MakeAvailable(GTest)
  file(GLOB _gtest_public_headers "${GTest_SOURCE_DIR}/*.h")
  file(MAKE_DIRECTORY "${GTest_SOURCE_DIR}/gtest")
  file(COPY ${_gtest_public_headers} DESTINATION "${GTest_SOURCE_DIR}/gtest")
  set(GTEST_EXTRA_INCLUDE_DIR "${GTest_SOURCE_DIR}")
endif()
include(GoogleTest)

set(FT_TESTS_ROOT ${CMAKE_CURRENT_SOURCE_DIR})

function(add_ft_test TARGET_NAME SOURCE_FILE)
    add_executable(${TARGET_NAME} ${SOURCE_FILE} ${FT_TESTS_ROOT}/main.cpp)
    target_link_libraries(${TARGET_NAME} PRIVATE GTest::gtest_main fast_task)
    target_include_directories(${TARGET_NAME} PRIVATE
        ${FT_TESTS_ROOT}              # for helpers.hpp
        ${CMAKE_SOURCE_DIR}/include   # library public headers
    )
    set_target_properties(${TARGET_NAME} PROPERTIES
        CXX_STANDARD 23
        CXX_EXTENSIONS OFF
    )
    if(MSVC)
        target_compile_options(${TARGET_NAME} PRIVATE /utf-8 /W3 /wd4100)
    else()
        if(CMAKE_BUILD_TYPE STREQUAL "Release" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebugInfo")
            target_link_options(${TARGET_NAME} PRIVATE -flto=auto)
        endif()
    endif()
    gtest_discover_tests(${TARGET_NAME})
endfunction()

add_subdirectory(allocator)
add_subdirectory(threading)
add_subdirectory(synchronization)
add_subdirectory(scheduler)
add_subdirectory(execution)
add_subdirectory(interrupt)
add_subdirectory(switch)
add_subdirectory(stackfull)
add_subdirectory(stackless)
add_subdirectory(futures)
add_subdirectory(mixed)

if(NOT FAST_TASK_DISABLE_IO_TESTS)
    add_subdirectory(io)
    add_subdirectory(network)
endif()

if(FAST_TASK_BUILD_BENCHMARKS)
    add_subdirectory(benchmark)
endif()
