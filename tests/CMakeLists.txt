enable_testing()

find_package(GTest CONFIG REQUIRED)
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
        set_property(TARGET ${TARGET_NAME} PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
        target_compile_options(${TARGET_NAME} PRIVATE /utf-8 /W3 /wd4100)
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
