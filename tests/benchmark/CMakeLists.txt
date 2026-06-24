add_executable(benchmark_runner
    benchmark_helpers.cpp
    benchmark_task_spawn.cpp
    benchmark_scheduler.cpp
    benchmark_context_switch.cpp
    benchmark_sync.cpp
    benchmark_memory.cpp
    benchmark_cpu.cpp
)

target_link_libraries(benchmark_runner PRIVATE fast_task)
target_include_directories(benchmark_runner PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/tests
)
set_target_properties(benchmark_runner PROPERTIES
    CXX_STANDARD 23
    CXX_EXTENSIONS OFF
)

if(MSVC)
    target_compile_options(benchmark_runner PRIVATE /utf-8 /W3 /wd4100)
else()
    if(CMAKE_BUILD_TYPE STREQUAL "Release" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebugInfo")
        target_link_options(benchmark_runner PRIVATE -flto=auto)
    endif()
endif()

