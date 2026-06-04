
function(add_benchmark TARGET_NAME SOURCE_FILE)
    add_executable(${TARGET_NAME} ${SOURCE_FILE})
    target_link_libraries(${TARGET_NAME} PRIVATE fast_task)
    target_include_directories(${TARGET_NAME} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/tests
    )
    set_target_properties(${TARGET_NAME} PROPERTIES
        CXX_STANDARD 23
        CXX_EXTENSIONS OFF
    )
    if(MSVC)
        target_compile_options(${TARGET_NAME} PRIVATE /utf-8 /W3 /wd4100)
    endif()
endfunction()

add_benchmark(benchmark_task_spawn benchmark_task_spawn.cpp)
add_benchmark(benchmark_scheduler benchmark_scheduler.cpp)
add_benchmark(benchmark_context_switch benchmark_context_switch.cpp)
add_benchmark(benchmark_sync benchmark_sync.cpp)
add_benchmark(benchmark_memory benchmark_memory.cpp)

