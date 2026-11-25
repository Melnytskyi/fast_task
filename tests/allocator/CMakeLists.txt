if(FAST_TASK_STATIC)
    add_ft_test(test_allocator test_allocator.cpp)
    target_include_directories(test_allocator PRIVATE ${CMAKE_SOURCE_DIR}/src)
endif()
