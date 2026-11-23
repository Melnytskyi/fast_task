add_ft_test(test_scheduler_lifecycle  test_scheduler_lifecycle.cpp)
add_ft_test(test_task_queue           test_task_queue.cpp)
add_ft_test(test_bind_executor        test_bind_executor.cpp)
add_ft_test(test_deadline_timer       test_deadline_timer.cpp)
add_ft_test(test_worker_context       test_worker_context.cpp)
add_ft_test(test_pool_policies        test_pool_policies.cpp)
add_ft_test(test_pool_control         test_pool_control.cpp)
add_ft_test(test_pool_affinity        test_pool_affinity.cpp)
add_ft_test(test_pool_dormant         test_pool_dormant.cpp)
add_ft_test(test_pool_balancer        test_pool_balancer.cpp)
add_ft_test(test_global_pool_config   test_global_pool_config.cpp)
# Reaches the private headers under src/ to unit-test the S1 eventcount itself.
add_ft_test(test_scheduler_event      test_scheduler_event.cpp ${CMAKE_SOURCE_DIR}/src)
# src/tasks/core/notify/event.hpp pads the eventcount to the cache line size, which
# triggers -Winterference-size; the library target suppresses it in
# cmake/CompilerOptions.cmake for exactly the same reason.
if(NOT MSVC)
  target_compile_options(test_scheduler_event PRIVATE -Wno-interference-size)
endif()
