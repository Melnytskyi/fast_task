#ifndef FAST_TASK_TASK_FWD
#define FAST_TASK_TASK_FWD
#pragma once
#include <chrono>
#include <coroutine>
#include <memory>
#include "../shared.hpp"

namespace fast_task {
    class task;
    class task_mutex;
    class task_recursive_mutex;
    class task_rw_mutex;
    class mutex_unify;
    class multiply_mutex;
    class task_condition_variable;
    class task_semaphore;
    class task_limiter;
    class task_query;

    struct task_promise_base;
    struct base_coro_handle;

    namespace debug {
        struct _debug_collect;
    }
}

#endif /* FAST_TASK_TASK_FWD */
