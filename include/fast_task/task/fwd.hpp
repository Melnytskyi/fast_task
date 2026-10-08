// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_INCLUDE_TASK_TASK_FWD
#define FAST_TASK_INCLUDE_TASK_TASK_FWD
#pragma once
#include "../shared.hpp"
#include "../shared/primitives.hpp"
#include <chrono>
#include <coroutine>
#include <memory>

namespace fast_task {
    class task;
    class mutex;
    class recursive_mutex;
    class rw_mutex;
    class mutex_unify;
    class multiply_mutex;
    class condition_variable;
    class semaphore;
    class limiter;
    class queue;

    struct task_promise_base;
    struct task_base_coro_handle;

    namespace debug {
        struct _debug_collect;
    }

    template <class T>
    class future;
}

#endif /* FAST_TASK_TASK_FWD */
