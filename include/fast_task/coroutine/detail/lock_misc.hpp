// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_INCLUDE_COROUTINE_DETAIL_LOCK_MISC
#define FAST_TASK_INCLUDE_COROUTINE_DETAIL_LOCK_MISC
#include "../../task/scheduler.hpp"
#include <chrono>

namespace fast_task::detail {
    template <class T>
    struct async_lock_awaiter {
        enter_state state;
        T& mutex;

        bool await_ready() {
            return mutex.try_lock();
        }

        template <std::derived_from<task_promise_base> Promise>
        bool await_suspend(std::coroutine_handle<Promise> h) {
            return !mutex.enter_wait(h.promise().task_object, state);
        }

        void await_resume() {}
    };

    template <class T>
    [[nodiscard]] auto async_lock(T& mut) {
        return async_lock_awaiter<T>{{}, mut};
    }

    template <class T>
    struct async_try_lock_until_awaiter {
        enter_state state;
        T& mutex;
        fast_task::time_point time_point;
        fast_task::task task_obj;
        bool successful = false;

        bool await_ready() {
            successful = mutex.try_lock();
            return successful;
        }

        template <std::derived_from<task_promise_base> Promise>
        bool await_suspend(std::coroutine_handle<Promise> h) {
            task_obj = h.promise().task_object;
            if (mutex.enter_wait_until(task_obj, state, time_point)) {
                successful = true;
                return false;
            }
            return true;
        }

        bool await_resume() {
            if (successful)
                return true;
            successful = !task_obj.has_wait_timed_out();
            return successful;
        }
    };

    template <class T>
    [[nodiscard]] auto async_try_lock_until(T& mut, fast_task::time_point time_point) {
        return async_try_lock_until_awaiter<T>{{}, mut, time_point, {}};
    }
}

#endif /* FAST_TASK_INCLUDE_COROUTINE_DETAIL_LOCK_MISC */
