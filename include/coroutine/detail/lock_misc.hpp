// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef INCLUDE_COROUTINE_DETAIL_LOCK_MISC
#define INCLUDE_COROUTINE_DETAIL_LOCK_MISC
#include "../../task/scheduler.hpp"
#include <chrono>

namespace fast_task::detail {
    template <class T>
    [[nodiscard]] auto async_lock(T& mut) {
        struct awaiter {
            T& mutex;

            bool await_ready() noexcept {
                return mutex.try_lock();
            }

            bool await_suspend(base_coro_handle h) {
                return !mutex.enter_wait(h.promise->task_object);
            }

            void await_resume() {}
        };

        return awaiter{mut};
    }

    template <class T>
    [[nodiscard]] auto async_try_lock_until(T& mut, std::chrono::high_resolution_clock::time_point time_point) {
        struct awaiter {
            T& mutex;
            std::chrono::high_resolution_clock::time_point time_point;
            base_coro_handle handle;
            bool successful = false;

            bool await_ready() noexcept {
                successful = mutex.try_lock();
                return successful;
            }

            bool await_suspend(base_coro_handle h) {
                return !mutex.enter_wait_until(h.promise->task_object, time_point);
            }

            bool await_resume() {
                if (successful)
                    return true;
                successful = !fast_task::scheduler::current_context_task()->has_wait_timed_out();
                return successful;
            }
        };

        return awaiter{mut, time_point};
    }
}

#endif /* INCLUDE_COROUTINE_DETAIL_LOCK_MISC */
