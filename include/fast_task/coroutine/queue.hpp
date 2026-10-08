// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_INCLUDE_COROUTINE_QUEUE
#define FAST_TASK_INCLUDE_COROUTINE_QUEUE
#include "../task/queue.hpp"
#include "../task/scheduler.hpp"
#include "core.hpp"

namespace fast_task {
    [[nodiscard]] inline auto async_wait(queue& q) {
        struct awaiter {
            enter_state state;
            queue& q;

            bool await_ready() noexcept {
                return false;
            }

            bool await_suspend(base_coro_handle h) {
                return !q.enter_wait(h.promise->task_object, state);
            }

            void await_resume() noexcept {}
        };

        return awaiter{{}, q};
    }

    [[nodiscard]] inline auto async_wait_until(queue& q, std::chrono::high_resolution_clock::time_point time_point) {
        struct awaiter {
            enter_state state;
            queue& q;
            std::chrono::high_resolution_clock::time_point time_point;
            fast_task::task task_obj;
            bool successful = false;

            bool await_ready() noexcept {
                successful = std::chrono::high_resolution_clock::now() >= time_point;
                return successful;
            }

            bool await_suspend(base_coro_handle h) {
                task_obj = h.promise->task_object;
                return !q.enter_wait_until(h.promise->task_object, state, time_point);
            }

            bool await_resume() noexcept {
                if (successful)
                    return true;
                successful = !task_obj.has_wait_timed_out();
                return successful;
            }
        };

        return awaiter{{}, q, time_point};
    }

    template <class Rep, class Period>
    [[nodiscard]] inline auto async_wait_for(queue& q, const std::chrono::duration<Rep, Period>& duration) {
        return async_wait_until(q, std::chrono::high_resolution_clock::now() + duration);
    }
} // namespace fast_task

#endif /* FAST_TASK_INCLUDE_COROUTINE_QUEUE */
