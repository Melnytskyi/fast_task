// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef INCLUDE_COROUTINE_DEADLINE_TIMER
#define INCLUDE_COROUTINE_DEADLINE_TIMER
#include "../task/deadline_timer.hpp"
#include "core.hpp"

namespace fast_task {
    inline [[nodiscard]] auto async_wait(deadline_timer& timer) {
        struct awaiter {
            deadline_timer& timer;
            std::chrono::high_resolution_clock::time_point timeout_time;
            std::shared_ptr<task> task_obj;

            bool await_ready() noexcept {
                return timer.timed_out();
            }

            bool await_suspend(base_coro_handle h) {
                task_obj = h.promise->task_object;
                return !timer.enter_wait(task_obj, timeout_time);
            }

            deadline_timer::status await_resume() noexcept {
                if (!task_obj)
                    return deadline_timer::status::timeouted;
                return timer.get_status(task_obj, timeout_time);
            }
        };

        return awaiter{timer};
    }

    inline [[nodiscard]] auto async_wait(deadline_timer& timer, fast_task::unique_lock<mutex_unify>& lock) {
        struct awaiter {
            mutex_unify& mut;
            deadline_timer& timer;
            std::chrono::high_resolution_clock::time_point timeout_time;
            std::shared_ptr<task> task_obj;

            bool await_ready() noexcept {
                return timer.timed_out();
            }

            bool await_suspend(base_coro_handle h) {
                task_obj = h.promise->task_object;
                return !timer.enter_wait(mut, task_obj, timeout_time);
            }

            deadline_timer::status await_resume() noexcept {
                if (!task_obj)
                    return deadline_timer::status::timeouted;
                return timer.get_status(task_obj, timeout_time);
            }
        };

        return awaiter{*lock.mutex(), timer};
    }

    inline [[nodiscard]] auto async_wait(deadline_timer& timer, std::unique_lock<mutex_unify>& lock) {
        struct awaiter {
            mutex_unify& mut;
            deadline_timer& timer;
            std::chrono::high_resolution_clock::time_point timeout_time;
            std::shared_ptr<task> task_obj;

            bool await_ready() noexcept {
                return timer.timed_out();
            }

            bool await_suspend(base_coro_handle h) {
                task_obj = h.promise->task_object;
                return !timer.enter_wait(mut, task_obj, timeout_time);
            }

            deadline_timer::status await_resume() noexcept {
                if (!task_obj)
                    return deadline_timer::status::timeouted;
                return timer.get_status(task_obj, timeout_time);
            }
        };

        return awaiter{*lock.mutex(), timer};
    }
} // namespace fast_task
#endif /* INCLUDE_COROUTINE_DEADLINE_TIMER */
