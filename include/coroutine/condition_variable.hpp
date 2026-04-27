// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef INCLUDE_COROUTINE_CONDITION_VARIABLE
#define INCLUDE_COROUTINE_CONDITION_VARIABLE
#include "../task/condition_variable.hpp"
#include "../task/scheduler.hpp"
#include "core.hpp"

namespace fast_task {
    [[nodiscard]] inline auto async_wait(task_condition_variable& cv, fast_task::unique_lock<mutex_unify>& lock) {
        struct awaiter {
            mutex_unify& mut;
            task_condition_variable& cv;

            bool await_ready() noexcept {
                return false;
            }

            bool await_suspend(base_coro_handle h) {
                return !cv.enter_wait(mut, h.promise->task_object);
            }

            void await_resume() noexcept {}
        };

        return awaiter{*lock.mutex(), cv};
    }

    [[nodiscard]] inline auto async_wait_until(task_condition_variable& cv, fast_task::unique_lock<mutex_unify>& lock, std::chrono::high_resolution_clock::time_point time_point) {
        struct awaiter {
            mutex_unify& mut;
            task_condition_variable& cv;
            std::chrono::high_resolution_clock::time_point time_point;
            bool successful = false;

            bool await_ready() noexcept {
                successful = std::chrono::high_resolution_clock::now() >= time_point;
                return successful;
            }

            bool await_suspend(base_coro_handle h) {
                return !cv.enter_wait_until(mut, h.promise->task_object, time_point);
            }

            bool await_resume() noexcept {
                if (successful)
                    return true;
                successful = !fast_task::scheduler::current_context_task()->has_wait_timed_out();
                return successful;
            }
        };

        return awaiter{*lock.mutex(), cv, time_point};
    }

    template <class Rep, class Period>
    [[nodiscard]] inline auto async_wait_for(task_condition_variable& cv, fast_task::unique_lock<mutex_unify>& lock, const std::chrono::duration<Rep, Period>& duration) {
        return async_wait_until(cv, lock, std::chrono::high_resolution_clock::now() + duration);
    }

    [[nodiscard]] inline auto async_wait(task_condition_variable& cv, std::unique_lock<mutex_unify>& lock) {
        struct awaiter {
            mutex_unify& mut;
            task_condition_variable& cv;

            bool await_ready() noexcept {
                return false;
            }

            bool await_suspend(base_coro_handle h) {
                return !cv.enter_wait(mut, h.promise->task_object);
            }

            void await_resume() noexcept {}
        };

        return awaiter{*lock.mutex(), cv};
    }

    [[nodiscard]] inline auto async_wait_until(task_condition_variable& cv, std::unique_lock<mutex_unify>& lock, std::chrono::high_resolution_clock::time_point time_point) {
        struct awaiter {
            mutex_unify& mut;
            task_condition_variable& cv;
            std::chrono::high_resolution_clock::time_point time_point;
            bool successful = false;

            bool await_ready() noexcept {
                successful = std::chrono::high_resolution_clock::now() >= time_point;
                return successful;
            }

            bool await_suspend(base_coro_handle h) {
                return !cv.enter_wait_until(mut, h.promise->task_object, time_point);
            }

            bool await_resume() noexcept {
                if (successful)
                    return true;
                successful = !fast_task::scheduler::current_context_task()->has_wait_timed_out();
                return successful;
            }
        };

        return awaiter{*lock.mutex(), cv, time_point};
    }

    template <class Rep, class Period>
    [[nodiscard]] inline auto async_wait_for(task_condition_variable& cv, std::unique_lock<mutex_unify>& lock, const std::chrono::duration<Rep, Period>& duration) {
        return async_wait_until(cv, lock, std::chrono::high_resolution_clock::now() + duration);
    }
} // namespace fast_task
#endif /* INCLUDE_COROUTINE_CONDITION_VARIABLE */
