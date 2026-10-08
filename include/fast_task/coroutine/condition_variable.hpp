// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_INCLUDE_COROUTINE_CONDITION_VARIABLE
#define FAST_TASK_INCLUDE_COROUTINE_CONDITION_VARIABLE
#include "../task/condition_variable.hpp"
#include "../task/scheduler.hpp"
#include "core.hpp"

namespace fast_task {
    [[nodiscard]] inline auto async_wait(condition_variable& cv, fast_task::unique_lock<mutex>& lock) {
        struct awaiter {
            enter_state state;
            fast_task::unique_lock<mutex>& lock;
            mutex* mut;
            condition_variable& cv;

            bool await_ready() noexcept {
                return false;
            }

            bool await_suspend(base_coro_handle h) {
                return !cv.enter_wait(*mut, h.promise->task_object, state);
            }

            void await_resume() noexcept {
                lock = {*mut, fast_task::adopt_lock};
            }
        };

        return awaiter{{}, lock, lock.release(), cv};
    }

    [[nodiscard]] inline auto async_wait_until(condition_variable& cv, fast_task::unique_lock<mutex>& lock, std::chrono::high_resolution_clock::time_point time_point) {
        struct awaiter {
            enter_state state;
            fast_task::unique_lock<mutex>& lock;
            mutex* mut;
            condition_variable& cv;
            std::chrono::high_resolution_clock::time_point time_point;
            fast_task::task task_obj;
            bool successful = false;

            bool await_ready() noexcept {
                successful = std::chrono::high_resolution_clock::now() >= time_point;
                return successful;
            }

            bool await_suspend(base_coro_handle h) {
                task_obj = h.promise->task_object;
                return !cv.enter_wait_until(*mut, h.promise->task_object, state, time_point);
            }

            bool await_resume() noexcept {
                if (successful)
                    return true;
                successful = !task_obj.has_wait_timed_out();
                lock = {*mut, fast_task::adopt_lock};
                return successful;
            }
        };

        return awaiter{{}, lock, lock.release(), cv, time_point};
    }

    template <class Rep, class Period>
    [[nodiscard]] inline auto async_wait_for(condition_variable& cv, fast_task::unique_lock<mutex>& lock, const std::chrono::duration<Rep, Period>& duration) {
        return async_wait_until(cv, lock, std::chrono::high_resolution_clock::now() + duration);
    }

    [[nodiscard]] inline auto async_wait(condition_variable& cv, std::unique_lock<mutex>& lock) {
        struct awaiter {
            enter_state state;
            std::unique_lock<mutex>& lock;
            mutex* mut;
            condition_variable& cv;

            bool await_ready() noexcept {
                return false;
            }

            bool await_suspend(base_coro_handle h) {
                return !cv.enter_wait(*mut, h.promise->task_object, state);
            }

            void await_resume() noexcept {
                lock = std::unique_lock<mutex>(*mut, std::adopt_lock);
            }
        };

        return awaiter{{}, lock, lock.release(), cv};
    }

    [[nodiscard]] inline auto async_wait_until(condition_variable& cv, std::unique_lock<mutex>& lock, std::chrono::high_resolution_clock::time_point time_point) {
        struct awaiter {
            enter_state state;
            std::unique_lock<mutex>& lock;
            mutex* mut;
            condition_variable& cv;
            std::chrono::high_resolution_clock::time_point time_point;
            fast_task::task task_obj;
            bool successful = false;

            bool await_ready() noexcept {
                successful = std::chrono::high_resolution_clock::now() >= time_point;
                return successful;
            }

            bool await_suspend(base_coro_handle h) {
                task_obj = h.promise->task_object;
                return !cv.enter_wait_until(*mut, h.promise->task_object, state, time_point);
            }

            bool await_resume() noexcept {
                if (successful)
                    return true;
                successful = !task_obj.has_wait_timed_out();
                lock = std::unique_lock<mutex>(*mut, std::adopt_lock);
                return successful;
            }
        };

        return awaiter{{}, lock, lock.release(), cv, time_point};
    }

    template <class Rep, class Period>
    [[nodiscard]] inline auto async_wait_for(condition_variable& cv, std::unique_lock<mutex>& lock, const std::chrono::duration<Rep, Period>& duration) {
        return async_wait_until(cv, lock, std::chrono::high_resolution_clock::now() + duration);
    }
} // namespace fast_task
#endif /* FAST_TASK_INCLUDE_COROUTINE_CONDITION_VARIABLE */
