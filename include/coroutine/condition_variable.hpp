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
            fast_task::unique_lock<mutex_unify>& lock;
            mutex_unify* mut;
            task_condition_variable& cv;

            bool await_ready() noexcept {
                return false;
            }

            bool await_suspend(base_coro_handle h) {
                return !cv.enter_wait(*mut, h.promise->task_object);
            }

            void await_resume() noexcept {
                lock = {*mut, fast_task::adopt_lock};
            }
        };

        return awaiter{lock, lock.release(), cv};
    }

    [[nodiscard]] inline auto async_wait_until(task_condition_variable& cv, fast_task::unique_lock<mutex_unify>& lock, std::chrono::high_resolution_clock::time_point time_point) {
        struct awaiter {
            fast_task::unique_lock<mutex_unify>& lock;
            mutex_unify* mut;
            task_condition_variable& cv;
            std::chrono::high_resolution_clock::time_point time_point;
            std::shared_ptr<fast_task::task> task_obj;
            bool successful = false;

            bool await_ready() noexcept {
                successful = std::chrono::high_resolution_clock::now() >= time_point;
                return successful;
            }

            bool await_suspend(base_coro_handle h) {
                task_obj = h.promise->task_object;
                return !cv.enter_wait_until(*mut, h.promise->task_object, time_point);
            }

            bool await_resume() noexcept {
                if (successful)
                    return true;
                successful = !task_obj->has_wait_timed_out();
                lock = {*mut, fast_task::adopt_lock};
                return successful;
            }
        };

        return awaiter{lock, lock.release(), cv, time_point};
    }

    template <class Rep, class Period>
    [[nodiscard]] inline auto async_wait_for(task_condition_variable& cv, fast_task::unique_lock<mutex_unify>& lock, const std::chrono::duration<Rep, Period>& duration) {
        return async_wait_until(cv, lock, std::chrono::high_resolution_clock::now() + duration);
    }

    [[nodiscard]] inline auto async_wait(task_condition_variable& cv, std::unique_lock<mutex_unify>& lock) {
        struct awaiter {
            std::unique_lock<mutex_unify>& lock;
            mutex_unify* mut;
            task_condition_variable& cv;

            bool await_ready() noexcept {
                return false;
            }

            bool await_suspend(base_coro_handle h) {
                return !cv.enter_wait(*mut, h.promise->task_object);
            }

            void await_resume() noexcept {
                lock = std::unique_lock<mutex_unify>(*mut, std::adopt_lock);
            }
        };

        return awaiter{lock, lock.release(), cv};
    }

    [[nodiscard]] inline auto async_wait_until(task_condition_variable& cv, std::unique_lock<mutex_unify>& lock, std::chrono::high_resolution_clock::time_point time_point) {
        struct awaiter {
            std::unique_lock<mutex_unify>& lock;
            mutex_unify* mut;
            task_condition_variable& cv;
            std::chrono::high_resolution_clock::time_point time_point;
            std::shared_ptr<fast_task::task> task_obj;
            bool successful = false;

            bool await_ready() noexcept {
                successful = std::chrono::high_resolution_clock::now() >= time_point;
                return successful;
            }

            bool await_suspend(base_coro_handle h) {
                task_obj = h.promise->task_object;
                return !cv.enter_wait_until(*mut, h.promise->task_object, time_point);
            }

            bool await_resume() noexcept {
                if (successful)
                    return true;
                successful = !task_obj->has_wait_timed_out();
                lock = std::unique_lock<mutex_unify>(*mut, std::adopt_lock);
                return successful;
            }
        };

        return awaiter{lock, lock.release(), cv, time_point};
    }

    template <class Rep, class Period>
    [[nodiscard]] inline auto async_wait_for(task_condition_variable& cv, std::unique_lock<mutex_unify>& lock, const std::chrono::duration<Rep, Period>& duration) {
        return async_wait_until(cv, lock, std::chrono::high_resolution_clock::now() + duration);
    }
} // namespace fast_task
#endif /* INCLUDE_COROUTINE_CONDITION_VARIABLE */
