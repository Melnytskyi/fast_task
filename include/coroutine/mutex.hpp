// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef INCLUDE_COROUTINE_MUTEX
#define INCLUDE_COROUTINE_MUTEX
#include "../task/mutex.hpp"
#include "detail/lock_misc.hpp"
#include "core.hpp"

namespace fast_task {
    [[nodiscard]] inline auto async_lock(task_mutex& mut) {
        return detail::async_lock(mut);
    }

    [[nodiscard]] inline auto async_try_lock_until(task_mutex& mut, std::chrono::high_resolution_clock::time_point time_point) {
        return detail::async_try_lock_until(mut, time_point);
    }

    template <class Rep, class Period>
    [[nodiscard]] inline auto async_try_lock_for(task_mutex& mut, const std::chrono::duration<Rep, Period>& duration) {
        return detail::async_try_lock_until(mut, std::chrono::high_resolution_clock::now() + duration);
    }

    [[nodiscard]] inline auto async_lock(task_recursive_mutex& mut) {
        return detail::async_lock(mut);
    }

    [[nodiscard]] inline auto async_try_lock_until(task_recursive_mutex& mut, std::chrono::high_resolution_clock::time_point time_point) {
        return detail::async_try_lock_until(mut, time_point);
    }

    template <class Rep, class Period>
    [[nodiscard]] inline auto async_try_lock_for(task_recursive_mutex& mut, const std::chrono::duration<Rep, Period>& duration) {
        return detail::async_try_lock_until(mut, std::chrono::high_resolution_clock::now() + duration);
    }

    [[nodiscard]] inline auto async_read_lock(task_rw_mutex& mut) {
        struct awaiter {
            task_rw_mutex& mutex;

            bool await_ready() noexcept {
                return mutex.try_read_lock();
            }

            bool await_suspend(base_coro_handle h) {
                return !mutex.enter_read_wait(h.promise->task_object);
            }

            void await_resume() noexcept {}
        };

        return awaiter{mut};
    }

    [[nodiscard]] inline auto async_write_lock(task_rw_mutex& mut) {
        struct awaiter {
            task_rw_mutex& mutex;

            bool await_ready() noexcept {
                return mutex.try_write_lock();
            }

            bool await_suspend(base_coro_handle h) {
                return !mutex.enter_write_wait(h.promise->task_object);
            }

            void await_resume() noexcept {}
        };

        return awaiter{mut};
    }


    [[nodiscard]] inline auto async_try_read_lock_until(task_rw_mutex& mut, std::chrono::high_resolution_clock::time_point time_point) {
        struct awaiter {
            task_rw_mutex& mutex;
            std::chrono::high_resolution_clock::time_point time_point;
            std::shared_ptr<fast_task::task> task_obj;
            bool successful = false;

            bool await_ready() noexcept {
                if (mutex.try_read_lock()) {
                    successful = true;
                    return true;
                }
                return false;
            }

            bool await_suspend(base_coro_handle h) {
                task_obj = h.promise->task_object;
                return !mutex.enter_read_wait_until(h.promise->task_object, time_point);
            }

            bool await_resume() noexcept {
                if (successful)
                    return true;
                successful = !task_obj->has_wait_timed_out();
                return successful;
            }
        };

        return awaiter{mut, time_point};
    }

    template <class Rep, class Period>
    [[nodiscard]] inline auto async_try_read_lock_for(task_recursive_mutex& mut, const std::chrono::duration<Rep, Period>& duration) {
        return async_try_read_lock_until(mut, std::chrono::high_resolution_clock::now() + duration);
    }

    [[nodiscard]] inline auto async_try_write_lock_until(task_rw_mutex& mut, std::chrono::high_resolution_clock::time_point time_point) {
        struct awaiter {
            task_rw_mutex& mutex;
            std::chrono::high_resolution_clock::time_point time_point;
            std::shared_ptr<fast_task::task> task_obj;
            bool successful = false;

            bool await_ready() noexcept {
                if (mutex.try_write_lock()) {
                    successful = true;
                    return true;
                }
                return false;
            }

            bool await_suspend(base_coro_handle h) {
                task_obj = h.promise->task_object;
                return !mutex.enter_write_wait_until(h.promise->task_object, time_point);
            }

            bool await_resume() noexcept {
                if (successful)
                    return true;
                successful = !task_obj->has_wait_timed_out();
                return successful;
            }
        };

        return awaiter{mut, time_point};
    }

    template <class Rep, class Period>
    [[nodiscard]] inline auto async_try_write_lock_for(task_recursive_mutex& mut, const std::chrono::duration<Rep, Period>& duration) {
        return async_try_write_lock_until(mut, std::chrono::high_resolution_clock::now() + duration);
    }
}

#endif /* INCLUDE_COROUTINE_MUTEX */
