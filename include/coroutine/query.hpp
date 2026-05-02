// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef INCLUDE_COROUTINE_QUERY
#define INCLUDE_COROUTINE_QUERY
#include "../task/query.hpp"
#include "../task/scheduler.hpp"
#include "core.hpp"

namespace fast_task {
    [[nodiscard]] inline auto async_wait(task_query& query) {
        struct awaiter {
            task_query& query;

            bool await_ready() noexcept {
                return false;
            }

            bool await_suspend(base_coro_handle h) {
                return !query.enter_wait(h.promise->task_object);
            }

            void await_resume() noexcept {}
        };

        return awaiter{query};
    }

    [[nodiscard]] inline auto async_wait_until(task_query& query, std::chrono::high_resolution_clock::time_point time_point) {
        struct awaiter {
            task_query& query;
            std::chrono::high_resolution_clock::time_point time_point;
            std::shared_ptr<fast_task::task> task_obj;
            bool successful = false;

            bool await_ready() noexcept {
                successful = std::chrono::high_resolution_clock::now() >= time_point;
                return successful;
            }

            bool await_suspend(base_coro_handle h) {
                task_obj = h.promise->task_object;
                return !query.enter_wait_until(h.promise->task_object, time_point);
            }

            bool await_resume() noexcept {
                if (successful)
                    return true;
                successful = !task_obj->has_wait_timed_out();
                return successful;
            }
        };

        return awaiter{query, time_point};
    }

    template <class Rep, class Period>
    [[nodiscard]] inline auto async_wait_for(task_query& query, const std::chrono::duration<Rep, Period>& duration) {
        return async_wait_until(query, std::chrono::high_resolution_clock::now() + duration);
    }
} // namespace fast_task

#endif /* INCLUDE_COROUTINE_QUERY */
