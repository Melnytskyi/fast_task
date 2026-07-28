#ifndef FAST_TASK_INCLUDE_COROUTINE_THIS_TASK
#define FAST_TASK_INCLUDE_COROUTINE_THIS_TASK
#include "../task/this_task.hpp"
#include "core.hpp"

namespace fast_task::this_task {
    [[nodiscard]] inline auto async_yield() {
        struct awaiter {
            enter_state state;

            bool await_ready() noexcept {
                return false;
            }

            bool await_suspend(base_coro_handle h) {
                return !enter_yield(state);
            }

            void await_resume() {}
        };

        return awaiter{};
    }

    [[nodiscard]] inline auto async_sleep_until(std::chrono::high_resolution_clock::time_point time_point) {
        struct awaiter {
            enter_state state;
            std::chrono::high_resolution_clock::time_point time_point;

            bool await_ready() noexcept {
                return false;
            }

            bool await_suspend(base_coro_handle h) {
                return !enter_sleep_until(state, time_point);
            }

            void await_resume() {}
        };

        return awaiter{{}, time_point};
    }

    template <class Rep, class Period>
    [[nodiscard]] inline auto async_sleep_for(const std::chrono::duration<Rep, Period>& duration) {
        return async_sleep_until(std::chrono::high_resolution_clock::now() + duration);
    }
}

#endif /* FAST_TASK_INCLUDE_COROUTINE_THIS_TASK */
