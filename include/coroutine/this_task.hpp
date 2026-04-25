#ifndef INCLUDE_COROUTINE_THIS_TASK
#define INCLUDE_COROUTINE_THIS_TASK
#include "../task/this_task.hpp"
#include "core.hpp"

namespace fast_task::this_task {
    inline [[nodiscard]] auto async_yield() {
        struct awaiter {

            bool await_ready() noexcept {
                return false;
            }

            bool await_suspend(base_coro_handle h) {
                return enter_yield();
            }

            void await_resume() {}
        };

        return awaiter{};
    }

    inline [[nodiscard]] auto async_sleep_until(std::chrono::high_resolution_clock::time_point time_point) {
        struct awaiter {
            std::chrono::high_resolution_clock::time_point time_point;

            bool await_ready() noexcept {
                return false;
            }

            bool await_suspend(base_coro_handle h) {
                return enter_sleep_until(time_point);
            }

            void await_resume() {}
        };

        return awaiter{time_point};
    }

    template <class Rep, class Period>
    inline [[nodiscard]] auto async_sleep_for(task_limiter& mut, const std::chrono::duration<Rep, Period>& duration) {
        return enter_sleep_until(mut, std::chrono::high_resolution_clock::now() + duration);
    }
}

#endif /* INCLUDE_COROUTINE_THIS_TASK */
