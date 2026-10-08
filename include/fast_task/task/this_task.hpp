// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_INCLUDE_TASK_THIS_TASK
#define FAST_TASK_INCLUDE_TASK_THIS_TASK
#include "enter_state.hpp"
#include "fwd.hpp"

#if __cplusplus >= 202002
    #include "../coroutine/core.hpp"
#endif
namespace fast_task::this_task {
    size_t FT_API get_id() noexcept;
    void FT_API yield();
    void FT_API sleep_until(std::chrono::high_resolution_clock::time_point time_point);

    template <class Dur_resolution, class Dur_type>
    void sleep_for(std::chrono::duration<Dur_resolution, Dur_type> duration) {
        sleep_until(std::chrono::high_resolution_clock::now() + duration);
    }
    
    void FT_API check_cancellation();
    bool FT_API is_cancellation_requested() noexcept;
    void FT_API self_cancel();
    bool FT_API is_task() noexcept;
    void FT_API the_coroutine_ended(const task&) noexcept;
    bool FT_API transfer_to(const task& target);


    bool FT_API enter_sleep_until(enter_state&, std::chrono::high_resolution_clock::time_point time_point);
    bool FT_API enter_yield(enter_state&);

#if __cplusplus >= 202002

    [[nodiscard]] inline auto async_yield() {
        struct awaiter {
            enter_state state;

            bool await_ready() noexcept {
                return false;
            }

            bool await_suspend(const base_coro_handle&) {
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

            bool await_suspend(const base_coro_handle&) {
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

#endif
}
#endif /* FAST_TASK_INCLUDE_TASK_THIS_TASK */
