// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_INCLUDE_COROUTINE_SEMAPHORE
#define FAST_TASK_INCLUDE_COROUTINE_SEMAPHORE
#include "../task/semaphore.hpp"
#include "core.hpp"

namespace fast_task {
    [[nodiscard]] inline auto async_lock(semaphore& mut) {
        return detail::async_lock(mut);
    }

    [[nodiscard]] inline auto async_try_lock_until(semaphore& mut, std::chrono::high_resolution_clock::time_point time_point) {
        return detail::async_try_lock_until(mut, time_point);
    }

    template <class Rep, class Period>
    [[nodiscard]] inline auto async_try_lock_for(semaphore& mut, const std::chrono::duration<Rep, Period>& duration) {
        return detail::async_try_lock_until(mut, std::chrono::high_resolution_clock::now() + duration);
    }

    [[nodiscard]] inline auto async_lock(limiter& mut) {
        return detail::async_lock(mut);
    }

    [[nodiscard]] inline auto async_try_lock_until(limiter& mut, std::chrono::high_resolution_clock::time_point time_point) {
        return detail::async_try_lock_until(mut, time_point);
    }

    template <class Rep, class Period>
    [[nodiscard]] inline auto async_try_lock_for(limiter& mut, const std::chrono::duration<Rep, Period>& duration) {
        return detail::async_try_lock_until(mut, std::chrono::high_resolution_clock::now() + duration);
    }
}

#endif /* FAST_TASK_INCLUDE_COROUTINE_SEMAPHORE */
