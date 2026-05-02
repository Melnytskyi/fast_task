// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef INCLUDE_COROUTINE_SEMAPHORE
#define INCLUDE_COROUTINE_SEMAPHORE
#include "../task/semaphore.hpp"
#include "core.hpp"

namespace fast_task {
    [[nodiscard]] inline auto async_lock(task_semaphore& mut) {
        return detail::async_lock(mut);
    }

    [[nodiscard]] inline auto async_try_lock_until(task_semaphore& mut, std::chrono::high_resolution_clock::time_point time_point) {
        return detail::async_try_lock_until(mut, time_point);
    }

    template <class Rep, class Period>
    [[nodiscard]] inline auto async_try_lock_for(task_semaphore& mut, const std::chrono::duration<Rep, Period>& duration) {
        return detail::async_try_lock_until(mut, std::chrono::high_resolution_clock::now() + duration);
    }

    [[nodiscard]] inline auto async_lock(task_limiter& mut) {
        return detail::async_lock(mut);
    }

    [[nodiscard]] inline auto async_try_lock_until(task_limiter& mut, std::chrono::high_resolution_clock::time_point time_point) {
        return detail::async_try_lock_until(mut, time_point);
    }

    template <class Rep, class Period>
    [[nodiscard]] inline auto async_try_lock_for(task_limiter& mut, const std::chrono::duration<Rep, Period>& duration) {
        return detail::async_try_lock_until(mut, std::chrono::high_resolution_clock::now() + duration);
    }
}

#endif /* INCLUDE_COROUTINE_SEMAPHORE */
