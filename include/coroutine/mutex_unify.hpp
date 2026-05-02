// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef INCLUDE_COROUTINE_MUTEX_UNIFY
#define INCLUDE_COROUTINE_MUTEX_UNIFY
#include "../task/condition_variable.hpp"
#include "core.hpp"
#include "detail/lock_misc.hpp"

namespace fast_task {
    [[nodiscard]] inline auto async_lock(mutex_unify& mut) {
        return detail::async_lock(mut);
    }

    [[nodiscard]] inline auto async_try_lock_until(mutex_unify& mut, std::chrono::high_resolution_clock::time_point time_point) {
        return detail::async_try_lock_until(mut, time_point);
    }

    template <class Rep, class Period>
    [[nodiscard]] inline auto async_try_lock_for(mutex_unify& mut, const std::chrono::duration<Rep, Period>& duration) {
        return detail::async_try_lock_until(mut, std::chrono::high_resolution_clock::now() + duration);
    }

    [[nodiscard]] inline auto async_lock(multiply_mutex& mut) {
        return detail::async_lock(mut);
    }

    [[nodiscard]] inline auto async_try_lock_until(multiply_mutex& mut, std::chrono::high_resolution_clock::time_point time_point) {
        return detail::async_try_lock_until(mut, time_point);
    }

    template <class Rep, class Period>
    [[nodiscard]] inline auto async_try_lock_for(multiply_mutex& mut, const std::chrono::duration<Rep, Period>& duration) {
        return detail::async_try_lock_until(mut, std::chrono::high_resolution_clock::now() + duration);
    }
}
#endif /* INCLUDE_COROUTINE_MUTEX_UNIFY */
