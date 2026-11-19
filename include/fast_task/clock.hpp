// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_INCLUDE_CLOCK
#define FAST_TASK_INCLUDE_CLOCK
#pragma once

#include <chrono>

namespace fast_task {
    // Every deadline, timeout and timer tick in the library uses this clock.
    //
    // fast_task::clock is std::system_clock on libstdc++ and
    // libc++, so it follows wall time: an NTP step or a manual clock change can
    // make a sleep finish instantly or stall for hours, and it can reorder
    // timer-wheel buckets. std::chrono::steady_clock is monotonic
    // (CLOCK_MONOTONIC on Linux, QueryPerformanceCounter on Windows) and must be
    // the only source of scheduling time.
    using clock = std::chrono::steady_clock;
    using time_point = clock::time_point;
    using duration = clock::duration;

    // Sentinel for "no deadline". The whole library uses time_point::min() as
    // the disabled value, both as a time_point and as a raw rep in
    // task_object::execution_data::timeout.
    inline constexpr time_point no_deadline = time_point::min();

    // Saturating "now + d". A caller may pass duration::max() (for example a
    // user-supplied "infinite" timeout), and a plain now() + d would overflow
    // the time_point representation into a negative value, which the scheduler
    // would read as an already-expired deadline.
    inline time_point deadline_after(duration d) noexcept {
        const auto now = clock::now();
        if (d <= duration::zero())
            return now + d;
        if (d >= time_point::max() - now)
            return time_point::max();
        return now + d;
    }

    // Convenience overload so callers can write deadline_after(milliseconds(5)).
    template <class Rep, class Period>
    inline time_point deadline_after(const std::chrono::duration<Rep, Period>& d) noexcept {
        const auto converted = std::chrono::duration_cast<duration>(d);
        return deadline_after(converted);
    }

    [[nodiscard]] inline bool is_no_deadline(time_point tp) noexcept {
        return tp == no_deadline;
    }
}

#endif /* FAST_TASK_INCLUDE_CLOCK */
