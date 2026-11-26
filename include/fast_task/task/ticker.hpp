// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_INCLUDE_TASK_TICKER
#define FAST_TASK_INCLUDE_TASK_TICKER

#include "../clock.hpp"
#include "this_task.hpp"
#include <chrono>
#include <cstdint>
#include <stdexcept>

#if __cplusplus >= 202002 || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002)
    #include "../coroutine/core.hpp"
#endif

namespace fast_task {
    enum class missed_tick_policy : uint8_t {
        burst, // fire immediately for each missed tick to catch up
        skip,  // advance schedule to the next future period multiple in O(1)
        delay  // reschedule next tick to now + period
    };

    // Drift-free periodic timer built on fast_task::clock and this_task::sleep_until.
    // Zero heap allocations, zero background threads, zero mutexes.
    class ticker {
        fast_task::duration period_;
        fast_task::time_point next_;
        missed_tick_policy policy_;

        fast_task::time_point advance_deadline() noexcept {
            const auto now = fast_task::clock::now();
            const auto target = next_;
            if (now < target) {
                next_ = target + period_;
                return target;
            }
            switch (policy_) {
            case missed_tick_policy::burst:
                next_ = target + period_;
                return target;
            case missed_tick_policy::skip: {
                const auto elapsed = (now - target).count();
                const auto step = period_.count();
                const auto missed = (elapsed / step) + 1;
                next_ = target + fast_task::duration(missed * step);
                return now;
            }
            case missed_tick_policy::delay:
                next_ = now + period_;
                return now;
            }
            next_ = now + period_;
            return now;
        }

    public:
        template <class Rep, class Period>
        explicit ticker(
            const std::chrono::duration<Rep, Period>& period,
            missed_tick_policy policy = missed_tick_policy::skip
        )
            : period_(std::chrono::duration_cast<fast_task::duration>(period)),
              next_(fast_task::clock::now() + period_),
              policy_(policy) {
            if (period_ <= fast_task::duration::zero())
                throw std::invalid_argument("fast_task::ticker period must be > 0");
        }

        void reset() noexcept {
            next_ = fast_task::clock::now() + period_;
        }

        fast_task::duration period() const noexcept {
            return period_;
        }

        fast_task::time_point next_tick() const noexcept {
            return next_;
        }

        missed_tick_policy policy() const noexcept {
            return policy_;
        }

        void tick() {
            const auto target = advance_deadline();
            if (target > fast_task::clock::now())
                this_task::sleep_until(target);
        }

#if __cplusplus >= 202002 || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002)
        [[nodiscard]] auto async_tick() {
            const auto target = advance_deadline();
            return this_task::async_sleep_until(target);
        }
#endif
    };
}

#endif /* FAST_TASK_INCLUDE_TASK_TICKER */
