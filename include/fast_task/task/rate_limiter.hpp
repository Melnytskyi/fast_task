// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_INCLUDE_TASK_RATE_LIMITER
#define FAST_TASK_INCLUDE_TASK_RATE_LIMITER

#include "../clock.hpp"
#include "this_task.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <stdexcept>

#if __cplusplus >= 202002 || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002)
    #include "../coroutine/core.hpp"
#endif

namespace fast_task {
    // Lock-free GCRA (Generic Cell Rate Algorithm) token bucket rate limiter.
    // Zero background threads, zero mutexes, zero heap allocations — 1 atomic int64_t.
    class rate_limiter {
        int64_t emission_interval_ns_;
        int64_t burst_tolerance_ns_;
        alignas(64) std::atomic<int64_t> tat_ns_{0};

        static int64_t now_ns() noexcept {
            return std::chrono::duration_cast<std::chrono::nanoseconds>(
                       fast_task::clock::now().time_since_epoch()
            )
                .count();
        }

    public:
        // rate_per_sec: sustained permits per second (> 0)
        // burst: maximum burst permits allowed immediately (>= 1)
        rate_limiter(double rate_per_sec, uint32_t burst = 1) {
            if (rate_per_sec <= 0.0)
                throw std::invalid_argument("rate_limiter rate_per_sec must be > 0");
            if (burst == 0)
                throw std::invalid_argument("rate_limiter burst must be >= 1");
            emission_interval_ns_ = std::max<int64_t>(1, static_cast<int64_t>(1'000'000'000.0 / rate_per_sec));
            burst_tolerance_ns_ = emission_interval_ns_ * static_cast<int64_t>(burst);
            tat_ns_.store(now_ns(), std::memory_order_relaxed);
        }

        rate_limiter(const rate_limiter&) = delete;
        rate_limiter& operator=(const rate_limiter&) = delete;
        rate_limiter(rate_limiter&&) = delete;
        rate_limiter& operator=(rate_limiter&&) = delete;

        bool try_acquire(uint32_t permits = 1) noexcept {
            if (permits == 0)
                return true;
            const int64_t cost = emission_interval_ns_ * static_cast<int64_t>(permits);
            const int64_t now = now_ns();
            int64_t tat = tat_ns_.load(std::memory_order_relaxed);
            for (;;) {
                const int64_t new_tat = (tat > now ? tat : now) + cost;
                if (new_tat - now > burst_tolerance_ns_)
                    return false;
                if (tat_ns_.compare_exchange_weak(tat, new_tat, std::memory_order_acq_rel, std::memory_order_relaxed))
                    return true;
            }
        }

        // Reserves `permits` atomically and returns the exact nanoseconds to wait (0 if immediate).
        int64_t reserve_wait_ns(uint32_t permits = 1) noexcept {
            if (permits == 0)
                return 0;
            const int64_t cost = emission_interval_ns_ * static_cast<int64_t>(permits);
            const int64_t now = now_ns();
            int64_t tat = tat_ns_.load(std::memory_order_relaxed);
            for (;;) {
                const int64_t new_tat = (tat > now ? tat : now) + cost;
                if (tat_ns_.compare_exchange_weak(tat, new_tat, std::memory_order_acq_rel, std::memory_order_relaxed)) {
                    const int64_t allow_at = new_tat - burst_tolerance_ns_;
                    return allow_at > now ? (allow_at - now) : 0;
                }
            }
        }

        void acquire(uint32_t permits = 1) {
            const int64_t wait_ns = reserve_wait_ns(permits);
            if (wait_ns > 0)
                this_task::sleep_for(std::chrono::nanoseconds(wait_ns));
        }

        bool acquire_until(fast_task::time_point deadline, uint32_t permits = 1) {
            if (permits == 0)
                return true;
            const int64_t cost = emission_interval_ns_ * static_cast<int64_t>(permits);
            const int64_t deadline_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                            deadline.time_since_epoch()
            )
                                            .count();
            const int64_t now = now_ns();
            int64_t tat = tat_ns_.load(std::memory_order_relaxed);
            for (;;) {
                const int64_t new_tat = (tat > now ? tat : now) + cost;
                const int64_t allow_at = new_tat - burst_tolerance_ns_;
                if (allow_at > deadline_ns)
                    return false;
                if (tat_ns_.compare_exchange_weak(tat, new_tat, std::memory_order_acq_rel, std::memory_order_relaxed)) {
                    if (allow_at > now)
                        this_task::sleep_for(std::chrono::nanoseconds(allow_at - now));
                    return true;
                }
            }
        }

        template <class Rep, class Period>
        bool acquire_for(const std::chrono::duration<Rep, Period>& dur, uint32_t permits = 1) {
            return acquire_until(fast_task::deadline_after(dur), permits);
        }

#if __cplusplus >= 202002 || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002)
        [[nodiscard]] auto async_acquire(uint32_t permits = 1) {
            const int64_t wait_ns = reserve_wait_ns(permits);
            return this_task::async_sleep_for(std::chrono::nanoseconds(wait_ns));
        }
#endif
    };
}

#endif /* FAST_TASK_INCLUDE_TASK_RATE_LIMITER */
