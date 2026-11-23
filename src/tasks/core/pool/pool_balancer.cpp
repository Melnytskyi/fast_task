// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <chrono>

#include <tasks/_internal.hpp>

namespace fast_task {
    namespace {
        constexpr uint64_t balance_prime_ns = 10'000'000ull;
        constexpr uint64_t balance_max_window_ns = 2'000'000'000ull;
        constexpr uint32_t balance_default_interval_ms = 10;
        constexpr uint32_t balance_min_target = 1;

        uint64_t monotonic_ns() noexcept {
            return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                             fast_task::clock::now().time_since_epoch()
            )
                                             .count());
        }

        template <class F>
        bool attempt(F&& f) noexcept {
            try {
                f();
                return true;
            } catch (...) {
                return false;
            }
        }

        bool window_due(const pool_balance_state& window, uint64_t now) noexcept {
            const uint64_t armed = window.next_ns.load(std::memory_order_relaxed);
            return armed != 0 && now >= armed;
        }

        void restart_window(pool_balance_state& window, uint64_t now, uint64_t completions) noexcept {
            window.last_ns = now;
            window.last_completions = completions;
            window.next_ns.store(now + balance_prime_ns, std::memory_order_relaxed);
        }

        void schedule_next(pool_balance_state& window, uint64_t now, uint32_t next_ms) noexcept {
            if (next_ms == 0)
                next_ms = balance_default_interval_ms;
            window.next_ns.store(now + static_cast<uint64_t>(next_ms) * 1'000'000ull, std::memory_order_relaxed);
            window.samples.fetch_add(1, std::memory_order_relaxed);
        }

        void apply_target(worker_pool_storage& pool, uint32_t current, uint32_t wanted) noexcept {
            attempt([&] {
                if (wanted > current)
                    spawn_pool_worker(pool, static_cast<uint16_t>(wanted - current));
                else if (wanted < current)
                    shrink_pool_workers(pool, static_cast<uint16_t>(current - wanted));
            });
        }

        struct worker_limits {
            uint32_t min;
            uint32_t max;
            uint32_t target;
        };

        worker_limits limits_of(const worker_pool_storage& pool) noexcept {
            uint32_t min_workers = pool.threads.min_limit();
            uint32_t max_workers = pool.threads.max_limit();
            if (min_workers < balance_min_target)
                min_workers = balance_min_target;
            if (max_workers < min_workers)
                max_workers = min_workers;
            return {min_workers, max_workers, pool.threads.target()};
        }
    }

    void pool_balancer<scheduler::worker_balancer::hill_climb>::arm(worker_pool_storage&) noexcept {
        fast_task::lock_guard guard(window.lock);
        window.last_ns = 0;
        window.last_completions = 0;
        window.next_ns.store(1, std::memory_order_release);
    }

    uint64_t pool_balancer<scheduler::worker_balancer::hill_climb>::samples() const noexcept {
        return window.samples.load(std::memory_order_relaxed);
    }

    void pool_balancer<scheduler::worker_balancer::hill_climb>::run(worker_pool_storage& pool) noexcept {
        if (window.next_ns.load(std::memory_order_relaxed) == 0)
            return;
        const uint64_t now = monotonic_ns();
        if (!window_due(window, now))
            return;

        fast_task::unique_lock<fast_task::native::spin_lock> guard(window.lock, fast_task::defer_lock);
        if (!guard.try_lock())
            return;
        if (!window_due(window, now))
            return;
        if (pool.runtime.paused.load(std::memory_order_relaxed)) {
            window.last_ns = 0;
            return;
        }

        const uint64_t completions = pool.runtime.completed_tasks.load(std::memory_order_relaxed);
        if (window.last_ns == 0 || now - window.last_ns > balance_max_window_ns) {
            restart_window(window, now, completions);
            return;
        }

        const worker_limits limits = limits_of(pool);
        const double seconds = static_cast<double>(now - window.last_ns) / 1e9;
        const uint32_t completions_delta = static_cast<uint32_t>(completions - window.last_completions);

        uint32_t wanted = limits.target;
        uint32_t next_ms = balance_default_interval_ms;
        attempt([&] {
            const auto next = climber.climb(limits.target, seconds, completions_delta, limits.min, limits.max);
            wanted = next.first;
            next_ms = next.second;
        });
        apply_target(pool, limits.target, wanted);

        window.last_ns = now;
        window.last_completions = completions;
        schedule_next(window, now, next_ms);
    }
}
