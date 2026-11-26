// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_CORE_THREADS_MANAGER
#define FAST_TASK_CORE_THREADS_MANAGER

#include <atomic>
#include <cstddef>
#include <cstdint>

#include <fast_task/shared.hpp>

namespace fast_task {
    enum class park_result : uint8_t {
        parked,
        no_surplus,
        retry,
    };

    struct pool_worker_counts {
        uint16_t target = 0;
        uint16_t active = 0;
        uint16_t foreign = 0;
        uint16_t dormant = 0;
        uint16_t borrowed_in = 0;
        uint16_t borrowed_out = 0;
        uint16_t pending_leases = 0;
        uint16_t live = 0;
    };

    class FT_API_LOCAL threads_manager {
        std::atomic<uint16_t> target_workers{0};
        std::atomic<uint16_t> active_workers{0};
        std::atomic<uint16_t> foreign_workers{0};
        std::atomic<uint16_t> dormant_workers{0};
        std::atomic<uint16_t> borrowed_in_count{0};
        std::atomic<uint16_t> borrowed_out_count{0};
        std::atomic<uint16_t> pending_leases_count{0};
        std::atomic<uint16_t> live_threads{0};
        std::atomic<uint16_t> min_workers{1};
        std::atomic<uint16_t> max_workers{UINT16_MAX};

        static std::atomic<size_t> total_active_;

    public:
        void attach(bool spawned, bool count_live) noexcept {
            if (spawned) {
                active_workers.fetch_add(1, std::memory_order_acq_rel);
                total_active_.fetch_add(1, std::memory_order_acq_rel);
            } else
                foreign_workers.fetch_add(1, std::memory_order_acq_rel);
            if (count_live)
                live_threads.fetch_add(1, std::memory_order_acq_rel);
        }

        void detach(bool spawned, bool count_live, bool count_active) noexcept {
            if (count_live)
                live_threads.fetch_sub(1, std::memory_order_acq_rel);
            if (spawned) {
                if (count_active) {
                    active_workers.fetch_sub(1, std::memory_order_acq_rel);
                    total_active_.fetch_sub(1, std::memory_order_acq_rel);
                }
            } else
                foreign_workers.fetch_sub(1, std::memory_order_acq_rel);
        }

        void detach_live() noexcept {
            live_threads.fetch_sub(1, std::memory_order_acq_rel);
        }

        park_result park() noexcept {
            dormant_workers.fetch_add(1, std::memory_order_acq_rel);
            uint16_t active = active_workers.load(std::memory_order_acquire);
            const uint16_t goal = target_workers.load(std::memory_order_acquire);
            if (active <= goal) {
                unpark();
                return park_result::no_surplus;
            }
            if (!active_workers.compare_exchange_weak(active, static_cast<uint16_t>(active - 1), std::memory_order_acq_rel)) {
                unpark();
                return park_result::retry;
            }
            total_active_.fetch_sub(1, std::memory_order_acq_rel);
            return park_result::parked;
        }

        void unpark() noexcept {
            dormant_workers.fetch_sub(1, std::memory_order_acq_rel);
        }

        void lend() noexcept {
            borrowed_out_count.fetch_add(1, std::memory_order_acq_rel);
            pending_leases_count.fetch_add(1, std::memory_order_acq_rel);
        }

        void accept_lease() noexcept {
            borrowed_in_count.fetch_add(1, std::memory_order_acq_rel);
        }

        void take_pending() noexcept {
            pending_leases_count.fetch_sub(1, std::memory_order_acq_rel);
        }

        void return_lease_to(threads_manager& lender) noexcept {
            borrowed_in_count.fetch_sub(1, std::memory_order_acq_rel);
            lender.borrowed_out_count.fetch_sub(1, std::memory_order_acq_rel);
        }

        void drop_lease_of(threads_manager& borrower) noexcept {
            pending_leases_count.fetch_sub(1, std::memory_order_acq_rel);
            borrowed_out_count.fetch_sub(1, std::memory_order_acq_rel);
            borrower.borrowed_in_count.fetch_sub(1, std::memory_order_acq_rel);
        }

        uint16_t target() const noexcept {
            return target_workers.load(std::memory_order_acquire);
        }

        uint16_t active() const noexcept {
            return active_workers.load(std::memory_order_acquire);
        }

        uint16_t foreign() const noexcept {
            return foreign_workers.load(std::memory_order_acquire);
        }

        uint16_t dormant() const noexcept {
            return dormant_workers.load(std::memory_order_acquire);
        }

        uint16_t borrowed_in() const noexcept {
            return borrowed_in_count.load(std::memory_order_acquire);
        }

        uint16_t borrowed_out() const noexcept {
            return borrowed_out_count.load(std::memory_order_acquire);
        }

        uint16_t pending_leases() const noexcept {
            return pending_leases_count.load(std::memory_order_acquire);
        }

        uint16_t live() const noexcept {
            return live_threads.load(std::memory_order_acquire);
        }

        uint16_t min_limit() const noexcept {
            return min_workers.load(std::memory_order_acquire);
        }

        uint16_t max_limit() const noexcept {
            return max_workers.load(std::memory_order_acquire);
        }

        bool surplus() const noexcept {
            return active_workers.load(std::memory_order_relaxed) >
                   static_cast<uint32_t>(target_workers.load(std::memory_order_relaxed));
        }

        bool wants_worker() const noexcept {
            return active_workers.load(std::memory_order_relaxed) <
                   target_workers.load(std::memory_order_relaxed);
        }

        void set_target(uint16_t target) noexcept {
            target_workers.store(target, std::memory_order_release);
        }

        void set_limits(uint16_t min, uint16_t max) noexcept {
            min_workers.store(min, std::memory_order_release);
            max_workers.store(max < min ? min : max, std::memory_order_release);
        }

        void set_min(uint16_t min) noexcept {
            max_workers.store(min > max_workers.load(std::memory_order_acquire) ? min : max_workers.load(std::memory_order_acquire), std::memory_order_release);
            min_workers.store(min, std::memory_order_release);
        }

        void set_max(uint16_t max) noexcept {
            min_workers.store(min_workers.load(std::memory_order_acquire) > max ? max : min_workers.load(std::memory_order_acquire), std::memory_order_release);
            max_workers.store(max, std::memory_order_release);
        }

        uint16_t claim_target(uint16_t count) noexcept {
            uint16_t goal = target_workers.load(std::memory_order_acquire);
            const uint16_t cap = max_workers.load(std::memory_order_acquire);
            if (goal >= cap)
                return 0;
            for (;;) {
                const uint16_t room = static_cast<uint16_t>(cap - goal);
                const uint16_t grow = count < room ? count : room;
                if (target_workers.compare_exchange_weak(goal, static_cast<uint16_t>(goal + grow), std::memory_order_acq_rel))
                    return grow;
                if (goal >= cap)
                    return 0;
            }
        }

        void release_target(uint16_t count) noexcept {
            target_workers.fetch_sub(count, std::memory_order_acq_rel);
        }

        uint16_t release_target_clamped(uint16_t count, uint16_t min) noexcept {
            if (count == 0)
                return 0;
            uint16_t goal = target_workers.load(std::memory_order_acquire);
            for (;;) {
                if (goal <= min)
                    return 0;
                const uint16_t avail = static_cast<uint16_t>(goal - min);
                const uint16_t shrink = count < avail ? count : avail;
                if (target_workers.compare_exchange_weak(
                        goal, static_cast<uint16_t>(goal - shrink), std::memory_order_acq_rel, std::memory_order_acquire
                    ))
                    return shrink;
            }
        }

        pool_worker_counts snapshot() const noexcept {
            return pool_worker_counts{target(), active(), foreign(), dormant(), borrowed_in(), borrowed_out(), pending_leases(), live()};
        }

        static void count_thread_launch() noexcept;
        static void count_thread_exit() noexcept;

        static size_t thread_count() noexcept {
            return thread_count_.load(std::memory_order_acquire);
        }

        static size_t total_active() noexcept {
            return total_active_.load(std::memory_order_acquire);
        }

        static std::atomic<size_t> thread_count_;
    };
}

#endif /* FAST_TASK_CORE_THREADS_MANAGER */
