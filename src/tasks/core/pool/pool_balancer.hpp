// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_CORE_POOL_BALANCER
#define FAST_TASK_CORE_POOL_BALANCER

#include <atomic>
#include <cstdint>

#include <fast_task/native/spin_lock.hpp>
#include <fast_task/shared.hpp>
#include <fast_task/task/scheduler.hpp>
#include <tasks/util/hill_climbing.hpp>

namespace fast_task {
    struct worker_pool_storage;

    struct FT_API_LOCAL pool_balance_state {
        std::atomic<uint64_t> next_ns{0};
        std::atomic<uint64_t> samples{0};
        fast_task::native::spin_lock lock;
        uint64_t last_ns = 0;
        uint64_t last_completions = 0;
    };

    template <scheduler::worker_balancer B>
    struct FT_API_LOCAL pool_balancer {
        void arm(worker_pool_storage&) noexcept {}

        void run(worker_pool_storage&) noexcept {}

        uint64_t samples() const noexcept {
            return 0;
        }
    };

    template <>
    struct alignas(64) FT_API_LOCAL pool_balancer<scheduler::worker_balancer::hill_climb> {
        void arm(worker_pool_storage& pool) noexcept;
        void run(worker_pool_storage& pool) noexcept;

        uint64_t samples() const noexcept;

    private:
        pool_balance_state window;
        util::hill_climb climber;
    };
}

#endif /* FAST_TASK_CORE_POOL_BALANCER */
