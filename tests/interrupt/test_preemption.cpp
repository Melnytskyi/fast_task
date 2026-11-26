// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <fast_task/interrupt.hpp>
#include <helpers.hpp>
#include <thread>
#include <vector>

namespace {
    fast_task::scheduler::worker_pool_options single_worker_options(uint16_t workers = 1) {
        fast_task::scheduler::worker_pool_options o;
        o.initial_workers = workers;
        o.start_with_worker_per_core = false;
        o.min_workers = workers;
        o.max_workers = workers;
        return o;
    }

    bool wait_workers(fast_task::scheduler::worker_pool& pool, uint16_t n) {
        const auto deadline = fast_task::clock::now() + std::chrono::seconds(5);
        while (pool.stats().active_workers < n && fast_task::clock::now() < deadline)
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        return pool.stats().active_workers >= n;
    }

    struct compute_result {
        uint64_t int_acc;
        double fp_acc;
    };

    compute_result run_compute_workload(uint64_t seed, uint64_t iterations) {
        uint64_t a = seed ^ 0x9e3779b97f4a7c15ULL;
        uint64_t b = (seed + 1) * 0xbf58476d1ce4e5b9ULL;
        double v0 = 1.0 + static_cast<double>(seed) * 0.125;
        double v1 = 2.0 + static_cast<double>(seed) * 0.25;
        double v2 = 3.0 + static_cast<double>(seed) * 0.5;
        double v3 = 4.0 + static_cast<double>(seed) * 0.75;

        for (uint64_t i = 0; i < iterations; ++i) {
            a = (a * 6364136223846793005ULL) + 1442695040888963407ULL;
            b ^= (a >> 17) ^ (b << 13);
            v0 = v0 * 1.0000001 + 0.0000003;
            v1 = v1 * 0.9999999 + 0.0000007;
            v2 = v2 + (v0 - v1) * 0.000001;
            v3 = v3 - (v2 * 0.0000005) + 0.0000002;
        }
        return {a ^ b, v0 + v1 + v2 + v3};
    }
}

TEST(PreemptionTest, CpuBoundTaskIsPreemptedOnSingleWorker) {
    if (!fast_task::scheduler::preemption_enabled())
        GTEST_SKIP() << "Built without FAST_TASK_ENABLE_PREEMPTIVE_SCHEDULER";

    auto pool = fast_task::scheduler::worker_pool::create(single_worker_options(1));
    ASSERT_TRUE(wait_workers(pool, 1));

    std::atomic<bool> spinner_started{false};
    std::atomic<bool> other_ran{false};

    auto spinner = fast_task::task::create(
        [&] {
            spinner_started.store(true, std::memory_order_release);
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
            volatile uint64_t sink = 0;
            while (!other_ran.load(std::memory_order_acquire) &&
                   std::chrono::steady_clock::now() < deadline) {
                for (int i = 0; i < 4096; ++i)
                    sink = sink + static_cast<uint64_t>(i);
            }
        },
        nullptr,
        fast_task::time_point::min(),
        fast_task::task_priority::background
    );

    auto other = fast_task::task::create(
        [&] {
            other_ran.store(true, std::memory_order_release);
        },
        nullptr,
        fast_task::time_point::min(),
        fast_task::task_priority::high
    );

    pool.post(spinner);
    const auto start_wait = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (!spinner_started.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < start_wait)
        std::this_thread::yield();
    ASSERT_TRUE(spinner_started.load(std::memory_order_acquire));

    pool.post(other);

    spinner.await_task();
    other.await_task();

    EXPECT_TRUE(other_ran.load(std::memory_order_acquire))
        << "Non-yielding CPU-bound task must be preempted so queued task can run";
    EXPECT_GE(spinner.get_counter_interrupt(), 1u);

    fast_task::scheduler::shut_down();
}

TEST(PreemptionTest, InterruptUnsafeRegionDefersPreemption) {
    if (!fast_task::scheduler::preemption_enabled())
        GTEST_SKIP() << "Built without FAST_TASK_ENABLE_PREEMPTIVE_SCHEDULER";

    auto pool = fast_task::scheduler::worker_pool::create(single_worker_options(1));
    ASSERT_TRUE(wait_workers(pool, 1));

    std::atomic<bool> entered_region{false};
    std::atomic<bool> other_queued{false};
    std::atomic<bool> other_ran{false};
    std::atomic<bool> ran_inside_region{false};

    auto spinner = fast_task::task::create(
        [&] {
            {
                fast_task::interrupt_unsafe_region guard;
                entered_region.store(true, std::memory_order_release);
                const auto wait_q = std::chrono::steady_clock::now() + std::chrono::seconds(5);
                while (!other_queued.load(std::memory_order_acquire) &&
                       std::chrono::steady_clock::now() < wait_q) {
                }
                const auto spin_end = std::chrono::steady_clock::now() + std::chrono::milliseconds(60);
                volatile uint64_t sink = 0;
                while (std::chrono::steady_clock::now() < spin_end)
                    sink = sink + 1;
                ran_inside_region.store(other_ran.load(std::memory_order_acquire), std::memory_order_release);
            }

            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
            volatile uint64_t sink = 0;
            while (!other_ran.load(std::memory_order_acquire) &&
                   std::chrono::steady_clock::now() < deadline) {
                for (int i = 0; i < 4096; ++i)
                    sink = sink + static_cast<uint64_t>(i);
            }
        },
        nullptr,
        fast_task::time_point::min(),
        fast_task::task_priority::background
    );

    auto other = fast_task::task::create(
        [&] {
            other_ran.store(true, std::memory_order_release);
        },
        nullptr,
        fast_task::time_point::min(),
        fast_task::task_priority::high
    );

    pool.post(spinner);
    const auto wait_enter = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (!entered_region.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < wait_enter)
        std::this_thread::yield();
    ASSERT_TRUE(entered_region.load(std::memory_order_acquire));

    pool.post(other);
    other_queued.store(true, std::memory_order_release);

    spinner.await_task();
    other.await_task();

    EXPECT_FALSE(ran_inside_region.load(std::memory_order_acquire))
        << "Preemption must not fire while inside interrupt_unsafe_region";
    EXPECT_TRUE(other_ran.load(std::memory_order_acquire))
        << "Deferred preemption must fire after leaving interrupt_unsafe_region";
    EXPECT_GE(spinner.get_counter_interrupt(), 1u);

    fast_task::scheduler::shut_down();
}

TEST(PreemptionTest, SemiRealtimeTaskIsNotPreempted) {
    if (!fast_task::scheduler::preemption_enabled())
        GTEST_SKIP() << "Built without FAST_TASK_ENABLE_PREEMPTIVE_SCHEDULER";

    auto pool = fast_task::scheduler::worker_pool::create(single_worker_options(1));
    ASSERT_TRUE(wait_workers(pool, 1));

    std::atomic<bool> rt_started{false};
    std::atomic<bool> other_queued{false};
    std::atomic<bool> other_ran{false};
    std::atomic<bool> ran_during_rt{false};

    auto rt_task = fast_task::task::create(
        [&] {
            rt_started.store(true, std::memory_order_release);
            const auto wait_q = std::chrono::steady_clock::now() + std::chrono::seconds(5);
            while (!other_queued.load(std::memory_order_acquire) &&
                   std::chrono::steady_clock::now() < wait_q) {
            }
            const auto spin_end = std::chrono::steady_clock::now() + std::chrono::milliseconds(80);
            volatile uint64_t sink = 0;
            while (std::chrono::steady_clock::now() < spin_end)
                sink = sink + 1;
            ran_during_rt.store(other_ran.load(std::memory_order_acquire), std::memory_order_release);
        },
        nullptr,
        fast_task::time_point::min(),
        fast_task::task_priority::semi_realtime
    );

    auto other = fast_task::task::create(
        [&] {
            other_ran.store(true, std::memory_order_release);
        },
        nullptr,
        fast_task::time_point::min(),
        fast_task::task_priority::high
    );

    pool.post(rt_task);
    const auto wait_start = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (!rt_started.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < wait_start)
        std::this_thread::yield();
    ASSERT_TRUE(rt_started.load(std::memory_order_acquire));

    pool.post(other);
    other_queued.store(true, std::memory_order_release);

    rt_task.await_task();
    other.await_task();

    EXPECT_FALSE(ran_during_rt.load(std::memory_order_acquire))
        << "semi_realtime task must not be preempted";
    EXPECT_TRUE(other_ran.load(std::memory_order_acquire));
    EXPECT_EQ(rt_task.get_counter_interrupt(), 0u);

    fast_task::scheduler::shut_down();
}

TEST(PreemptionTest, CooperativeOnlyPolicyDisablesPreemption) {
    if (!fast_task::scheduler::preemption_enabled())
        GTEST_SKIP() << "Built without FAST_TASK_ENABLE_PREEMPTIVE_SCHEDULER";

    auto pool = fast_task::scheduler::worker_pool::create(single_worker_options(0));

    std::atomic<bool> other_ran{false};
    std::atomic<bool> ran_during_spin{false};

    auto first = fast_task::task::create(
        [&] {
            const auto spin_end = std::chrono::steady_clock::now() + std::chrono::milliseconds(60);
            volatile uint64_t sink = 0;
            while (std::chrono::steady_clock::now() < spin_end)
                sink = sink + 1;
            ran_during_spin.store(other_ran.load(std::memory_order_acquire), std::memory_order_release);
        },
        nullptr,
        fast_task::time_point::min(),
        fast_task::task_priority::background
    );

    auto other = fast_task::task::create(
        [&] {
            other_ran.store(true, std::memory_order_release);
        },
        nullptr,
        fast_task::time_point::min(),
        fast_task::task_priority::high
    );

    pool.post(first);
    pool.post(other);

    fast_task::scheduler::worker_context_options ctx_opts;
    ctx_opts.policy = fast_task::scheduler::preemption_policy::cooperative_only;
    fast_task::scheduler::worker_context ctx(ctx_opts);
    pool.join_pool(ctx);
    ctx.poll_drained();
    pool.leave_pool(ctx);

    EXPECT_FALSE(ran_during_spin.load(std::memory_order_acquire));
    EXPECT_TRUE(other_ran.load(std::memory_order_acquire));
    EXPECT_EQ(first.get_counter_interrupt(), 0u);

    fast_task::scheduler::shut_down();
}

TEST(PreemptionTest, RegistersAndSimdPreservedAcrossPreemptionAndMigration) {
    if (!fast_task::scheduler::preemption_enabled())
        GTEST_SKIP() << "Built without FAST_TASK_ENABLE_PREEMPTIVE_SCHEDULER";

    auto pool = fast_task::scheduler::worker_pool::create(single_worker_options(2));
    ASSERT_TRUE(wait_workers(pool, 2));

    constexpr size_t task_count = 6;
    constexpr uint64_t iterations = 25'000'000;

    std::vector<compute_result> expected(task_count);
    for (size_t i = 0; i < task_count; ++i)
        expected[i] = run_compute_workload(i + 1, iterations);

    std::vector<compute_result> actual(task_count);
    std::vector<fast_task::task> tasks;
    tasks.reserve(task_count);

    for (size_t i = 0; i < task_count; ++i) {
        auto t = fast_task::task::create(
            [&actual, i] {
                actual[i] = run_compute_workload(i + 1, iterations);
            },
            nullptr,
            fast_task::time_point::min(),
            fast_task::task_priority::background
        );
        pool.post(t);
        tasks.push_back(std::move(t));
    }

    size_t total_interrupts = 0;
    for (size_t i = 0; i < task_count; ++i) {
        tasks[i].await_task();
        total_interrupts += tasks[i].get_counter_interrupt();
        EXPECT_EQ(actual[i].int_acc, expected[i].int_acc) << "Integer state corrupted in task " << i;
        EXPECT_DOUBLE_EQ(actual[i].fp_acc, expected[i].fp_acc) << "FP/SIMD state corrupted in task " << i;
    }

    EXPECT_GE(total_interrupts, 1u)
        << "Expected at least one preemption across 6 background compute tasks on 2 workers";

    fast_task::scheduler::shut_down();
}
