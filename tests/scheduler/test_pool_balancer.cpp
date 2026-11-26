// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)


#include <atomic>
#include <chrono>
#include <helpers.hpp>
#include <thread>

namespace {
    using fast_task::scheduler::worker_balancer;
    using fast_task::scheduler::worker_pool;
    using fast_task::scheduler::worker_pool_options;

    worker_pool_options balance_options(uint16_t initial, uint16_t min, uint16_t max) {
        worker_pool_options o;
        o.initial_workers = initial;
        o.start_with_worker_per_core = false;
        o.min_workers = min;
        o.max_workers = max;
        return o;
    }

    template <class Pred>
    bool eventually(Pred&& pred, std::chrono::milliseconds limit = std::chrono::seconds(5)) {
        const auto deadline = fast_task::clock::now() + limit;
        while (fast_task::clock::now() < deadline) {
            if (pred())
                return true;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        return pred();
    }

    void wait_workers(worker_pool& pool, uint16_t n) {
        ASSERT_TRUE(eventually([&pool, n] { return pool.stats().active_workers >= n; }))
            << "the pool did not reach " << n << " active workers";
    }
}

TEST(PoolBalancer, HillClimbKeepsTargetInLimits) {
    constexpr uint16_t min_workers = 1;
    constexpr uint16_t max_workers = 3;
    auto opts = balance_options(1, min_workers, max_workers);
    opts.balancer = worker_balancer::hill_climb;
    auto pool = worker_pool::create(opts);
    wait_workers(pool, 1);
    ASSERT_EQ(pool.stats().balancer, worker_balancer::hill_climb);

    std::atomic<bool> stop{false};
    std::atomic<uint64_t> ran{0};
    std::atomic<uint16_t> observed_min{max_workers};
    std::atomic<uint16_t> observed_max{0};

    std::thread load([&] {
        while (!stop.load(std::memory_order_relaxed)) {
            for (int i = 0; i < 32; ++i)
                pool.post(fast_task::task::create([&ran] { ran.fetch_add(1, std::memory_order_relaxed); }));
            const uint16_t target = pool.stats().target_workers;
            if (target < observed_min.load(std::memory_order_relaxed))
                observed_min.store(target, std::memory_order_relaxed);
            if (target > observed_max.load(std::memory_order_relaxed))
                observed_max.store(target, std::memory_order_relaxed);
            std::this_thread::sleep_for(std::chrono::microseconds(500));
        }
    });

    EXPECT_TRUE(eventually(
        [&] { return ran.load(std::memory_order_relaxed) >= 100u && pool.stats().balance_samples >= 1u; },
        std::chrono::seconds(3)
    ));
    stop.store(true, std::memory_order_relaxed);
    load.join();

    EXPECT_GE(ran.load(), 100u) << "the load never reached the pool";
    EXPECT_GE(pool.stats().completed_tasks, 100u) << "completions are not being counted";
    EXPECT_GE(pool.stats().balance_samples, 1u) << "the climber was never sampled";
    EXPECT_GE(observed_min.load(), min_workers);
    EXPECT_LE(observed_max.load(), max_workers);

    const auto st = pool.stats();
    EXPECT_GE(st.target_workers, min_workers);
    EXPECT_LE(st.target_workers, max_workers);
    EXPECT_GE(st.active_workers, 1u);

    EXPECT_TRUE(pool.wait_idle(fast_task::clock::now() + std::chrono::seconds(5)));
    EXPECT_EQ(pool.stats().executing_tasks, 0u);

    fast_task::scheduler::shut_down();
}

TEST(PoolBalancer, HillClimbDoesNotResizeAPausedPool) {
    auto opts = balance_options(1, 1, 4);
    opts.balancer = worker_balancer::hill_climb;
    auto pool = worker_pool::create(opts);
    wait_workers(pool, 1);

    pool.pause();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    const uint16_t frozen = pool.stats().target_workers;

    std::atomic<uint64_t> ran{0};
    for (int i = 0; i < 8; ++i)
        pool.post(fast_task::task::create([&ran] { ran.fetch_add(1, std::memory_order_relaxed); }));

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_EQ(pool.stats().target_workers, frozen);
    EXPECT_EQ(ran.load(), 0u);
    EXPECT_NE(pool.stats().queued_tasks_approx, 0u);

    pool.resume();
    EXPECT_TRUE(eventually([&ran] { return ran.load() == 8; }));
    fast_task::scheduler::shut_down();
}

TEST(PoolBalancer, BalancerNoneLeavesTargetAlone) {
    auto pool = worker_pool::create(balance_options(1, 1, 4));
    wait_workers(pool, 1);

    std::atomic<bool> stop{false};
    std::atomic<uint64_t> ran{0};
    std::thread load([&] {
        while (!stop.load(std::memory_order_relaxed)) {
            pool.post(fast_task::task::create([&ran] { ran.fetch_add(1, std::memory_order_relaxed); }));
            std::this_thread::sleep_for(std::chrono::microseconds(200));
        }
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    stop.store(true, std::memory_order_relaxed);
    load.join();

    const auto st = pool.stats();
    EXPECT_EQ(st.balancer, worker_balancer::none);
    EXPECT_EQ(st.balance_samples, 0u);
    EXPECT_EQ(st.target_workers, 1u);
    EXPECT_EQ(st.max_workers, 4u);

    EXPECT_TRUE(pool.wait_idle(fast_task::clock::now() + std::chrono::seconds(5)));
    fast_task::scheduler::shut_down();
}

TEST(PoolBalancer, CrossPoolTransferToRefuses) {
    auto a = worker_pool::create(balance_options(1, 0, 1));
    auto b = worker_pool::create(balance_options(1, 0, 1));
    wait_workers(a, 1);
    wait_workers(b, 1);

    auto target = fast_task::task::create(
        [] {},
        nullptr,
        fast_task::time_point::min(),
        fast_task::task_priority::high,
        true);
    b.bind(target);
    EXPECT_EQ(b.stats().executing_tasks, 0u);

    std::atomic<bool> accepted{true};
    auto runner = fast_task::task::create(
        [&accepted, &target] { accepted.store(fast_task::this_task::transfer_to(target), std::memory_order_relaxed); },
        nullptr,
        fast_task::time_point::min(),
        fast_task::task_priority::high,
        true);
    a.post(runner);
    runner.await_task();

    EXPECT_FALSE(accepted.load(std::memory_order_relaxed));
    EXPECT_TRUE(eventually([&a] { return a.stats().executing_tasks == 0; }));
    EXPECT_EQ(b.stats().executing_tasks, 0u);

    target.start();
    target.await_task();
    EXPECT_TRUE(eventually([&b] { return b.stats().completed_tasks == 1; }));

    fast_task::scheduler::shut_down();
}

TEST(PoolBalancer, TransferKeepsAccountingBalanced) {
    auto a = worker_pool::create(balance_options(1, 0, 1));
    auto b = worker_pool::create(balance_options(1, 0, 1));
    wait_workers(a, 1);
    wait_workers(b, 1);

    std::atomic<bool> release{false};
    std::atomic<bool> started{false};
    auto gated = fast_task::task::create([&release, &started] {
        started.store(true, std::memory_order_relaxed);
        while (!release.load(std::memory_order_relaxed))
            fast_task::this_task::yield();
    });
    a.bind(gated);
    EXPECT_EQ(a.stats().executing_tasks, 0u);
    a.post(gated);
    EXPECT_EQ(a.stats().executing_tasks, 1u);
    EXPECT_TRUE(eventually([&started] { return started.load(); }));
    EXPECT_TRUE(eventually([&a] { return a.stats().in_run_tasks == 1; }));

    release.store(true, std::memory_order_relaxed);
    EXPECT_TRUE(eventually([&a] { return a.stats().executing_tasks == 0; }));
    EXPECT_TRUE(eventually([&a] { return a.stats().completed_tasks == 1; }));
    gated.await_task();

    std::atomic<fast_task::scheduler::worker_pool*> where{nullptr};
    auto mover = fast_task::task::create([&where, &b] {
        fast_task::this_task::set_pool(b);
        fast_task::this_task::yield();
        where.store(&fast_task::this_task::current_pool(), std::memory_order_relaxed);
    });
    a.post(mover);
    mover.await_task();

    EXPECT_EQ(where.load(), &b);
    EXPECT_EQ(a.stats().executing_tasks, 0u);
    EXPECT_TRUE(eventually([&b] { return b.stats().executing_tasks == 0; }));
    EXPECT_TRUE(eventually([&b] { return b.stats().completed_tasks == 1; }));

    fast_task::scheduler::shut_down();
}
