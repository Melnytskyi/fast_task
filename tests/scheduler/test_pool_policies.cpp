// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <atomic>
#include <helpers.hpp>

namespace {
    fast_task::scheduler::worker_pool_options policy_options(uint16_t workers) {
        fast_task::scheduler::worker_pool_options o;
        o.initial_workers = workers;
        o.start_with_worker_per_core = false;
        o.min_workers = 0;
        return o;
    }

    void wait_workers(fast_task::scheduler::worker_pool& pool, uint16_t n) {
        const auto deadline = fast_task::clock::now() + std::chrono::seconds(5);
        while (pool.stats().active_workers < n && fast_task::clock::now() < deadline)
            std::this_thread::yield();
    }

    fast_task::task ordered_task(fast_task::task_priority priority,
                                 std::atomic<int>& slot,
                                 std::atomic<int>& seq) {
        auto t = fast_task::task::create([&slot, &seq] { slot.store(seq.fetch_add(1)); });
        t.set_priority(priority);
        return t;
    }
}

TEST(PoolPolicies, PriorityFifoRunsHighestClassFirst) {
    auto opts = policy_options(0);
    opts.queue = fast_task::scheduler::queue_policy::priority_fifo;
    auto pool = fast_task::scheduler::worker_pool::create(opts);

    fast_task::scheduler::worker_context ctx;
    pool.join_pool(ctx);

    std::atomic<int> seq{0};
    std::atomic<int> order_low{-1};
    std::atomic<int> order_high{-1};
    std::atomic<int> order_bg{-1};

    auto low = ordered_task(fast_task::task_priority::low, order_low, seq);
    auto high = ordered_task(fast_task::task_priority::high, order_high, seq);
    auto bg = ordered_task(fast_task::task_priority::background, order_bg, seq);
    pool.post(low);
    pool.post(high);
    pool.post(bg);

    for (int i = 0; i < 3; ++i)
        ctx.poll(1);

    EXPECT_EQ(order_high.load(), 0);
    EXPECT_EQ(order_low.load(), 1);
    EXPECT_EQ(order_bg.load(), 2);

    pool.leave_pool(ctx);
}

TEST(PoolPolicies, PriorityFifoIsFifoWithinAClass) {
    auto opts = policy_options(0);
    opts.queue = fast_task::scheduler::queue_policy::priority_fifo;
    auto pool = fast_task::scheduler::worker_pool::create(opts);

    fast_task::scheduler::worker_context ctx;
    pool.join_pool(ctx);

    std::atomic<int> seq{0};
    std::atomic<int> first{-1};
    std::atomic<int> second{-1};
    std::atomic<int> third{-1};

    auto a = ordered_task(fast_task::task_priority::normal, first, seq);
    auto b = ordered_task(fast_task::task_priority::normal, second, seq);
    auto c = ordered_task(fast_task::task_priority::normal, third, seq);
    pool.post(a);
    pool.post(b);
    pool.post(c);

    for (int i = 0; i < 3; ++i)
        ctx.poll(1);

    EXPECT_EQ(first.load(), 0);
    EXPECT_EQ(second.load(), 1);
    EXPECT_EQ(third.load(), 2);

    pool.leave_pool(ctx);
}

TEST(PoolPolicies, PriorityFifoYieldDoesNotStarveLowerClasses) {
    auto opts = policy_options(1);
    opts.queue = fast_task::scheduler::queue_policy::priority_fifo;
    auto pool = fast_task::scheduler::worker_pool::create(opts);
    wait_workers(pool, 1);
    ensure_global_workers(1);

    std::atomic<int> yields{0};
    std::atomic<bool> low_ran{false};

    auto yielder = fast_task::task::create([&] {
        for (int i = 0; i < 5; ++i) {
            yields.fetch_add(1);
            fast_task::this_task::yield();
        }
    });
    yielder.set_priority(fast_task::task_priority::semi_realtime);

    auto low = fast_task::task::create([&] { low_ran.store(true); });
    low.set_priority(fast_task::task_priority::background);

    pool.post(yielder);
    pool.post(low);

    yielder.await_task();
    low.await_task();

    EXPECT_EQ(yields.load(), 5);
    EXPECT_TRUE(low_ran.load());
    fast_task::scheduler::shut_down();
}

TEST(PoolPolicies, BusySpinRunsTasks) {
    auto opts = policy_options(1);
    opts.idle = fast_task::scheduler::idle_policy::busy_spin;
    auto pool = fast_task::scheduler::worker_pool::create(opts);
    wait_workers(pool, 1);

    EXPECT_EQ(pool.stats().idle, fast_task::scheduler::idle_policy::busy_spin);

    constexpr int N = 8;
    std::atomic<int> ran{0};
    for (int i = 0; i < N; ++i)
        pool.post(fast_task::task::create([&] { ran.fetch_add(1); }));

    const auto deadline = fast_task::clock::now() + std::chrono::seconds(5);
    while (ran.load() < N && fast_task::clock::now() < deadline)
        std::this_thread::yield();

    EXPECT_EQ(ran.load(), N);
    fast_task::scheduler::shut_down();
}

TEST(PoolPolicies, StatsReportTheSelectedPairing) {
    auto listo = policy_options(0);
    auto pool = fast_task::scheduler::worker_pool::create(listo);
    EXPECT_EQ(pool.stats().queue, fast_task::scheduler::queue_policy::work_stealing_lifo);
    EXPECT_EQ(pool.stats().idle, fast_task::scheduler::idle_policy::wait);

    auto popts = policy_options(0);
    popts.queue = fast_task::scheduler::queue_policy::priority_fifo;
    popts.idle = fast_task::scheduler::idle_policy::busy_spin;
    auto ppool = fast_task::scheduler::worker_pool::create(popts);
    EXPECT_EQ(ppool.stats().queue, fast_task::scheduler::queue_policy::priority_fifo);
    EXPECT_EQ(ppool.stats().idle, fast_task::scheduler::idle_policy::busy_spin);
}
