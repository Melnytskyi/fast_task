// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>
#include <atomic>

TEST(SchedulerLifecycle, CreateAndShutDown) {
    ensure_global_workers(1);
    fast_task::scheduler::shut_down();
}

TEST(SchedulerLifecycle, TotalExecutors) {
    ensure_global_workers(2);
    EXPECT_GE(fast_task::scheduler::worker_pool::global().stats().active_workers, 2u);
    fast_task::scheduler::shut_down();
}

TEST(SchedulerLifecycle, ReduceExecutor) {
    ensure_global_workers(3);
    auto& pool = fast_task::scheduler::worker_pool::global();
    const uint16_t before = pool.stats().active_workers;

    pool.remove_workers(1);
    const auto deadline = fast_task::clock::now() + std::chrono::seconds(5);
    while (pool.stats().active_workers >= before && fast_task::clock::now() < deadline)
        std::this_thread::yield();
    EXPECT_LT(pool.stats().active_workers, before);
    fast_task::scheduler::shut_down();
}

TEST(SchedulerLifecycle, AwaitNoTasks) {
    ensure_global_workers(2);
    std::atomic<int> done{0};

    auto t1 = fast_task::task::create([&] {
        fast_task::this_task::sleep_for(std::chrono::milliseconds(10));
        ++done;
    });
    auto t2 = fast_task::task::create([&] {
        fast_task::this_task::sleep_for(std::chrono::milliseconds(10));
        ++done;
    });
    fast_task::scheduler::start(t1);
    fast_task::scheduler::start(t2);
    fast_task::scheduler::await_no_tasks();

    EXPECT_EQ(done.load(), 2);
    fast_task::scheduler::shut_down();
}

TEST(SchedulerLifecycle, AwaitEndTasks) {
    ensure_global_workers(2);
    std::atomic<int> done{0};

    auto t = fast_task::task::create([&] {
        fast_task::this_task::sleep_for(std::chrono::milliseconds(10));
        ++done;
    });
    fast_task::scheduler::start(t);
    fast_task::scheduler::await_end_tasks();

    EXPECT_EQ(done.load(), 1);
    fast_task::scheduler::shut_down();
}

TEST(SchedulerLifecycle, Schedule) {
    ensure_global_workers(2);
    fast_task::scheduler::explicit_start_timer();
    std::atomic<bool> ran{false};

    auto t = fast_task::task::create([&] { ran = true; });
    fast_task::scheduler::schedule(t, std::chrono::milliseconds(30));

    fast_task::native::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_TRUE(ran.load());
    fast_task::scheduler::shut_down();
}
