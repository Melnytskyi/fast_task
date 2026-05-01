// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>
#include <atomic>

// Each test manages its own scheduler lifecycle to test the APIs directly.

TEST(SchedulerLifecycle, CreateAndShutDown) {
    fast_task::scheduler::create_executor(1);
    while (fast_task::scheduler::total_executors() < 1u)
        std::this_thread::yield();
    fast_task::scheduler::shut_down();
}

TEST(SchedulerLifecycle, TotalExecutors) {
    fast_task::scheduler::create_executor(2);
    while (fast_task::scheduler::total_executors() < 2u)
        std::this_thread::yield();
    EXPECT_GE(fast_task::scheduler::total_executors(), 2u);
    fast_task::scheduler::shut_down();
}

TEST(SchedulerLifecycle, ReduceExecutor) {
    fast_task::scheduler::create_executor(3);
    while (fast_task::scheduler::total_executors() < 3u)
        std::this_thread::yield();
    size_t before = fast_task::scheduler::total_executors();
    fast_task::scheduler::reduce_executor(1);
    // Wait for the executor count to decrease
    while (fast_task::scheduler::total_executors() >= before)
        std::this_thread::yield();
    size_t after = fast_task::scheduler::total_executors();
    EXPECT_LT(after, before);
    fast_task::scheduler::shut_down();
}

TEST(SchedulerLifecycle, AwaitNoTasks) {
    fast_task::scheduler::create_executor(2);
    while (fast_task::scheduler::total_executors() < 2u)
        std::this_thread::yield();
    std::atomic<int> done{0};

    auto t1 = std::make_shared<fast_task::task>([&] {
        fast_task::this_task::sleep_for(std::chrono::milliseconds(10));
        ++done;
    });
    auto t2 = std::make_shared<fast_task::task>([&] {
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
    fast_task::scheduler::create_executor(2);
    while (fast_task::scheduler::total_executors() < 2u)
        std::this_thread::yield();
    std::atomic<int> done{0};

    auto t = std::make_shared<fast_task::task>([&] {
        fast_task::this_task::sleep_for(std::chrono::milliseconds(10));
        ++done;
    });
    fast_task::scheduler::start(t);
    fast_task::scheduler::await_end_tasks();

    EXPECT_EQ(done.load(), 1);
    fast_task::scheduler::shut_down();
}

TEST(SchedulerLifecycle, Schedule) {
    fast_task::scheduler::create_executor(2);
    while (fast_task::scheduler::total_executors() < 2u)
        std::this_thread::yield();
    fast_task::scheduler::explicit_start_timer();
    std::atomic<bool> ran{false};

    auto t = std::make_shared<fast_task::task>([&] { ran = true; });
    fast_task::scheduler::schedule(t, std::chrono::milliseconds(30));

    fast_task::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_TRUE(ran.load());
    fast_task::scheduler::shut_down();
}
