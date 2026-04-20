// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>
#include <atomic>

class StackfullSleepTest : public SchedulerFixture {};

TEST_F(StackfullSleepTest, SleepFor) {
    auto start = std::chrono::high_resolution_clock::now();
    run_task([&] {
        fast_task::this_task::sleep_for(std::chrono::milliseconds(50));
    });
    auto elapsed = std::chrono::high_resolution_clock::now() - start;
    EXPECT_GE(elapsed, std::chrono::milliseconds(40));
}

TEST_F(StackfullSleepTest, SleepUntil) {
    auto tp = std::chrono::high_resolution_clock::now() + std::chrono::milliseconds(50);
    auto start = std::chrono::high_resolution_clock::now();
    run_task([&] {
        fast_task::this_task::sleep_until(tp);
    });
    auto elapsed = std::chrono::high_resolution_clock::now() - start;
    EXPECT_GE(elapsed, std::chrono::milliseconds(40));
}

TEST_F(StackfullSleepTest, Yield) {
    // yield suspends and resumes, counter increases
    std::shared_ptr<fast_task::task> t_ref;
    auto t = std::make_shared<fast_task::task>([&] {
        fast_task::this_task::yield();
        fast_task::this_task::yield();
    });
    t_ref = t;
    fast_task::scheduler::start(t);
    t->await_task();
    EXPECT_GE(t_ref->get_counter_context_switch(), 2u);
}

TEST_F(StackfullSleepTest, SleepForZeroReturnsQuickly) {
    auto start = std::chrono::high_resolution_clock::now();
    run_task([&] {
        fast_task::this_task::sleep_for(std::chrono::milliseconds(0));
    });
    auto elapsed = std::chrono::high_resolution_clock::now() - start;
    EXPECT_LT(elapsed, std::chrono::milliseconds(100));
}

TEST_F(StackfullSleepTest, MultipleSleepsFairOrder) {
    std::atomic<int> counter{0};
    auto t1 = std::make_shared<fast_task::task>([&] {
        fast_task::this_task::sleep_for(std::chrono::milliseconds(20));
        counter.fetch_add(1);
    });
    auto t2 = std::make_shared<fast_task::task>([&] {
        fast_task::this_task::sleep_for(std::chrono::milliseconds(20));
        counter.fetch_add(1);
    });
    fast_task::scheduler::start(t1);
    fast_task::scheduler::start(t2);
    std::vector<std::shared_ptr<fast_task::task>> tasks2{t1, t2};
    fast_task::task::await_multiple(tasks2, true);
    EXPECT_EQ(counter.load(), 2);
}
