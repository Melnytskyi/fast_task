// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>
#include <atomic>

class TaskTimeoutTest : public SchedulerFixture {};

TEST_F(TaskTimeoutTest, SetAndGetTimeout) {
    auto deadline = std::chrono::high_resolution_clock::now() + std::chrono::seconds(10);
    auto t = std::make_shared<fast_task::task>([] {});
    t->set_timeout(deadline);
    EXPECT_EQ(t->get_timeout(), deadline);
}

TEST_F(TaskTimeoutTest, TimeoutBeforeCompletion) {
    // Task sleeps longer than its timeout — should be cancelled via time_end_flag
    std::atomic<bool> completed{false};
    std::atomic<bool> was_cancelled{false};

    auto deadline = std::chrono::high_resolution_clock::now() + std::chrono::milliseconds(50);

    auto t = std::make_shared<fast_task::task>(
        [&] {
            try {
                fast_task::this_task::sleep_for(std::chrono::seconds(10));
                completed = true;
            } catch (const fast_task::task_cancellation&) {
                was_cancelled = true;
                throw;
            }
        },
        nullptr,
        deadline
    );

    fast_task::scheduler::start(t);
    t->await_task();

    EXPECT_FALSE(completed.load());
    EXPECT_TRUE(was_cancelled.load());
}

TEST_F(TaskTimeoutTest, NoTimeoutWhenCompletesEarly) {
    std::atomic<bool> completed{false};
    auto deadline = std::chrono::high_resolution_clock::now() + std::chrono::seconds(60);
    auto t = std::make_shared<fast_task::task>(
        [&] { completed = true; },
        nullptr,
        deadline
    );
    fast_task::scheduler::start(t);
    t->await_task();
    EXPECT_TRUE(completed.load());
}
