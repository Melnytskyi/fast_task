// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>
#include <atomic>

class TaskPriorityTest : public SchedulerFixture {};

TEST_F(TaskPriorityTest, SetAndGetPriority) {
    // Without FT_ENABLE_PREEMPTIVE_SCHEDULER, set_priority is a no-op
    // and get_priority always returns semi_realtime (= 6).
    GTEST_SKIP() << "Skipped: requires FT_ENABLE_PREEMPTIVE_SCHEDULER";
}

TEST_F(TaskPriorityTest, AllPrioritiesRun) {
    // Just verify all priority levels complete successfully
    using tp = fast_task::task_priority;
    const tp priorities[] = {
        tp::background, tp::low, tp::lower,
        tp::normal, tp::higher, tp::high, tp::semi_realtime
    };

    for (auto prio : priorities) {
        std::atomic<bool> ran{false};
        auto t = std::make_shared<fast_task::task>([&] { ran = true; });
        t->set_priority(prio);
        fast_task::scheduler::start(t);
        t->await_task();
        EXPECT_TRUE(ran.load()) << "Priority " << static_cast<int>(prio) << " task did not run";
    }
}

TEST_F(TaskPriorityTest, HighPriorityRunsBeforeBackground) {
    // Queue a high-priority task while a background one is sleeping.
    // The high-priority one should finish first.
    std::atomic<int> order_bg{0};
    std::atomic<int> order_hi{0};
    std::atomic<int> seq{0};

    // background: sleep then record order
    auto bg = std::make_shared<fast_task::task>([&] {
        fast_task::this_task::sleep_for(std::chrono::milliseconds(50));
        order_bg = ++seq;
    });
    bg->set_priority(fast_task::task_priority::background);

    // high: just record order (no sleep)
    auto hi = std::make_shared<fast_task::task>([&] {
        order_hi = ++seq;
    });
    hi->set_priority(fast_task::task_priority::high);

    fast_task::scheduler::start(bg);
    fast_task::scheduler::start(hi);

    std::vector<std::shared_ptr<fast_task::task>> tasks{bg, hi};
    fast_task::task::await_multiple(tasks, true);

    EXPECT_LT(order_hi.load(), order_bg.load());
}
