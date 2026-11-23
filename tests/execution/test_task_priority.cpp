// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>
#include <atomic>

class TaskPriorityTest : public SchedulerFixture {};

TEST_F(TaskPriorityTest, SetAndGetPriority) {
    auto t = fast_task::task::create([] {});
    EXPECT_EQ(t.get_priority(), fast_task::task_priority::high);

    for (auto prio : {fast_task::task_priority::background, fast_task::task_priority::lower, fast_task::task_priority::semi_realtime}) {
        t.set_priority(prio);
        EXPECT_EQ(t.get_priority(), prio);
    }

    fast_task::scheduler::start(t);
    t.await_task();

    fast_task::task empty;
    EXPECT_EQ(empty.get_priority(), fast_task::task_priority::semi_realtime);
}

TEST_F(TaskPriorityTest, AllPrioritiesRun) {
    using tp = fast_task::task_priority;
    const tp priorities[] = {
        tp::background, tp::low, tp::lower,
        tp::normal, tp::higher, tp::high, tp::semi_realtime
    };

    for (auto prio : priorities) {
        std::atomic<bool> ran{false};
        auto t = fast_task::task::create([&] { ran = true; });
        t.set_priority(prio);
        fast_task::scheduler::start(t);
        t.await_task();
        EXPECT_TRUE(ran.load()) << "Priority " << static_cast<int>(prio) << " task did not run";
    }
}

TEST_F(TaskPriorityTest, HighPriorityRunsBeforeBackground) {
    std::atomic<int> order_bg{0};
    std::atomic<int> order_hi{0};
    std::atomic<int> seq{0};

    auto bg = fast_task::task::create([&] {
        fast_task::this_task::sleep_for(std::chrono::milliseconds(50));
        order_bg = ++seq;
    });
    bg.set_priority(fast_task::task_priority::background);

    auto hi = fast_task::task::create([&] {
        order_hi = ++seq;
    });
    hi.set_priority(fast_task::task_priority::high);

    fast_task::scheduler::start(bg);
    fast_task::scheduler::start(hi);

    std::vector<fast_task::task> tasks{bg, hi};
    fast_task::task::await_multiple(tasks, true);

    EXPECT_LT(order_hi.load(), order_bg.load());
}
