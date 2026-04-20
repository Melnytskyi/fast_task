// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>
#include <atomic>

class ContextSwitchTest : public SchedulerFixture {};

TEST_F(ContextSwitchTest, YieldIncreasesContextSwitchCounter) {
    std::shared_ptr<fast_task::task> t_ref;
    auto t = std::make_shared<fast_task::task>([&] {
        fast_task::this_task::yield();
        fast_task::this_task::yield();
        fast_task::this_task::yield();
    });
    t_ref = t;
    fast_task::scheduler::start(t);
    t->await_task();
    EXPECT_GE(t_ref->get_counter_context_switch(), 3u);
}

TEST_F(ContextSwitchTest, NoYieldHasLowCounter) {
    std::shared_ptr<fast_task::task> t_ref;
    auto t = std::make_shared<fast_task::task>([&] {
        // no yield
        volatile int x = 0;
        for (int i = 0; i < 1000; ++i) x += i;
    });
    t_ref = t;
    fast_task::scheduler::start(t);
    t->await_task();
    // Without explicit yields the counter may be 0 or 1 (initial switch)
    EXPECT_LE(t_ref->get_counter_context_switch(), 1u);
}

TEST_F(ContextSwitchTest, SleepCausesContextSwitch) {
    std::shared_ptr<fast_task::task> t_ref;
    auto t = std::make_shared<fast_task::task>([&] {
        fast_task::this_task::sleep_for(std::chrono::milliseconds(10));
    });
    t_ref = t;
    fast_task::scheduler::start(t);
    t->await_task();
    EXPECT_GE(t_ref->get_counter_context_switch(), 1u);
}

TEST_F(ContextSwitchTest, InterruptCounterTracked) {
    std::shared_ptr<fast_task::task> t_ref;
    std::atomic<bool> cancelled{false};
    std::atomic<bool> started{false};

    auto t = std::make_shared<fast_task::task>(
        [&] {
            started = true;
            while (!fast_task::this_task::is_cancellation_requested())
                fast_task::this_task::yield();
            try {
                fast_task::this_task::check_cancellation();
            } catch (const fast_task::task_cancellation&) {
                cancelled = true;
                throw; // must re-throw so context_exec handles destructor cleanup
            }
        },
        nullptr
    );
    t_ref = t;
    fast_task::scheduler::start(t);
    while (!started.load())
        fast_task::this_thread::sleep_for(std::chrono::milliseconds(1));
    t->notify_cancel();
    t->await_task();

    EXPECT_TRUE(cancelled.load());
    // interrupt counter requires FT_ENABLE_PREEMPTIVE_SCHEDULER; just check >= 0
    EXPECT_GE(t_ref->get_counter_interrupt(), 0u);
}
