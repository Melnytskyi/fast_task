// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>
#include <atomic>

class ContextSwitchTest : public SchedulerFixture {};

TEST_F(ContextSwitchTest, YieldIncreasesContextSwitchCounter) {
    fast_task::task t_ref;
    auto t = fast_task::task::create([&] {
        fast_task::this_task::yield();
        fast_task::this_task::yield();
        fast_task::this_task::yield();
    });
    t_ref = t;
    fast_task::scheduler::start(t);
    t.await_task();
    EXPECT_GE(t_ref.get_counter_context_switch(), 3u);
}

TEST_F(ContextSwitchTest, NoYieldHasLowCounter) {
    fast_task::task t_ref;
    auto t = fast_task::task::create([&] {
        // no yield
        volatile int x = 0;
        for (int i = 0; i < 1000; ++i)
            x += i;
    });
    t_ref = t;
    fast_task::scheduler::start(t);
    t.await_task();
    EXPECT_LE(t_ref.get_counter_context_switch(), 1u);
}

TEST_F(ContextSwitchTest, SleepCausesContextSwitch) {
    fast_task::task t_ref;
    auto t = fast_task::task::create([&] {
        fast_task::this_task::sleep_for(std::chrono::milliseconds(10));
    });
    t_ref = t;
    fast_task::scheduler::start(t);
    t.await_task();
    EXPECT_GE(t_ref.get_counter_context_switch(), 1u);
}

TEST_F(ContextSwitchTest, InterruptCounterTracked) {
    fast_task::task t_ref;
    std::atomic<bool> cancelled{false};
    std::atomic<bool> started{false};

    auto t = fast_task::task::create(
        [&] {
            started = true;
            while (!fast_task::this_task::is_cancellation_requested())
                fast_task::this_task::yield();
            try {
                fast_task::this_task::check_cancellation();
            } catch (const fast_task::task_cancellation&) {
                cancelled = true;
                throw;
            }
        },
        nullptr
    );
    t_ref = t;
    fast_task::scheduler::start(t);
    while (!started.load())
        fast_task::native::this_thread::sleep_for(std::chrono::milliseconds(1));
    t.notify_cancel();
    t.await_task();

    EXPECT_TRUE(cancelled.load());
    EXPECT_GE(t_ref.get_counter_interrupt(), 0u);
}

namespace {
    struct transfer_end_state {
        fast_task::task partner;
        int64_t remaining = 0;
        bool yield = false;
        fast_task::enter_state state;
    };

    fast_task::task_vtable transfer_end_vt{
        nullptr,
        nullptr,
        [](void* ptr) {
            auto* s = static_cast<transfer_end_state*>(ptr);
            if (s->remaining > 0) {
                if (!s->yield)
                    --s->remaining;
                else
                    s->yield = false;
                if (!fast_task::this_task::transfer_to(s->partner)) {
                    s->yield = true;
                    fast_task::this_task::enter_yield(s->state);
                }
                if (s->remaining == 0)
                    fast_task::this_task::the_coroutine_ended(fast_task::scheduler::current_context_task());
            } else
                fast_task::this_task::the_coroutine_ended(fast_task::scheduler::current_context_task());
        },
        nullptr,
        nullptr,
        false
    };
}

TEST_F(ContextSwitchTest, EndedTaskThatHandsOverIsAccounted) {
    transfer_end_state a, b;
    a.remaining = 1000;
    b.remaining = 1000;

    auto task_a = fast_task::task(&a, &transfer_end_vt, true, true);
    auto task_b = fast_task::task(&b, &transfer_end_vt, true, true);
    a.partner = fast_task::task(task_b);
    b.partner = fast_task::task(task_a);

    task_a.await_task();
    fast_task::task::await_task(task_b, false);

    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (fast_task::scheduler::get_runtime_stats().executing_tasks != 0 &&
           std::chrono::steady_clock::now() < deadline)
        fast_task::native::this_thread::sleep_for(std::chrono::milliseconds(1));

    EXPECT_EQ(fast_task::scheduler::get_runtime_stats().executing_tasks, 0u);
}
