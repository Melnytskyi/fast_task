// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>
#include <atomic>

class TaskCancellationTest : public SchedulerFixture {};

TEST_F(TaskCancellationTest, CheckCancellationThrows) {
    std::atomic<bool> caught{false};
    std::atomic<bool> started{false};
    auto t = std::make_shared<fast_task::task>([&] {
        started = true;
        try {
            while (!fast_task::this_task::is_cancellation_requested())
                fast_task::this_task::yield();
            fast_task::this_task::check_cancellation();
        } catch (const fast_task::task_cancellation&) {
            caught = true;
            throw; // must re-throw so context_exec handles destructor cleanup
        }
    }, nullptr);
    fast_task::scheduler::start(t);
    while (!started.load())
        fast_task::this_thread::sleep_for(std::chrono::milliseconds(1));
    t->notify_cancel();
    t->await_task();
    EXPECT_TRUE(caught.load());
}

TEST_F(TaskCancellationTest, IsCancellationRequested) {
    std::atomic<bool> requested{false};
    std::atomic<bool> started{false};
    auto t = std::make_shared<fast_task::task>([&] {
        started = true;
        // spin until cancellation is requested from outside
        while (!fast_task::this_task::is_cancellation_requested())
            fast_task::this_task::yield();
        requested = fast_task::this_task::is_cancellation_requested();
    });
    fast_task::scheduler::start(t);
    while (!started.load())
        fast_task::this_thread::sleep_for(std::chrono::milliseconds(1));
    t->notify_cancel();
    t->await_task();
    EXPECT_TRUE(requested.load());
}

TEST_F(TaskCancellationTest, IsCancellationNotRequestedByDefault) {
    std::atomic<bool> requested{true};
    run_task([&] {
        requested = fast_task::this_task::is_cancellation_requested();
    });
    EXPECT_FALSE(requested.load());
}

TEST_F(TaskCancellationTest, SelfCancel) {
    // self_cancel() throws task_cancellation which is caught by the scheduler
    // (context_exec), not passed to ex_handle. Set a flag before throwing.
    std::atomic<bool> cancelled{false};
    auto t = std::make_shared<fast_task::task>([&] {
        cancelled = true;
        fast_task::this_task::self_cancel();
    });
    fast_task::scheduler::start(t);
    t->await_task();
    EXPECT_TRUE(cancelled.load());
}

TEST_F(TaskCancellationTest, NotifyCancelFromOutside) {
    std::atomic<bool> was_cancelled{false};
    std::atomic<bool> started{false};

    auto t = std::make_shared<fast_task::task>(
        [&] {
            started = true;
            try {
                // yield in a loop until cancellation is requested
                while (!fast_task::this_task::is_cancellation_requested())
                    fast_task::this_task::yield();
                fast_task::this_task::check_cancellation();
            } catch (const fast_task::task_cancellation&) {
                was_cancelled = true;
                throw;
            }
        },
        nullptr
    );

    fast_task::scheduler::start(t);

    // Wait for the task to have started
    while (!started.load())
        fast_task::this_thread::sleep_for(std::chrono::milliseconds(1));

    t->notify_cancel();
    t->await_task();

    EXPECT_TRUE(was_cancelled.load());
}

TEST_F(TaskCancellationTest, AwaitNotifyCancelReturnsWhenCancelled) {
    std::atomic<bool> passed{false};
    std::atomic<bool> started{false};
    auto t = std::make_shared<fast_task::task>([&] {
        started = true;
        // spin until cancellation is requested from outside
        while (!fast_task::this_task::is_cancellation_requested())
            fast_task::this_task::yield();
        try {
            fast_task::this_task::check_cancellation();
        } catch (const fast_task::task_cancellation&) {
            passed = true;
            throw; // must re-throw so context_exec handles destructor cleanup
        }
    }, nullptr);
    fast_task::scheduler::start(t);
    while (!started.load())
        fast_task::this_thread::sleep_for(std::chrono::milliseconds(1));
    t->notify_cancel();
    t->await_task();
    EXPECT_TRUE(passed.load());
}
