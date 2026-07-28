// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <atomic>
#include <helpers.hpp>

class TaskCancellationTest : public SchedulerFixture {};

TEST_F(TaskCancellationTest, CheckCancellationThrows) {
    std::atomic<bool> caught{false};
    std::atomic<bool> started{false};
    auto t = fast_task::task::create([&] {
        started = true;
        try {
            while (!fast_task::this_task::is_cancellation_requested())
                fast_task::this_task::yield();
            fast_task::this_task::check_cancellation();
        } catch (const fast_task::task_cancellation&) {
            caught = true;
            throw;
        }
    },
                                     nullptr);
    fast_task::scheduler::start(t);
    while (!started.load())
        fast_task::native::this_thread::sleep_for(std::chrono::milliseconds(1));
    t.notify_cancel();
    t.await_task();
    EXPECT_TRUE(caught.load());
}

TEST_F(TaskCancellationTest, IsCancellationRequested) {
    std::atomic<bool> requested{false};
    std::atomic<bool> started{false};
    auto t = fast_task::task::create([&] {
        started = true;

        while (!fast_task::this_task::is_cancellation_requested())
            fast_task::this_task::yield();
        requested = fast_task::this_task::is_cancellation_requested();
    });
    fast_task::scheduler::start(t);
    while (!started.load())
        fast_task::native::this_thread::sleep_for(std::chrono::milliseconds(1));
    t.notify_cancel();
    t.await_task();
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
    std::atomic<bool> cancelled{false};
    auto t = fast_task::task::create([&] {
        cancelled = true;
        fast_task::this_task::self_cancel();
    });
    fast_task::scheduler::start(t);
    t.await_task();
    EXPECT_TRUE(cancelled.load());
}

TEST_F(TaskCancellationTest, NotifyCancelFromOutside) {
    std::atomic<bool> was_cancelled{false};
    std::atomic<bool> started{false};

    auto t = fast_task::task::create(
        [&] {
            started = true;
            try {
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

    while (!started.load())
        fast_task::native::this_thread::sleep_for(std::chrono::milliseconds(1));

    t.notify_cancel();
    t.await_task();

    EXPECT_TRUE(was_cancelled.load());
}

TEST_F(TaskCancellationTest, AwaitNotifyCancelReturnsWhenCancelled) {
    std::atomic<bool> passed{false};
    std::atomic<bool> started{false};
    auto t = fast_task::task::create(
        [&] {
            started = true;
            while (!fast_task::this_task::is_cancellation_requested())
                fast_task::this_task::yield();
            try {
                fast_task::this_task::check_cancellation();
            } catch (const fast_task::task_cancellation&) {
                passed = true;
                throw;
            }
        },
        nullptr
    );
    fast_task::scheduler::start(t);
    while (!started.load())
        fast_task::native::this_thread::sleep_for(std::chrono::milliseconds(1));
    t.notify_cancel();
    t.await_task();
    EXPECT_TRUE(passed.load());
}
