// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>
#include <future.hpp>
#include <atomic>

class FutureCallbacksTest : public SchedulerFixture {};

TEST_F(FutureCallbacksTest, WhenReadyCalledAfterCompletion) {
    std::atomic<int> received{0};
    auto f = fast_task::future<int>::start([] { return 7; });
    f->when_ready([&](int v) { received = v; });
    // wait for the callback task to run
    fast_task::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_EQ(received.load(), 7);
}

TEST_F(FutureCallbacksTest, WhenReadyCalledImmediatelyIfAlreadyReady) {
    auto f = fast_task::future<int>::make_ready(42);
    std::atomic<int> received{0};
    f->when_ready([&](int v) { received = v; });
    // For an already-ready future the callback runs synchronously
    EXPECT_EQ(received.load(), 42);
}

TEST_F(FutureCallbacksTest, WaitWithUniqueLock) {
    fast_task::task_mutex mtx;
    fast_task::mutex_unify mu(mtx);
    fast_task::unique_lock<fast_task::mutex_unify> lk(mu);

    auto f = fast_task::future<int>::start([] {
        fast_task::this_task::sleep_for(std::chrono::milliseconds(20));
        return 99;
    });

    // wait_with should release lk while waiting and reacquire after
    f->wait_with(lk);
    EXPECT_EQ(f->get(), 99);
}

TEST_F(FutureCallbacksTest, VoidWhenReady) {
    std::atomic<bool> called{false};
    auto f = fast_task::future<void>::start([] {});
    f->when_ready([&] { called = true; });
    fast_task::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_TRUE(called.load());
}
