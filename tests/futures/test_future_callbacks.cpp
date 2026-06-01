// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <atomic>
#include <helpers.hpp>
#include <task/future.hpp>

class FutureCallbacksTest : public SchedulerFixture {};

TEST_F(FutureCallbacksTest, WhenReadyCalledAfterCompletion) {
    std::atomic<int> received{0};
    auto f = fast_task::future<int>::start([] { return 7; });
    f->when_ready([&](auto& v) { received = v.get(); });
    // wait for the callback task to run
    fast_task::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_EQ(received.load(), 7);
}

TEST_F(FutureCallbacksTest, WhenReadyCalledImmediatelyIfAlreadyReady) {
    auto f = fast_task::future<int>::make_ready(42);
    std::atomic<int> received{0};
    f->when_ready([&](auto& v) { received = v.get(); });
    // For an already-ready future the callback runs synchronously
    EXPECT_EQ(received.load(), 42);
}

TEST_F(FutureCallbacksTest, VoidWhenReady) {
    std::atomic<bool> called{false};
    auto f = fast_task::future<void>::start([] {});
    f->when_ready([&] { called = true; });
    fast_task::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_TRUE(called.load());
}
