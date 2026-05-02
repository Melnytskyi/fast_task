// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>
#include <future.hpp>
#include <stdexcept>
#include <atomic>

class CancelableFutureTest : public SchedulerFixture {};

TEST_F(CancelableFutureTest, StartAndGet) {
    auto f = fast_task::cancelable_future<int>::start([] { return 10; });
    EXPECT_EQ(f->get(), 10);
}

TEST_F(CancelableFutureTest, CancelStopsTask) {
    std::atomic<bool> started{false};
    auto f = fast_task::cancelable_future<int>::start([&] -> int {
        started = true;
        try {
            fast_task::this_task::sleep_for(std::chrono::microseconds(200));
        } catch (const fast_task::task_cancellation&) {
            throw;
        }
        return 0;
    });

    while (!started.load())
        fast_task::this_thread::sleep_for(std::chrono::milliseconds(1));

    f->cancel();

    // After cancellation get() should throw because task was cancelled
    EXPECT_THROW(f->get(), std::runtime_error);
}

TEST_F(CancelableFutureTest, MakeReady) {
    auto f = fast_task::cancelable_future<int>::make_ready(77);
    EXPECT_TRUE(f->is_ready());
    EXPECT_EQ(f->get(), 77);
}

TEST_F(CancelableFutureTest, HasException) {
    auto f = fast_task::cancelable_future<int>::start([] -> int {
        throw std::runtime_error("cfuture_error");
    });
    f->wait_no_except();
    EXPECT_TRUE(f->has_exception());
}

TEST_F(CancelableFutureTest, VoidCancelable) {
    std::atomic<bool> ran{false};
    auto f = fast_task::cancelable_future<void>::start([&] { ran = true; });
    f->get();
    EXPECT_TRUE(ran.load());
}

TEST_F(CancelableFutureTest, VoidCancelStopsTask) {
    std::atomic<bool> started{false};
    auto f = fast_task::cancelable_future<void>::start([&] {
        started = true;
        try {
            fast_task::this_task::sleep_for(std::chrono::microseconds(200));
        } catch (const fast_task::task_cancellation&) {
            throw;
        }
    });

    while (!started.load())
        fast_task::this_thread::sleep_for(std::chrono::milliseconds(1));

    f->cancel();
    EXPECT_THROW(f->get(), std::runtime_error);
}
