// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>
#include <future.hpp>
#include <stdexcept>

class FutureBasicTest : public SchedulerFixture {};

TEST_F(FutureBasicTest, StartAndGet) {
    auto f = fast_task::future<int>::start([] { return 42; });
    EXPECT_EQ(f->get(), 42);
}

TEST_F(FutureBasicTest, StartAndTake) {
    auto f = fast_task::future<std::string>::start([] { return std::string("hello"); });
    EXPECT_EQ(f->take(), "hello");
}

TEST_F(FutureBasicTest, MakeReady) {
    auto f = fast_task::future<int>::make_ready(99);
    EXPECT_TRUE(f->is_ready());
    EXPECT_EQ(f->get(), 99);
}

TEST_F(FutureBasicTest, IsReadyAfterCompletion) {
    auto f = fast_task::future<int>::start([] { return 1; });
    f->wait();
    EXPECT_TRUE(f->is_ready());
}

TEST_F(FutureBasicTest, WaitForSuccess) {
    auto f = fast_task::future<int>::start([] { return 5; });
    bool ready = f->wait_for(std::chrono::seconds(1));
    EXPECT_TRUE(ready);
    EXPECT_EQ(f->get(), 5);
}

TEST_F(FutureBasicTest, WaitForTimeout) {
    auto f = fast_task::future<int>::start([] {
        fast_task::this_task::sleep_for(std::chrono::milliseconds(90));
        return 0;
    });
    bool ready = f->wait_for(std::chrono::milliseconds(30));
    EXPECT_FALSE(ready);
}

TEST_F(FutureBasicTest, WaitUntilSuccess) {
    auto f = fast_task::future<int>::start([] { return 3; });
    auto until = std::chrono::high_resolution_clock::now() + std::chrono::seconds(1);
    bool ready = f->wait_until(until);
    EXPECT_TRUE(ready);
}

TEST_F(FutureBasicTest, HasException) {
    auto f = fast_task::future<int>::start([] -> int {
        throw std::runtime_error("boom");
    });
    f->wait_no_except();
    EXPECT_TRUE(f->has_exception());
}

TEST_F(FutureBasicTest, GetRethrowsException) {
    auto f = fast_task::future<int>::start([] -> int {
        throw std::runtime_error("future_error");
    });
    EXPECT_THROW(f->get(), std::runtime_error);
}
