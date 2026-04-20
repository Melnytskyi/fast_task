// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>
#include <future.hpp>
#include <stdexcept>

class FutureVoidTest : public SchedulerFixture {};

TEST_F(FutureVoidTest, StartAndGet) {
    std::atomic<bool> ran{false};
    auto f = fast_task::future<void>::start([&] { ran = true; });
    f->get();
    EXPECT_TRUE(ran.load());
}

TEST_F(FutureVoidTest, MakeReady) {
    auto f = fast_task::future<void>::make_ready();
    EXPECT_TRUE(f->is_ready());
    f->get(); // should not throw
}

TEST_F(FutureVoidTest, IsReady) {
    auto f = fast_task::future<void>::start([] {});
    f->wait();
    EXPECT_TRUE(f->is_ready());
}

TEST_F(FutureVoidTest, WaitForSuccess) {
    auto f = fast_task::future<void>::start([] {});
    EXPECT_TRUE(f->wait_for(std::chrono::seconds(5)));
}

TEST_F(FutureVoidTest, WaitForTimeout) {
    auto f = fast_task::future<void>::start([] {
        fast_task::this_task::sleep_for(std::chrono::seconds(10));
    });
    EXPECT_FALSE(f->wait_for(std::chrono::milliseconds(30)));
}

TEST_F(FutureVoidTest, HasExceptionOnThrow) {
    auto f = fast_task::future<void>::start([] {
        throw std::runtime_error("void_error");
    });
    f->wait_no_except();
    EXPECT_TRUE(f->has_exception());
}

TEST_F(FutureVoidTest, GetRethrowsException) {
    auto f = fast_task::future<void>::start([] {
        throw std::logic_error("void_logic");
    });
    EXPECT_THROW(f->get(), std::logic_error);
}

TEST_F(FutureVoidTest, TakeEqualsGet) {
    std::atomic<bool> ran{false};
    auto f = fast_task::future<void>::start([&] { ran = true; });
    f->take(); // should not throw
    EXPECT_TRUE(ran.load());
}
