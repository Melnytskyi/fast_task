// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>
#include <coroutine.hpp>
#include <stdexcept>

class CoroutineBasicTest : public SchedulerFixture {};

// ---- task_coro<void> ----

fast_task::task_coro<void> coro_void_fn(std::atomic<bool>& ran) {
    ran = true;
    co_return;
}

TEST_F(CoroutineBasicTest, VoidCoroutineRuns) {
    std::atomic<bool> ran{false};
    auto coro = coro_void_fn(ran);
    fast_task::scheduler::start(coro.get_task());
    coro->await_task();
    EXPECT_TRUE(ran.load());
}

// ---- task_coro<int> ----

fast_task::task_coro<int> coro_int_fn() {
    co_return 42;
}

TEST_F(CoroutineBasicTest, IntCoroutineResult) {
    auto coro = coro_int_fn();
    fast_task::scheduler::start(coro.get_task());
    coro->await_task();

    int result = 0;
    coro->access_dummy([&](void* addr) {
        auto h = std::coroutine_handle<fast_task::task_promise<int>>::from_address(addr);
        result = h.promise().result();
    });
    EXPECT_EQ(result, 42);
}

// ---- exception propagation ----

fast_task::task_coro<void> coro_throws_fn() {
    throw std::runtime_error("coro_error");
    co_return;
}

TEST_F(CoroutineBasicTest, ExceptionInCoroutineStoredInPromise) {
    auto coro = coro_throws_fn();
    fast_task::scheduler::start(coro.get_task());
    coro->await_task();

    bool threw = false;
    coro->access_dummy([&](void* addr) {
        auto h = std::coroutine_handle<fast_task::task_promise<void>>::from_address(addr);
        try {
            h.promise().result();
        } catch (const std::runtime_error& e) {
            threw = (std::string(e.what()) == "coro_error");
        }
    });
    EXPECT_TRUE(threw);
}

// ---- task_auto_start_coro ----

fast_task::task_auto_start_coro<void> auto_start_fn(std::atomic<bool>& ran) {
    ran = true;
    co_return;
}

TEST_F(CoroutineBasicTest, AutoStartCoro) {
    std::atomic<bool> ran{false};
    auto coro = auto_start_fn(ran);
    coro->await_task();
    EXPECT_TRUE(ran.load());
}
