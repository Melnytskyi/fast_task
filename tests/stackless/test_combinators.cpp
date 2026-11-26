// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <atomic>
#include <fast_task/coroutine.hpp>
#include <helpers.hpp>
#include <stdexcept>
#include <string>

class CombinatorsTest : public SchedulerFixture {};

TEST_F(CombinatorsTest, WhenAllHeterogeneousTupleAndVoid) {
    std::atomic<bool> void_ran{false};

    auto make_int = []() -> fast_task::task_coro<int> {
        co_await fast_task::this_task::async_yield();
        co_return 42;
    };
    auto make_str = []() -> fast_task::task_coro<std::string> {
        co_await fast_task::this_task::async_yield();
        co_return "fast_task";
    };
    auto make_void = [](std::atomic<bool>& flag) -> fast_task::task_coro<void> {
        flag.store(true, std::memory_order_relaxed);
        co_return;
    };

    int got_int = 0;
    std::string got_str;

    auto driver = [](auto c1, auto c2, auto c3, int& out_i, std::string& out_s) -> fast_task::task_coro<void> {
        auto [i, s, mono] = co_await fast_task::when_all(std::move(c1), std::move(c2), std::move(c3));
        (void)mono;
        out_i = i;
        out_s = std::move(s);
        co_return;
    }(make_int(), make_str(), make_void(void_ran), got_int, got_str);

    fast_task::scheduler::start(driver.get_task());
    driver->await_task();

    EXPECT_EQ(got_int, 42);
    EXPECT_EQ(got_str, "fast_task");
    EXPECT_TRUE(void_ran.load());
}

TEST_F(CombinatorsTest, WhenAllPropagatesExceptionAfterDraining) {
    std::atomic<bool> second_done{false};

    auto failing = []() -> fast_task::task_coro<int> {
        throw std::runtime_error("boom");
        co_return 0;
    };
    auto slow_ok = [](std::atomic<bool>& done) -> fast_task::task_coro<int> {
        co_await fast_task::this_task::async_sleep_for(std::chrono::milliseconds(15));
        done.store(true, std::memory_order_release);
        co_return 7;
    };

    auto driver = [](auto c1, auto c2) -> fast_task::task_coro<int> {
        auto [a, b] = co_await fast_task::when_all(std::move(c1), std::move(c2));
        co_return a + b;
    }(failing(), slow_ok(second_done));

    fast_task::scheduler::start(driver.get_task());
    EXPECT_THROW((void)driver.sync_get(), std::runtime_error);
    EXPECT_TRUE(second_done.load(std::memory_order_acquire));
}

TEST_F(CombinatorsTest, WhenAnyReturnsFastestWinner) {
    auto fast_coro = []() -> fast_task::task_coro<int> {
        co_await fast_task::this_task::async_yield();
        co_return 99;
    };
    auto slow_coro = []() -> fast_task::task_coro<std::string> {
        co_await fast_task::this_task::async_sleep_for(std::chrono::milliseconds(40));
        co_return "slow";
    };

    size_t winner_idx = 999;
    int winner_val = 0;

    auto driver = [](auto c1, auto c2, size_t& idx, int& val) -> fast_task::task_coro<void> {
        auto [w, v] = co_await fast_task::when_any(std::move(c1), std::move(c2));
        idx = w;
        if (w == 0)
            val = std::get<0>(v);
        co_return;
    }(fast_coro(), slow_coro(), winner_idx, winner_val);

    fast_task::scheduler::start(driver.get_task());
    driver->await_task();

    EXPECT_EQ(winner_idx, 0u);
    EXPECT_EQ(winner_val, 99);
}

TEST_F(CombinatorsTest, WithTimeoutSucceedsAndTimesOut) {
    // Fast operation succeeds before deadline
    {
        auto fast_op = []() -> fast_task::task_coro<int> {
            co_await fast_task::this_task::async_yield();
            co_return 77;
        };
        auto wrapped = fast_task::with_timeout(fast_op(), std::chrono::milliseconds(200));
        fast_task::scheduler::start(wrapped.get_task());
        auto res = wrapped.sync_get();
        ASSERT_TRUE(res.has_value());
        EXPECT_EQ(*res, 77);
    }

    // Slow operation times out and returns std::nullopt
    {
        auto slow_op = []() -> fast_task::task_coro<int> {
            co_await fast_task::this_task::async_sleep_for(std::chrono::milliseconds(150));
            co_return 88;
        };
        auto wrapped = fast_task::with_timeout(slow_op(), std::chrono::milliseconds(20));
        fast_task::scheduler::start(wrapped.get_task());
        auto res = wrapped.sync_get();
        EXPECT_FALSE(res.has_value());
    }
}
