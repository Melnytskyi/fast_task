// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <atomic>
#include <fast_task/coroutine.hpp>
#include <helpers.hpp>
#include <vector>

class CoroutineUtilitiesTest : public SchedulerFixture {};

// ---- coroutine::wait_all ----

TEST_F(CoroutineUtilitiesTest, WaitAllWaitsForAll) {
    std::atomic<int> count{0};

    auto make_coro = [&]() -> fast_task::task_coro<void> {
        ++count;
        co_return;
    };

    std::vector<fast_task::task_coro<void>> coros;
    coros.push_back(make_coro());
    coros.push_back(make_coro());
    coros.push_back(make_coro());

    for (auto& c : coros)
        fast_task::scheduler::start(c.get_task());

    auto waiter = fast_task::coroutine::wait_all(std::move(coros));
    waiter->await_task();

    EXPECT_EQ(count.load(), 3);
}

// ---- coroutine::wait_all_blocking ----

TEST_F(CoroutineUtilitiesTest, WaitAllBlockingWaitsForAll) {
    std::atomic<int> count{0};

    auto make_coro = [&]() -> fast_task::task_coro<void> {
        ++count;
        co_return;
    };

    std::vector<fast_task::task_coro<void>> coros;
    coros.push_back(make_coro());
    coros.push_back(make_coro());

    fast_task::coroutine::wait_all_blocking(coros);

    EXPECT_EQ(count.load(), 2);
}

// ---- coroutine::async_for_each lvalue preservation ----

TEST_F(CoroutineUtilitiesTest, AsyncForEachPreservesLvalueContainer) {
    std::vector<std::string> items{"alpha", "beta", "gamma"};
    std::atomic<size_t> total_len{0};

    auto coro = fast_task::coroutine::async_for_each(items, [&](const std::string& s) {
        total_len.fetch_add(s.size(), std::memory_order_relaxed);
    });
    coro->await_task();

    EXPECT_EQ(total_len.load(), 5u + 4u + 5u);
    EXPECT_EQ(items[0], "alpha");
    EXPECT_EQ(items[1], "beta");
    EXPECT_EQ(items[2], "gamma");
}

// ---- task_generator ----

TEST_F(CoroutineUtilitiesTest, TaskGeneratorYieldsValuesAndCompletes) {
    auto gen_fn = []() -> fast_task::task_generator<int> {
        for (int i = 1; i <= 5; ++i)
            co_yield i * 10;
    };

    std::vector<int> received;
    auto consumer = [&]() -> fast_task::task_coro<void> {
        auto gen = gen_fn();
        while (auto val = co_await gen.next())
            received.push_back(*val);
        co_return;
    }();
    fast_task::scheduler::start(consumer.get_task());
    consumer->await_task();

    ASSERT_EQ(received.size(), 5u);
    EXPECT_EQ(received[0], 10);
    EXPECT_EQ(received[4], 50);
}
