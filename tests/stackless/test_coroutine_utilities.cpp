// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>
#include <coroutine.hpp>
#include <atomic>
#include <vector>

class CoroutineUtilitiesTest : public SchedulerFixture {};

// NOTE: coroutine::for_each and coroutine::async_for_each are disabled
// due to a library bug: they call coros.emplace_back(cor) on an lvalue
// task_coro<void> which is move-only (deleted copy constructor).

// ---- coroutine::wait_all ----

TEST_F(CoroutineUtilitiesTest, WaitAllWaitsForAll) {
    std::atomic<int> count{0};

    auto make_coro = [&]() -> fast_task::task_coro<void> {
        fast_task::this_task::sleep_for(std::chrono::milliseconds(20));
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

// async_for_each with task_query also uses the same buggy emplace_back pattern - disabled.
