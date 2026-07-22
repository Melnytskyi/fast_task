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
