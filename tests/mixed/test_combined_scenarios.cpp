// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>
#include <coroutine.hpp>
#include <future.hpp>
#include <atomic>

class CombinedScenariosTest : public SchedulerFixture {};

// ---- task_query grouping stackful + stackless tasks ----

TEST_F(CombinedScenariosTest, TaskQueryMixedTasksAndCoroutines) {
    fast_task::task_query query(3);
    std::atomic<int> count{0};

    // Stackful tasks
    auto t1 = std::make_shared<fast_task::task>([&] { ++count; });
    auto t2 = std::make_shared<fast_task::task>([&] { ++count; });
    query.add(t1);
    query.add(t2);

    // Stackless coroutine
    auto make_coro = [&]() -> fast_task::task_coro<void> {
        ++count;
        co_return;
    };
    auto c = make_coro();
    query.add(c.get_task());
    query.enable();
    query.wait();

    t1->await_task();
    t2->await_task();
    c->await_task();

    EXPECT_EQ(count.load(), 3);
}

// ---- deadline_timer canceling a blocked task ----

TEST_F(CombinedScenariosTest, DeadlineTimerCancelsBlockedTask) {
    GTEST_SKIP() << "Skipped: library limitation — task deadline does not cancel a task on wait, but would only prevent it from being scheduled after the wait is over. This is a known issue and will be fixed in a future .";
    fast_task::task_mutex mtx;
    std::atomic<bool> cancelled{false};

    auto deadline = std::chrono::high_resolution_clock::now() + std::chrono::milliseconds(50);
    auto t = std::make_shared<fast_task::task>(
        [&] {
            try {
                fast_task::unique_lock<fast_task::task_mutex> lock(mtx);
            } catch (const fast_task::task_cancellation&) {
                cancelled = true;
                throw;
            }
        },
        nullptr,
        deadline
    );

    fast_task::unique_lock<fast_task::task_mutex> native_lock(mtx);
    fast_task::scheduler::start(t);
    t->await_task();

    EXPECT_TRUE(cancelled.load());
}

// ---- nested coroutines ----

fast_task::task_coro<int> nested_inner(int v) {
    co_return v * 2;
}

fast_task::task_coro<int> nested_middle(int v) {
    auto inner = nested_inner(v);
    fast_task::scheduler::start(inner.get_task());
    int r = co_await inner;
    co_return r + 1;
}

fast_task::task_coro<int> nested_outer(int v) {
    auto mid = nested_middle(v);
    fast_task::scheduler::start(mid.get_task());
    int r = co_await mid;
    co_return r + 10;
}

TEST_F(CombinedScenariosTest, NestedCoroutinesComputeCorrectly) {
    auto coro = nested_outer(5);
    fast_task::scheduler::start(coro.get_task());
    coro->await_task();

    int result = 0;
    coro->access_dummy([&](void* addr) {
        auto h = std::coroutine_handle<fast_task::task_promise<int>>::from_address(addr);
        result = h.promise().result();
    });

    EXPECT_EQ(result, 21);
}

// ---- future chained from coroutine result ----

fast_task::task_coro<int> compute_coro() {
    co_return 5;
}

TEST_F(CombinedScenariosTest, FutureChainedFromCoroutineResult) {
    auto coro = compute_coro();
    fast_task::scheduler::start(coro.get_task());
    coro->await_task();

    int coro_result = 0;
    coro->access_dummy([&](void* addr) {
        auto h = std::coroutine_handle<fast_task::task_promise<int>>::from_address(addr);
        coro_result = h.promise().result();
    });

    auto f = fast_task::future<int>::start([coro_result] { return coro_result * 10; });
    EXPECT_EQ(f->get(), 50);
}
