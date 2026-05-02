// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>
#include <coroutine.hpp>
#include <atomic>

class CoroutineAwaitTest : public SchedulerFixture {};

// ---- co_await task_coro<T> ----

fast_task::task_coro<int> inner_coro() {
    co_return 7;
}

fast_task::task_coro<int> outer_coro() {
    auto coro = inner_coro();
    fast_task::scheduler::start(coro.get_task());
    int v = co_await coro;
    co_return v * 2;
}

TEST_F(CoroutineAwaitTest, CoAwaitInnerCoro) {
    std::atomic<bool> done{false};
    auto coro_fn = [&done]() -> fast_task::task_coro<void> {
        auto c = outer_coro();
        fast_task::scheduler::start(c.get_task());
        int v = co_await c;
        EXPECT_EQ(v, 14);
        done = true;
        co_return;
    };
    auto coro = coro_fn();
    fast_task::scheduler::start(coro.get_task());
    coro->await_task();
    EXPECT_TRUE(done.load());
}

// ---- co_await std::shared_ptr<task> ----

fast_task::task_coro<void> await_task_ptr(std::atomic<int>& out) {
    auto t = std::make_shared<fast_task::task>([&] { out = 55; });
    fast_task::scheduler::start(t);
    co_await std::move(t);
    // value should be set after await
}

TEST_F(CoroutineAwaitTest, CoAwaitSharedPtrTask) {
    std::atomic<int> out{0};
    auto coro_fn = [&out]() -> fast_task::task_coro<void> {
        auto at = await_task_ptr(out);
        fast_task::scheduler::start(at.get_task());
        co_await at;
        co_return;
    };
    auto coro = coro_fn();
    fast_task::scheduler::start(coro.get_task());
    coro->await_task();
    EXPECT_EQ(out.load(), 55);
}

// ---- task_auto_start_coro: no manual start ----

fast_task::task_auto_start_coro<void> chained_auto(std::atomic<bool>& done) {
    auto inner = [] -> fast_task::task_auto_start_coro<void> {
        co_return;
    }();
    co_await inner;
    done = true;
    co_return;
}

TEST_F(CoroutineAwaitTest, AutoStartChained) {
    std::atomic<bool> done{false};
    auto coro = chained_auto(done);
    coro->await_task();
    EXPECT_TRUE(done.load());
}

// ---- sequential co_await chain ----

fast_task::task_coro<int> step(int v) {
    co_return v + 1;
}

fast_task::task_coro<int> pipeline() {
    auto a = step(0);
    fast_task::scheduler::start(a.get_task());
    int r1 = co_await a;

    auto b = step(r1);
    fast_task::scheduler::start(b.get_task());
    int r2 = co_await b;

    auto c = step(r2);
    fast_task::scheduler::start(c.get_task());
    int r3 = co_await c;
    co_return r3;
}

TEST_F(CoroutineAwaitTest, SequentialPipeline) {
    std::atomic<bool> done{false};
    auto coro_fn = [&done]() -> fast_task::task_coro<void> {
        auto p = pipeline();
        fast_task::scheduler::start(p.get_task());
        int result = co_await p;
        EXPECT_EQ(result, 3);
        done = true;
        co_return;
    };
    auto coro = coro_fn();
    fast_task::scheduler::start(coro.get_task());
    coro->await_task();
    EXPECT_TRUE(done.load());
}
