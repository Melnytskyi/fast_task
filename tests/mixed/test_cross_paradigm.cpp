// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>
#include <coroutine.hpp>
#include <future.hpp>
#include <atomic>

class CrossParadigmTest : public SchedulerFixture {};

// ---- stackful task awaiting future<T> ----

TEST_F(CrossParadigmTest, StackfulTaskAwaitsIntFuture) {
    int result = 0;
    run_task([&] {
        auto f = fast_task::future<int>::start([] { return 99; });
        result = f->get();
    });
    EXPECT_EQ(result, 99);
}

TEST_F(CrossParadigmTest, StackfulTaskAwaitsVoidFuture) {
    std::atomic<bool> ran{false};
    run_task([&] {
        auto f = fast_task::future<void>::start([&] { ran = true; });
        f->wait();
    });
    EXPECT_TRUE(ran.load());
}

// ---- coroutine awaiting future<T> ----

fast_task::task_coro<int> coro_awaits_future() {
    auto f = fast_task::future<int>::start([] { return 77; });
    co_return co_await f;
}

TEST_F(CrossParadigmTest, CoroutineAwaitsIntFuture) {
    auto coro = coro_awaits_future();
    fast_task::scheduler::start(coro.get_task());
    coro->await_task();

    int result = 0;
    coro->access_dummy([&](void* addr) {
        auto h = std::coroutine_handle<fast_task::task_promise<int>>::from_address(addr);
        result = h.promise().result();
    });
    EXPECT_EQ(result, 77);
}

// ---- native thread waiting on future started by coroutine ----

fast_task::task_coro<void> coro_starts_future(fast_task::future_ptr<int>& out_future) {
    out_future = fast_task::future<int>::start([] {
        fast_task::this_task::sleep_for(std::chrono::milliseconds(20));
        return 55;
    });
    co_return;
}

TEST_F(CrossParadigmTest, NativeThreadWaitsOnFutureStartedByCoroutine) {
    fast_task::future_ptr<int> f;

    auto coro = coro_starts_future(f);
    fast_task::scheduler::start(coro.get_task());
    coro->await_task(); // native thread waits for coroutine to set f

    ASSERT_NE(f, nullptr);
    // Now native thread blocks on the future
    EXPECT_EQ(f->get(), 55);
}

// ---- coroutine starting a stackful task and awaiting it ----

fast_task::task_coro<void> coro_spawns_task(std::atomic<bool>& ran) {
    auto t = std::make_shared<fast_task::task>([&] { ran = true; });
    fast_task::scheduler::start(t);
    co_await std::move(t);
}

TEST_F(CrossParadigmTest, CoroutineSpawnsAndAwaitsStackfulTask) {
    std::atomic<bool> ran{false};
    auto coro = coro_spawns_task(ran);
    fast_task::scheduler::start(coro.get_task());
    coro->await_task();
    EXPECT_TRUE(ran.load());
}
