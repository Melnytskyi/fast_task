// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>
#include <coroutine.hpp>
#include <atomic>

class CoroutineAwaitersTest : public SchedulerFixture {};

// ---- async_lock on mutex ----

fast_task::task_coro<void> coro_lock(fast_task::mutex& mtx, std::atomic<int>& val) {
    co_await async_lock(mtx);
    int v = val.load();
    // make yield
    val = v + 1;
    mtx.unlock();
    co_return;
}

TEST_F(CoroutineAwaitersTest, AsyncLockMutex) {
    fast_task::mutex mtx;
    std::atomic<int> val{0};

    auto c1 = coro_lock(mtx, val);
    auto c2 = coro_lock(mtx, val);
    auto c3 = coro_lock(mtx, val);

    fast_task::scheduler::start(c1.get_task());
    fast_task::scheduler::start(c2.get_task());
    fast_task::scheduler::start(c3.get_task());

    c1->await_task();
    c2->await_task();
    c3->await_task();

    EXPECT_EQ(val.load(), 3);
}

// ---- async_try_lock_for on mutex ----

fast_task::task_coro<bool> coro_try_lock_for_timeout(fast_task::mutex& mtx) {
    bool result = co_await async_try_lock_for(mtx, std::chrono::milliseconds(20));
    if (result) {
        mtx.unlock();
    }
    co_return result;
}

TEST_F(CoroutineAwaitersTest, AsyncTryLockForTimesOut) {
    fast_task::mutex mtx;
    mtx.lock();

    auto coro = coro_try_lock_for_timeout(mtx);
    fast_task::scheduler::start(coro.get_task());

    bool locked = coro.sync_get();
    EXPECT_FALSE(locked);
    mtx.unlock();
}

// ---- async_wait on condition_variable ----

fast_task::task_coro<void> coro_cv_wait(
    fast_task::mutex& mtx,
    fast_task::condition_variable& cv,
    bool& ready
) {
    co_await async_lock(mtx);
    fast_task::unique_lock lk(mtx, fast_task::adopt_lock);
    while (!ready)
        co_await async_wait(cv, lk);
    co_return;
}

TEST_F(CoroutineAwaitersTest, AsyncWaitCV) {
    fast_task::mutex mtx;
    fast_task::condition_variable cv;
    bool ready = false;

    auto coro = coro_cv_wait(mtx, cv, ready);
    fast_task::scheduler::start(coro.get_task());

    run_task([&] {
        fast_task::this_task::sleep_for(std::chrono::milliseconds(20));
        {
            fast_task::lock_guard<fast_task::mutex> lk(mtx);
            ready = true;
        }
        cv.notify_one();
    });

    coro->await_task();
    EXPECT_TRUE(ready);
}

// ---- async_read_lock / async_write_lock on rw_mutex ----

fast_task::task_coro<void> coro_rw_read(fast_task::rw_mutex& mtx, std::atomic<int>& reads) {
    co_await async_read_lock(mtx);
    ++reads;

    --reads;
    mtx.read_unlock();
    co_return;
}

fast_task::task_coro<void> coro_rw_write(fast_task::rw_mutex& mtx, int& value, int newval) {
    co_await async_write_lock(mtx);
    value = newval;
    mtx.write_unlock();
    co_return;
}

TEST_F(CoroutineAwaitersTest, AsyncReadLockMultipleReaders) {
    fast_task::rw_mutex mtx;
    std::atomic<int> reads{0};

    auto r1 = coro_rw_read(mtx, reads);
    auto r2 = coro_rw_read(mtx, reads);

    fast_task::scheduler::start(r1.get_task());
    fast_task::scheduler::start(r2.get_task());

    r1->await_task();
    r2->await_task();

    EXPECT_EQ(reads.load(), 0);
}

TEST_F(CoroutineAwaitersTest, AsyncWriteLock) {
    fast_task::rw_mutex mtx;
    int value = 0;

    auto w = coro_rw_write(mtx, value, 77);
    fast_task::scheduler::start(w.get_task());
    w->await_task();

    EXPECT_EQ(value, 77);
}
