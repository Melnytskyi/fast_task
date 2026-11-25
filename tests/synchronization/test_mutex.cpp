// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>
#include <atomic>

class TaskMutexTest : public SchedulerFixture {};

TEST_F(TaskMutexTest, BasicLockUnlock) {
    fast_task::mutex m;
    run_task([&] {
        m.lock();
        m.unlock();
    });
}

TEST_F(TaskMutexTest, IsLockedAndIsOwn) {
    fast_task::mutex m;
    run_task([&] {
        EXPECT_FALSE(m.is_locked());
        m.lock();
        EXPECT_TRUE(m.is_locked());
        EXPECT_TRUE(m.is_own());
        m.unlock();
        EXPECT_FALSE(m.is_locked());
    });
}

TEST_F(TaskMutexTest, TryLockSucceeds) {
    fast_task::mutex m;
    run_task([&] {
        EXPECT_TRUE(m.try_lock());
        EXPECT_TRUE(m.is_own());
        m.unlock();
    });
}

TEST_F(TaskMutexTest, TryLockFailsWhenHeld) {
    fast_task::mutex m;
    bool failed = false;
    run_task([&] {
        m.lock();
        auto t2 = fast_task::task::create([&] {
            failed = !m.try_lock();
        });
        fast_task::scheduler::start(t2);
        t2.await_task();
        m.unlock();
    });
    EXPECT_TRUE(failed);
}

TEST_F(TaskMutexTest, Contention) {
    fast_task::mutex m;
    std::atomic<int> counter{0};
    const int per_task = 500;

    auto worker = [&] {
        for (int i = 0; i < per_task; ++i) {
            m.lock();
            ++counter;
            m.unlock();
        }
    };

    run_task([&] {
        auto t1 = fast_task::task::create([&] { worker(); });
        auto t2 = fast_task::task::create([&] { worker(); });
        fast_task::scheduler::start(t1);
        fast_task::scheduler::start(t2);
        std::vector<fast_task::task> tasks2{t1, t2};
        fast_task::task::await_multiple(tasks2, true);
    });

    EXPECT_EQ(counter.load(), per_task * 2);
}

TEST_F(TaskMutexTest, TryLockForTimeout) {
    fast_task::mutex m;
    bool timed_out = false;

    run_task([&] {
        m.lock();

        auto t2 = fast_task::task::create([&] {
            timed_out = !m.try_lock_for(std::chrono::milliseconds(50)); // 50 ms
        });
        fast_task::scheduler::start(t2);
        fast_task::this_task::sleep_for(std::chrono::milliseconds(100));
        t2.await_task();
        m.unlock();
    });

    EXPECT_TRUE(timed_out);
}

TEST_F(TaskMutexTest, AsyncLock) {
    fast_task::mutex m;
    std::atomic<int> order{0};

    run_task([&] {
        m.lock();

        // stackful task blocks on m.lock() until outer releases it
        std::atomic<bool> t2_started{false};
        auto t2 = fast_task::task::create([&] {
            t2_started = true;
            m.lock();
            order = 2;
            m.unlock();
        });
        fast_task::scheduler::start(t2);

        // yield until t2 has started (it will then block on m.lock())
        while (!t2_started.load())
            fast_task::this_task::yield();

        order = 1;
        m.unlock(); // wakes t2

        t2.await_task();
    });

    EXPECT_EQ(order.load(), 2);
}

TEST_F(TaskMutexTest, TryLockUntilNoDeadlineReturnsFalseImmediately) {
    fast_task::mutex mtx;
    mtx.lock();

    bool locked = true;
    std::chrono::steady_clock::duration elapsed{};
    run_task([&] {
        const auto start = std::chrono::steady_clock::now();
        locked = mtx.try_lock_until(fast_task::no_deadline);
        elapsed = std::chrono::steady_clock::now() - start;
    });

    mtx.unlock();
    EXPECT_FALSE(locked);
    EXPECT_LT(elapsed, std::chrono::milliseconds(100));
}

TEST_F(TaskMutexTest, FutexHeadWaiterTimeoutWhileSecondRemains) {
    fast_task::mutex mtx;
    std::atomic<bool> t1_started{false};
    std::atomic<bool> t1_done{false};
    std::atomic<bool> t1_acquired{true};
    std::atomic<bool> t2_started{false};
    std::atomic<bool> t2_acquired{false};

    auto holder = fast_task::task::run([&] {
        mtx.lock();
        auto t1 = fast_task::task::run([&] {
            t1_started.store(true, std::memory_order_release);
            bool ok = mtx.try_lock_for(std::chrono::milliseconds(20));
            t1_acquired.store(ok, std::memory_order_release);
            if (ok)
                mtx.unlock();
            t1_done.store(true, std::memory_order_release);
        });
        while (!t1_started.load(std::memory_order_acquire))
            fast_task::this_task::yield();

        auto t2 = fast_task::task::run([&] {
            t2_started.store(true, std::memory_order_release);
            mtx.lock();
            t2_acquired.store(true, std::memory_order_release);
            mtx.unlock();
        });
        while (!t2_started.load(std::memory_order_acquire))
            fast_task::this_task::yield();

        while (!t1_done.load(std::memory_order_acquire))
            fast_task::this_task::sleep_for(std::chrono::milliseconds(5));

        mtx.unlock();
        t1.await_task();
        t2.await_task();
    });
    holder.await_task();
    EXPECT_FALSE(t1_acquired.load(std::memory_order_acquire));
    EXPECT_TRUE(t2_acquired.load(std::memory_order_acquire));
}