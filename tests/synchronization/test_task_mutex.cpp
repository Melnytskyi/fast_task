// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>
#include <atomic>

class TaskMutexTest : public SchedulerFixture {};

TEST_F(TaskMutexTest, BasicLockUnlock) {
    fast_task::task_mutex m;
    run_task([&] {
        m.lock();
        m.unlock();
    });
}

TEST_F(TaskMutexTest, IsLockedAndIsOwn) {
    fast_task::task_mutex m;
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
    fast_task::task_mutex m;
    run_task([&] {
        EXPECT_TRUE(m.try_lock());
        EXPECT_TRUE(m.is_own());
        m.unlock();
    });
}

TEST_F(TaskMutexTest, TryLockFailsWhenHeld) {
    fast_task::task_mutex m;
    bool failed = false;
    run_task([&] {
        m.lock();
        auto t2 = std::make_shared<fast_task::task>([&] {
            failed = !m.try_lock();
        });
        fast_task::scheduler::start(t2);
        t2->await_task();
        m.unlock();
    });
    EXPECT_TRUE(failed);
}

TEST_F(TaskMutexTest, Contention) {
    fast_task::task_mutex m;
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
        auto t1 = std::make_shared<fast_task::task>([&] { worker(); });
        auto t2 = std::make_shared<fast_task::task>([&] { worker(); });
        fast_task::scheduler::start(t1);
        fast_task::scheduler::start(t2);
        std::vector<std::shared_ptr<fast_task::task>> tasks2{t1, t2};
        fast_task::task::await_multiple(tasks2, true);
    });

    EXPECT_EQ(counter.load(), per_task * 2);
}

TEST_F(TaskMutexTest, TryLockForTimeout) {
    fast_task::task_mutex m;
    bool timed_out = false;

    run_task([&] {
        m.lock();

        auto t2 = std::make_shared<fast_task::task>([&] {
            timed_out = !m.try_lock_for(std::chrono::milliseconds(50)); // 50 ms
        });
        fast_task::scheduler::start(t2);
        fast_task::this_task::sleep_for(std::chrono::milliseconds(100));
        t2->await_task();
        m.unlock();
    });

    EXPECT_TRUE(timed_out);
}

TEST_F(TaskMutexTest, AsyncLock) {
    fast_task::task_mutex m;
    std::atomic<int> order{0};

    run_task([&] {
        m.lock();

        // stackful task blocks on m.lock() until outer releases it
        std::atomic<bool> t2_started{false};
        auto t2 = std::make_shared<fast_task::task>([&] {
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

        t2->await_task();
    });

    EXPECT_EQ(order.load(), 2);
}
