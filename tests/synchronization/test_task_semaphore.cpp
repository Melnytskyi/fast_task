// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>
#include <atomic>

class TaskSemaphoreTest : public SchedulerFixture {};

TEST_F(TaskSemaphoreTest, BasicLockRelease) {
    fast_task::task_semaphore sem;
    sem.set_max_threshold(1);
    run_task([&] {
        sem.lock();
        EXPECT_TRUE(sem.is_locked());
        sem.release();
        EXPECT_FALSE(sem.is_locked());
    });
}

TEST_F(TaskSemaphoreTest, TryLockSucceeds) {
    fast_task::task_semaphore sem;
    sem.set_max_threshold(1);
    run_task([&] {
        EXPECT_TRUE(sem.try_lock());
        sem.release();
    });
}

TEST_F(TaskSemaphoreTest, CountingThreshold) {
    fast_task::task_semaphore sem;
    sem.set_max_threshold(3);
    run_task([&] {
        sem.lock();
        sem.lock();
        sem.lock();
        EXPECT_TRUE(sem.is_locked());
        // 4th lock would block — verify try_lock fails
        EXPECT_FALSE(sem.try_lock());
        sem.release();
        sem.release();
        sem.release();
    });
}

TEST_F(TaskSemaphoreTest, ReleaseAll) {
    fast_task::task_semaphore sem;
    sem.set_max_threshold(3);
    run_task([&] {
        sem.lock();
        sem.lock();
        sem.lock();
        sem.release_all();
        EXPECT_FALSE(sem.is_locked());
    });
}

TEST_F(TaskSemaphoreTest, WaiterUnblocked) {
    fast_task::task_semaphore sem;
    sem.set_max_threshold(1);
    std::atomic<bool> second_done{false};
    std::atomic<bool> holder_locked{false};

    auto holder = std::make_shared<fast_task::task>([&] {
        sem.lock(); // fill the semaphore
        holder_locked = true;
        fast_task::this_task::sleep_for(std::chrono::milliseconds(20));
        sem.release(); // unblock waiter
    });
    fast_task::scheduler::start(holder);

    while (!holder_locked.load())
        fast_task::this_thread::yield();

    auto waiter = std::make_shared<fast_task::task>([&] {
        sem.lock(); // should block until release
        second_done = true;
        sem.release();
    });
    fast_task::scheduler::start(waiter);

    std::vector<std::shared_ptr<fast_task::task>> tasks{holder, waiter};
    fast_task::task::await_multiple(tasks, true);

    EXPECT_TRUE(second_done.load());
}

TEST_F(TaskSemaphoreTest, TryLockForTimeout) {
    fast_task::task_semaphore sem;
    sem.set_max_threshold(1);
    bool timed_out = false;

    run_task([&] {
        sem.lock();
        auto t2 = std::make_shared<fast_task::task>([&] {
            timed_out = !sem.try_lock_for(std::chrono::milliseconds(50));
        });
        fast_task::scheduler::start(t2);
        fast_task::this_task::sleep_for(std::chrono::milliseconds(100));
        t2->await_task();
        sem.release();
    });

    EXPECT_TRUE(timed_out);
}
