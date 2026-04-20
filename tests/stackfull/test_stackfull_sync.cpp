// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>
#include <atomic>

class StackfullSyncTest : public SchedulerFixture {};

// ---- task_mutex shared between tasks ----

TEST_F(StackfullSyncTest, TaskMutexMutualExclusion) {
    fast_task::task_mutex mtx;
    int value = 0;

    auto worker = [&] {
        fast_task::lock_guard<fast_task::task_mutex> lk(mtx);
        int v = value;
        fast_task::this_task::yield();
        value = v + 1;
    };

    auto t1 = std::make_shared<fast_task::task>(worker);
    auto t2 = std::make_shared<fast_task::task>(worker);
    auto t3 = std::make_shared<fast_task::task>(worker);
    fast_task::scheduler::start(t1);
    fast_task::scheduler::start(t2);
    fast_task::scheduler::start(t3);
    std::vector<std::shared_ptr<fast_task::task>> tasks3{t1, t2, t3};
    fast_task::task::await_multiple(tasks3, true);

    EXPECT_EQ(value, 3);
}

// ---- task_condition_variable ----

TEST_F(StackfullSyncTest, TaskCVWakesSleeper) {
    fast_task::task_mutex mtx;
    fast_task::task_condition_variable cv;
    bool ready = false;

    auto waiter = std::make_shared<fast_task::task>([&] {
        fast_task::mutex_unify mu(mtx);
        fast_task::unique_lock<fast_task::mutex_unify> lk(mu);
        while (!ready)
            cv.wait(lk);
    });

    auto notifier = std::make_shared<fast_task::task>([&] {
        fast_task::this_task::sleep_for(std::chrono::milliseconds(20));
        {
            fast_task::lock_guard<fast_task::task_mutex> lk(mtx);
            ready = true;
        }
        cv.notify_one();
    });

    fast_task::scheduler::start(waiter);
    fast_task::scheduler::start(notifier);
    std::vector<std::shared_ptr<fast_task::task>> wn{waiter, notifier};
    fast_task::task::await_multiple(wn, true);

    EXPECT_TRUE(ready);
}

// ---- task_semaphore ----

TEST_F(StackfullSyncTest, TaskSemaphoreThrottles) {
    fast_task::task_semaphore sem;
    sem.set_max_threshold(2); // allow 2 concurrent holders
    std::atomic<int> concurrent{0};
    std::atomic<int> max_concurrent{0};

    auto worker = [&] {
        sem.lock();
        int c = ++concurrent;
        int expected = max_concurrent.load();
        while (expected < c && !max_concurrent.compare_exchange_weak(expected, c))
            ;
        fast_task::this_task::sleep_for(std::chrono::milliseconds(20));
        --concurrent;
        sem.release();
    };

    std::vector<std::shared_ptr<fast_task::task>> tasks;
    for (int i = 0; i < 5; ++i) {
        tasks.push_back(std::make_shared<fast_task::task>(worker));
        fast_task::scheduler::start(tasks.back());
    }
    fast_task::task::await_multiple(tasks, true);

    EXPECT_LE(max_concurrent.load(), 2);
}
