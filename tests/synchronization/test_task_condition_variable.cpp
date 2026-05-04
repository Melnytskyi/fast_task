// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>
#include <atomic>

class TaskCvTest : public SchedulerFixture {};

TEST_F(TaskCvTest, WaitAndNotifyOne) {
    fast_task::task_mutex m;
    fast_task::task_condition_variable cv;
    bool ready = false;

    run_task([&] {
        auto waiter = std::make_shared<fast_task::task>([&] {
            fast_task::mutex_unify um(m);
            fast_task::unique_lock<fast_task::mutex_unify> lock(um);
            while (!ready)
                cv.wait(lock);
        });
        fast_task::scheduler::start(waiter);

        fast_task::this_task::sleep_for(std::chrono::milliseconds(20));
        {
            fast_task::lock_guard<fast_task::task_mutex> lg(m);
            ready = true;
        }
        cv.notify_one();

        waiter->await_task();
    });

    EXPECT_TRUE(ready);
}

TEST_F(TaskCvTest, NotifyAll) {
    fast_task::task_mutex m;
    fast_task::task_condition_variable cv;
    std::atomic<int> woken{0};
    bool go = false;

    auto waiter_fn = [&] {
        fast_task::mutex_unify um(m);
        fast_task::unique_lock<fast_task::mutex_unify> lock(um);
        while (!go)
            cv.wait(lock);
        ++woken;
    };

    run_task([&] {
        auto t1 = std::make_shared<fast_task::task>([&] { waiter_fn(); });
        auto t2 = std::make_shared<fast_task::task>([&] { waiter_fn(); });
        auto t3 = std::make_shared<fast_task::task>([&] { waiter_fn(); });
        fast_task::scheduler::start(t1);
        fast_task::scheduler::start(t2);
        fast_task::scheduler::start(t3);

        fast_task::this_task::sleep_for(std::chrono::milliseconds(20));
        {
            fast_task::lock_guard<fast_task::task_mutex> lg(m);
            go = true;
        }
        cv.notify_all();

        std::vector<std::shared_ptr<fast_task::task>> tasks3{t1, t2, t3};
        fast_task::task::await_multiple(tasks3, true);
    });

    EXPECT_EQ(woken.load(), 3);
}

TEST_F(TaskCvTest, WaitForTimeout) {
    fast_task::task_mutex m;
    fast_task::task_condition_variable cv;
    bool timed_out = false;

    run_task([&] {
        fast_task::mutex_unify um(m);
        fast_task::unique_lock<fast_task::mutex_unify> lock(um);
        timed_out = !cv.wait_for(lock, std::chrono::milliseconds(50));
    });

    EXPECT_TRUE(timed_out);
}

TEST_F(TaskCvTest, HasWaiters) {
    fast_task::task_mutex m;
    fast_task::task_condition_variable cv;
    std::atomic<bool> waiter_in{false};
    bool notify = false;

    run_task([&] {
        auto waiter = std::make_shared<fast_task::task>([&] {
            fast_task::mutex_unify um(m);
            fast_task::unique_lock<fast_task::mutex_unify> lock(um);
            waiter_in = true;
            while (!notify)
                cv.wait(lock);
        });
        fast_task::scheduler::start(waiter);

        // yield until waiter is blocking
        while (!cv.has_waiters())
            fast_task::this_task::yield();

        EXPECT_TRUE(cv.has_waiters());

        {
            fast_task::lock_guard<fast_task::task_mutex> lg(m);
            notify = true;
        }
        cv.notify_one();
        waiter->await_task();
    });

    EXPECT_FALSE(cv.has_waiters());
}

TEST_F(TaskCvTest, AsyncWait) {
    fast_task::task_mutex m;
    fast_task::task_condition_variable cv;
    bool ready = false;
    bool completed = false;

    run_task([&] {
        auto coro = [](auto& m, auto& cv, auto& ready, auto& completed) -> fast_task::task_coro<void> {
            fast_task::mutex_unify um(m);
            co_await async_lock(m);
            fast_task::unique_lock<fast_task::mutex_unify> lock(um, fast_task::adopt_lock);
            while (!ready)
                co_await async_wait(cv, lock);
            completed = true;
            co_return;
        }(m, cv, ready, completed);
        fast_task::scheduler::start(coro.get_task());

        fast_task::this_task::sleep_for(std::chrono::milliseconds(50));
        {
            fast_task::lock_guard<fast_task::task_mutex> lg(m);
            ready = true;
        }
        cv.notify_one();
        coro->await_task();
    });

    EXPECT_TRUE(completed);
}
