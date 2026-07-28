// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>
#include <atomic>

class TaskLimiterTest : public SchedulerFixture {};

TEST_F(TaskLimiterTest, BasicLockUnlock) {
    fast_task::limiter lim;
    lim.set_max_threshold(1);
    EXPECT_FALSE(lim.is_locked());
    run_task([&] {
        EXPECT_FALSE(lim.is_locked());
        lim.lock();
        EXPECT_TRUE(lim.is_locked());
        lim.unlock();
        EXPECT_FALSE(lim.is_locked());
    });
}

TEST_F(TaskLimiterTest, TryLockSucceeds) {
    fast_task::limiter lim;
    lim.set_max_threshold(1);
    EXPECT_FALSE(lim.is_locked());
    run_task([&] {
        EXPECT_TRUE(lim.try_lock());
        EXPECT_TRUE(lim.is_locked());
        lim.unlock();
        EXPECT_FALSE(lim.is_locked());
    });
}

TEST_F(TaskLimiterTest, TryLockFailsAtThreshold) {
    fast_task::limiter lim;
    lim.set_max_threshold(1);
    bool failed = false;
    run_task([&] {
        lim.lock();
        auto t2 = fast_task::task::create([&] {
            failed = !lim.try_lock();
        });
        fast_task::scheduler::start(t2);
        t2.await_task();
        lim.unlock();
    });
    EXPECT_TRUE(failed);
}

TEST_F(TaskLimiterTest, WaiterUnblockedOnUnlock) {
    fast_task::limiter lim;
    lim.set_max_threshold(1);
    std::atomic<bool> waiter_done{false};
    std::atomic<bool> holder_locked{false};

    auto holder = fast_task::task::create([&] {
        lim.lock();
        holder_locked = true;
        fast_task::this_task::sleep_for(std::chrono::milliseconds(20));
        lim.unlock();
    });
    fast_task::scheduler::start(holder);

    while (!holder_locked.load())
        fast_task::native::this_thread::yield();

    auto waiter = fast_task::task::create([&] {
        lim.lock();
        waiter_done = true;
        lim.unlock();
    });
    fast_task::scheduler::start(waiter);

    std::vector<fast_task::task> tasks{holder, waiter};
    fast_task::task::await_multiple(tasks, true);

    EXPECT_TRUE(waiter_done.load());
}

TEST_F(TaskLimiterTest, MultipleSlots) {
    fast_task::limiter lim;
    lim.set_max_threshold(3);
    std::atomic<int> locked_count{0};
    std::atomic<bool> release{false};


    auto make_holder = [&] {
        return fast_task::task::create([&] {
            lim.lock();
            locked_count.fetch_add(1);
            while (!release.load())
                fast_task::this_task::sleep_for(std::chrono::milliseconds(5));
            lim.unlock();
        });
    };

    auto t1 = make_holder();
    auto t2 = make_holder();
    auto t3 = make_holder();
    fast_task::scheduler::start(t1);
    fast_task::scheduler::start(t2);
    fast_task::scheduler::start(t3);


    while (locked_count.load() < 3)
        fast_task::native::this_thread::sleep_for(std::chrono::milliseconds(5));

    EXPECT_TRUE(lim.is_locked());


    bool fourth_failed = false;
    run_task([&] {
        fourth_failed = !lim.try_lock();
    });
    EXPECT_TRUE(fourth_failed);

    release = true;
    t1.await_task();
    t2.await_task();
    t3.await_task();
    EXPECT_FALSE(lim.is_locked());
}
