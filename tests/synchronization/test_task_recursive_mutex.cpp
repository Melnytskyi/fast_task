// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>
#include <atomic>

class TaskRecursiveMutexTest : public SchedulerFixture {};

TEST_F(TaskRecursiveMutexTest, BasicLockUnlock) {
    fast_task::task_recursive_mutex m;
    run_task([&] {
        m.lock();
        m.unlock();
    });
}

TEST_F(TaskRecursiveMutexTest, ReentrantFromSameTask) {
    fast_task::task_recursive_mutex m;
    run_task([&] {
        m.lock();
        m.lock(); // must not deadlock
        m.lock();
        m.unlock();
        m.unlock();
        m.unlock();
    });
}

TEST_F(TaskRecursiveMutexTest, TryLockFromSameTask) {
    fast_task::task_recursive_mutex m;
    run_task([&] {
        m.lock();
        EXPECT_TRUE(m.try_lock()); // recursive — should succeed
        m.unlock();
        m.unlock();
    });
}

TEST_F(TaskRecursiveMutexTest, ContentionFromDifferentTask) {
    fast_task::task_recursive_mutex m;
    std::atomic<int> counter{0};
    const int per_task = 200;

    auto worker = [&] {
        for (int i = 0; i < per_task; ++i) {
            m.lock();
            m.lock();
            ++counter;
            m.unlock();
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

TEST_F(TaskRecursiveMutexTest, IsOwn) {
    fast_task::task_recursive_mutex m;
    run_task([&] {
        m.lock();
        EXPECT_TRUE(m.is_own());
        m.unlock();
    });
}
