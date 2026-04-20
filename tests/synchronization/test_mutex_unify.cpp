// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>

// mutex_unify wraps native and task-aware mutex types under a common interface.

TEST(MutexUnify, DefaultIsNull) {
    fast_task::mutex_unify mu;
    EXPECT_FALSE(static_cast<bool>(mu));
}

TEST(MutexUnify, WrapStdMutex) {
    std::mutex m;
    fast_task::mutex_unify mu(m);
    EXPECT_TRUE(static_cast<bool>(mu));
    mu.lock();
    mu.unlock();
}

TEST(MutexUnify, WrapFtMutex) {
    fast_task::mutex m;
    fast_task::mutex_unify mu(m);
    mu.lock();
    mu.unlock();
}

TEST(MutexUnify, WrapSpinLock) {
    fast_task::spin_lock sl;
    fast_task::mutex_unify mu(sl);
    mu.lock();
    mu.unlock();
}

TEST(MutexUnify, WrapRwMutexWrite) {
    fast_task::rw_mutex m;
    fast_task::mutex_unify mu(m, true); // write mode
    mu.lock();
    mu.unlock();
}

TEST(MutexUnify, WrapRwMutexRead) {
    fast_task::rw_mutex m;
    fast_task::mutex_unify mu(m, false); // read mode
    mu.lock();
    mu.unlock();
}

TEST(MutexUnify, WrapRecursiveMutex) {
    fast_task::recursive_mutex m;
    fast_task::mutex_unify mu(m);
    mu.lock();
    mu.lock(); // recursive
    mu.unlock();
    mu.unlock();
}

class MutexUnifyTaskTest : public SchedulerFixture {};

TEST_F(MutexUnifyTaskTest, WrapTaskMutex) {
    fast_task::task_mutex m;
    run_task([&] {
        fast_task::mutex_unify mu(m);
        mu.lock();
        mu.unlock();
    });
}

TEST_F(MutexUnifyTaskTest, WrapTaskRwMutexWrite) {
    fast_task::task_rw_mutex m;
    run_task([&] {
        fast_task::mutex_unify mu(m, true);
        mu.lock();
        mu.unlock();
    });
}

TEST_F(MutexUnifyTaskTest, WrapTaskRecursiveMutex) {
    fast_task::task_recursive_mutex m;
    run_task([&] {
        fast_task::mutex_unify mu(m);
        mu.lock();
        mu.lock();
        mu.unlock();
        mu.unlock();
    });
}

TEST(MutexUnify, EqualityComparisonSameMutex) {
    fast_task::mutex m;
    fast_task::mutex_unify mu1(m);
    fast_task::mutex_unify mu2(m);
    EXPECT_TRUE(mu1 == m);
    EXPECT_TRUE(mu2 == m);
}
