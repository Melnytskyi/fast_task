// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>
#include <atomic>

TEST(MultiplyMutex, LockUnlockTwoMutexes) {
    fast_task::mutex m1, m2;
    fast_task::multiply_mutex mm({m1, m2});
    mm.lock();
    mm.unlock();
}

TEST(MultiplyMutex, TryLock) {
    fast_task::mutex m1, m2;
    fast_task::multiply_mutex mm({m1, m2});
    EXPECT_TRUE(mm.try_lock());
    mm.unlock();
}

TEST(MultiplyMutex, TryLockFailsWhenOneHeld) {
    fast_task::mutex m1, m2;
    m2.lock();
    fast_task::multiply_mutex mm({m1, m2});
    bool result = mm.try_lock();
    if (result) mm.unlock();
    m2.unlock();
    EXPECT_FALSE(result);
}

TEST(MultiplyMutex, TryLockFor) {
    fast_task::mutex m1, m2;
    fast_task::multiply_mutex mm({m1, m2});
    EXPECT_TRUE(mm.try_lock_for(100));
    mm.unlock();
}

TEST(MultiplyMutex, ThreeMutexes) {
    fast_task::mutex m1, m2;
    fast_task::spin_lock sl;
    fast_task::multiply_mutex mm({
        fast_task::mutex_unify(m1),
        fast_task::mutex_unify(m2),
        fast_task::mutex_unify(sl)
    });
    mm.lock();
    mm.unlock();
}

TEST(MultiplyMutex, Contention) {
    fast_task::mutex m1, m2;
    fast_task::multiply_mutex mm({m1, m2});
    std::atomic<int> counter{0};

    auto worker = [&] {
        for (int i = 0; i < 1000; ++i) {
            mm.lock();
            ++counter;
            mm.unlock();
        }
    };

    fast_task::thread t1(worker);
    fast_task::thread t2(worker);
    t1.join();
    t2.join();
    EXPECT_EQ(counter.load(), 2000);
}
