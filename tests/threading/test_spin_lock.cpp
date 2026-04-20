// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>
#include <threading.hpp>
#include <atomic>

TEST(SpinLock, BasicLockUnlock) {
    fast_task::spin_lock sl;
    sl.lock();
    sl.unlock();
}

TEST(SpinLock, TryLockSucceedsWhenFree) {
    fast_task::spin_lock sl;
    // spin_lock::try_lock() returns true on success (acquired), false on failure
    EXPECT_TRUE(sl.try_lock());
    sl.unlock();
}

TEST(SpinLock, TryLockFailsWhenHeld) {
    fast_task::spin_lock sl;
    sl.lock();
    bool result = true;
    fast_task::thread t([&] {
        result = sl.try_lock();
    });
    t.join();
    // spin_lock::try_lock() returns false when the lock is held (cannot acquire)
    EXPECT_FALSE(result);
    sl.unlock();
}

TEST(SpinLock, ContentionCounter) {
    fast_task::spin_lock sl;
    std::atomic<int> counter{0};
    auto worker = [&] {
        for (int i = 0; i < 10000; ++i) {
            sl.lock();
            ++counter;
            sl.unlock();
        }
    };
    fast_task::thread t1(worker);
    fast_task::thread t2(worker);
    t1.join();
    t2.join();
    EXPECT_EQ(counter.load(), 20000);
}
