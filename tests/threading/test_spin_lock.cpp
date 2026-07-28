// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <atomic>
#include <helpers.hpp>
#include <native/spin_lock.hpp>
#include <native/thread.hpp>

TEST(SpinLock, BasicLockUnlock) {
    fast_task::native::spin_lock sl;
    sl.lock();
    sl.unlock();
}

TEST(SpinLock, TryLockSucceedsWhenFree) {
    fast_task::native::spin_lock sl;
    EXPECT_TRUE(sl.try_lock());
    sl.unlock();
}

TEST(SpinLock, TryLockFailsWhenHeld) {
    fast_task::native::spin_lock sl;
    sl.lock();
    bool result = true;
    fast_task::native::thread t([&] {
        result = sl.try_lock();
    });
    t.join();
    EXPECT_FALSE(result);
    sl.unlock();
}

TEST(SpinLock, ContentionCounter) {
    fast_task::native::spin_lock sl;
    std::atomic<int> counter{0};
    auto worker = [&] {
        for (int i = 0; i < 10000; ++i) {
            sl.lock();
            ++counter;
            sl.unlock();
        }
    };
    fast_task::native::thread t1(worker);
    fast_task::native::thread t2(worker);
    t1.join();
    t2.join();
    EXPECT_EQ(counter.load(), 20000);
}
