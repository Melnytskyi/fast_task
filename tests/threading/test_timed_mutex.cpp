// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>
#include <threading.hpp>

TEST(TimedMutex, BasicLockUnlock) {
    fast_task::timed_mutex m;
    m.lock();
    m.unlock();
}

TEST(TimedMutex, TryLockSucceedsWhenFree) {
    fast_task::timed_mutex m;
    EXPECT_TRUE(m.try_lock());
    m.unlock();
}

TEST(TimedMutex, TryLockForSucceeds) {
    fast_task::timed_mutex m;
    EXPECT_TRUE(m.try_lock_for(std::chrono::milliseconds(100)));
    m.unlock();
}

TEST(TimedMutex, TryLockForTimesOut) {
    fast_task::timed_mutex m;
    m.lock(); // held by this thread

    bool result = true;
    fast_task::thread t([&] {
        result = m.try_lock_for(std::chrono::milliseconds(30));
    });
    t.join();
    EXPECT_FALSE(result);
    m.unlock();
}

TEST(TimedMutex, TryLockUntilSucceeds) {
    fast_task::timed_mutex m;
    auto deadline = std::chrono::high_resolution_clock::now() + std::chrono::milliseconds(200);
    EXPECT_TRUE(m.try_lock_until(deadline));
    m.unlock();
}

TEST(TimedMutex, TryLockUntilTimesOut) {
    fast_task::timed_mutex m;
    m.lock();
    bool result = true;
    fast_task::thread t([&] {
        auto deadline = std::chrono::high_resolution_clock::now() + std::chrono::milliseconds(30);
        result = m.try_lock_until(deadline);
    });
    t.join();
    EXPECT_FALSE(result);
    m.unlock();
}
