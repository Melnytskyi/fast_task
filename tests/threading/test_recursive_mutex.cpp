// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>
#include <threading.hpp>
#include <atomic>

TEST(RecursiveMutex, BasicLockUnlock) {
    fast_task::recursive_mutex m;
    m.lock();
    m.unlock();
}

TEST(RecursiveMutex, ReentrantLock) {
    fast_task::recursive_mutex m;
    m.lock();
    m.lock(); // same thread — must not deadlock
    m.lock();
    m.unlock();
    m.unlock();
    m.unlock();
}

TEST(RecursiveMutex, TryLockSucceedsOnSameThread) {
    fast_task::recursive_mutex m;
    m.lock();
    EXPECT_TRUE(m.try_lock());
    m.unlock();
    m.unlock();
}

TEST(RecursiveMutex, TryLockFailsFromOtherThread) {
    fast_task::recursive_mutex m;
    m.lock();
    bool result = true;
    fast_task::thread t([&] {
        result = m.try_lock();
    });
    t.join();
    EXPECT_FALSE(result);
    m.unlock();
}

TEST(RecursiveMutex, RelockBeginEnd) {
    fast_task::recursive_mutex m;
    m.lock();
    m.lock(); // recursion depth 2

    // relock_begin saves depth (2) and reduces count to 1 — mutex still held
    fast_task::relock_state state = m.relock_begin();
    m.unlock(); // fully release (count → 0, underlying mutex unlocked)

    // now another thread can acquire
    bool acquired = false;
    fast_task::thread t([&] {
        if (m.try_lock()) {
            acquired = true;
            m.unlock();
        }
    });
    t.join();
    EXPECT_TRUE(acquired);

    m.lock();            // re-acquire at depth 1
    m.relock_end(state); // restores saved depth (2)
    m.unlock();
    m.unlock();
}

TEST(RecursiveMutex, Contention) {
    fast_task::recursive_mutex m;
    std::atomic<int> counter{0};
    auto worker = [&] {
        for (int i = 0; i < 5000; ++i) {
            m.lock();
            m.lock();
            ++counter;
            m.unlock();
            m.unlock();
        }
    };
    fast_task::thread t1(worker);
    fast_task::thread t2(worker);
    t1.join();
    t2.join();
    EXPECT_EQ(counter.load(), 10000);
}
