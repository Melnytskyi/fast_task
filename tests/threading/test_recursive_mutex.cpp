// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <atomic>
#include <helpers.hpp>
#include <native/mutex.hpp>

TEST(RecursiveMutex, BasicLockUnlock) {
    fast_task::native::recursive_mutex m;
    m.lock();
    m.unlock();
}

TEST(RecursiveMutex, ReentrantLock) {
    fast_task::native::recursive_mutex m;
    m.lock();
    m.lock();
    m.lock();
    m.unlock();
    m.unlock();
    m.unlock();
}

TEST(RecursiveMutex, TryLockSucceedsOnSameThread) {
    fast_task::native::recursive_mutex m;
    m.lock();
    EXPECT_TRUE(m.try_lock());
    m.unlock();
    m.unlock();
}

TEST(RecursiveMutex, TryLockFailsFromOtherThread) {
    fast_task::native::recursive_mutex m;
    m.lock();
    bool result = true;
    fast_task::native::thread t([&] {
        result = m.try_lock();
    });
    t.join();
    EXPECT_FALSE(result);
    m.unlock();
}

TEST(RecursiveMutex, RelockBeginEnd) {
    fast_task::native::recursive_mutex m;
    m.lock();
    m.lock();

    auto state = m.relock_begin();
    m.unlock();

    bool acquired = false;
    fast_task::native::thread t([&] {
        if (m.try_lock()) {
            acquired = true;
            m.unlock();
        }
    });
    t.join();
    EXPECT_TRUE(acquired);

    m.lock();
    m.relock_end(state);
    m.unlock();
    m.unlock();
}

TEST(RecursiveMutex, Contention) {
    fast_task::native::recursive_mutex m;
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
    fast_task::native::thread t1(worker);
    fast_task::native::thread t2(worker);
    t1.join();
    t2.join();
    EXPECT_EQ(counter.load(), 10000);
}
