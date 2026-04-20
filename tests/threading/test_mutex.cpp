// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>
#include <threading.hpp>
#include <atomic>
#include <thread>
#include <vector>

TEST(Mutex, BasicLockUnlock) {
    fast_task::mutex m;
    m.lock();
    m.unlock();
}

TEST(Mutex, TryLockSucceedsWhenFree) {
    fast_task::mutex m;
    EXPECT_TRUE(m.try_lock());
    m.unlock();
}

TEST(Mutex, TryLockFailsWhenHeld) {
    fast_task::mutex m;
    m.lock();
    // try_lock from a second thread
    bool result = true;
    fast_task::thread t([&] {
        result = m.try_lock();
    });
    t.join();
    EXPECT_FALSE(result);
    m.unlock();
}

TEST(Mutex, Contention) {
    fast_task::mutex m;
    std::atomic<int> counter{0};
    const int iterations = 10000;

    auto worker = [&] {
        for (int i = 0; i < iterations; ++i) {
            m.lock();
            ++counter;
            m.unlock();
        }
    };

    fast_task::thread t1(worker);
    fast_task::thread t2(worker);
    t1.join();
    t2.join();

    EXPECT_EQ(counter.load(), iterations * 2);
}
