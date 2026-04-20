// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>
#include <threading.hpp>
#include <atomic>
#include <vector>

TEST(RwMutex, ExclusiveWrite) {
    fast_task::rw_mutex m;
    m.lock();
    m.unlock();
}

TEST(RwMutex, SharedRead) {
    fast_task::rw_mutex m;
    m.lock_shared();
    m.unlock_shared();
}

TEST(RwMutex, TryLockSharedSucceedsWhenFree) {
    fast_task::rw_mutex m;
    EXPECT_TRUE(m.try_lock_shared());
    m.unlock_shared();
}

TEST(RwMutex, TryLockExclusiveSucceedsWhenFree) {
    fast_task::rw_mutex m;
    EXPECT_TRUE(m.try_lock());
    m.unlock();
}

TEST(RwMutex, ConcurrentReaders) {
    fast_task::rw_mutex m;
    std::atomic<int> concurrent{0};
    std::atomic<int> max_concurrent{0};

    auto reader = [&] {
        m.lock_shared();
        int val = ++concurrent;
        int expected = max_concurrent.load();
        while (expected < val && !max_concurrent.compare_exchange_weak(expected, val))
            ;
        fast_task::this_thread::sleep_for(std::chrono::milliseconds(5));
        --concurrent;
        m.unlock_shared();
    };

    fast_task::thread t1(reader);
    fast_task::thread t2(reader);
    fast_task::thread t3(reader);
    t1.join();
    t2.join();
    t3.join();

    EXPECT_GT(max_concurrent.load(), 1); // at least 2 readers ran concurrently
}

TEST(RwMutex, WriterExcludesReaders) {
    fast_task::rw_mutex m;
    std::atomic<bool> writer_done{false};
    std::atomic<bool> reader_ran_during_write{false};

    m.lock(); // hold write lock from main thread

    fast_task::thread reader([&] {
        m.lock_shared();
        reader_ran_during_write = !writer_done.load();
        m.unlock_shared();
    });

    fast_task::this_thread::sleep_for(std::chrono::milliseconds(20));
    writer_done = true;
    m.unlock();

    reader.join();
    EXPECT_FALSE(reader_ran_during_write.load());
}
