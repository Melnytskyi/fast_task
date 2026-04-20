// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>
#include <threading.hpp>
#include <atomic>

// ---- lock_guard ------------------------------------------------------------

TEST(LockGuard, AcquiresAndReleasesOnDestruct) {
    fast_task::mutex m;
    {
        fast_task::lock_guard<fast_task::mutex> lg(m);
        EXPECT_FALSE(m.try_lock()); // still held inside scope
    }
    EXPECT_TRUE(m.try_lock()); // released after destruct
    m.unlock();
}

TEST(LockGuard, AdoptLock) {
    fast_task::mutex m;
    m.lock();
    {
        fast_task::lock_guard<fast_task::mutex> lg(m, fast_task::adopt_lock);
        // lock_guard takes ownership without re-locking
    }
    // should be released now
    EXPECT_TRUE(m.try_lock());
    m.unlock();
}

// ---- unique_lock -----------------------------------------------------------

TEST(UniqueLock, BasicLockUnlock) {
    fast_task::mutex m;
    fast_task::unique_lock<fast_task::mutex> ul(m);
    EXPECT_FALSE(m.try_lock());
    ul.unlock();
    EXPECT_TRUE(m.try_lock());
    m.unlock();
}

TEST(UniqueLock, DeferLock) {
    fast_task::mutex m;
    fast_task::unique_lock<fast_task::mutex> ul(m, fast_task::defer_lock);
    EXPECT_TRUE(m.try_lock()); // mutex not yet locked by unique_lock
    m.unlock();
    ul.lock();
    EXPECT_FALSE(m.try_lock());
    ul.unlock();
}

TEST(UniqueLock, TryLock) {
    fast_task::mutex m;
    fast_task::unique_lock<fast_task::mutex> ul(m, fast_task::defer_lock);
    EXPECT_TRUE(ul.try_lock());
    EXPECT_FALSE(m.try_lock());
    ul.unlock();
}

TEST(UniqueLock, DestructUnlocks) {
    fast_task::mutex m;
    {
        fast_task::unique_lock<fast_task::mutex> ul(m);
        EXPECT_FALSE(m.try_lock());
    }
    EXPECT_TRUE(m.try_lock());
    m.unlock();
}

// ---- shared_lock -----------------------------------------------------------

TEST(SharedLock, BasicReadLockUnlock) {
    fast_task::rw_mutex m;
    {
        fast_task::shared_lock<fast_task::rw_mutex> sl(m);
        // multiple shared locks on same mutex should not block
        EXPECT_TRUE(m.try_lock_shared());
        m.unlock_shared();
    }
    EXPECT_TRUE(m.try_lock());
    m.unlock();
}

TEST(SharedLock, DeferLock) {
    fast_task::rw_mutex m;
    fast_task::shared_lock<fast_task::rw_mutex> sl(m, fast_task::defer_lock);
    EXPECT_TRUE(m.try_lock());
    m.unlock();
    sl.lock();
    sl.unlock();
}

// ---- relock_guard ----------------------------------------------------------

TEST(RelockGuard, UnlocksAndRelocks) {
    fast_task::mutex m;
    m.lock();
    {
        fast_task::relock_guard<fast_task::mutex> rg(m);
        // within relock_guard the mutex is unlocked
        bool acquired = m.try_lock();
        if (acquired) m.unlock();
        EXPECT_TRUE(acquired);
    }
    // relock_guard destructor re-locks
    m.unlock(); // should succeed — was relocked
}
