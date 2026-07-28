// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <atomic>
#include <helpers.hpp>
#include <native.hpp>

TEST(LockGuard, AcquiresAndReleasesOnDestruct) {
    fast_task::native::mutex m;
    {
        fast_task::lock_guard lg(m);
        EXPECT_FALSE(m.try_lock());
    }
    EXPECT_TRUE(m.try_lock());
    m.unlock();
}

TEST(LockGuard, AdoptLock) {
    fast_task::native::mutex m;
    m.lock();
    {
        fast_task::lock_guard lg(m, fast_task::adopt_lock);
    }
    EXPECT_TRUE(m.try_lock());
    m.unlock();
}

TEST(UniqueLock, BasicLockUnlock) {
    fast_task::native::mutex m;
    fast_task::unique_lock ul(m);
    EXPECT_FALSE(m.try_lock());
    ul.unlock();
    EXPECT_TRUE(m.try_lock());
    m.unlock();
}

TEST(UniqueLock, DeferLock) {
    fast_task::native::mutex m;
    fast_task::unique_lock ul(m, fast_task::defer_lock);
    EXPECT_TRUE(m.try_lock());
    m.unlock();
    ul.lock();
    EXPECT_FALSE(m.try_lock());
    ul.unlock();
}

TEST(UniqueLock, TryLock) {
    fast_task::native::mutex m;
    fast_task::unique_lock ul(m, fast_task::defer_lock);
    EXPECT_TRUE(ul.try_lock());
    EXPECT_FALSE(m.try_lock());
    ul.unlock();
}

TEST(UniqueLock, DestructUnlocks) {
    fast_task::native::mutex m;
    {
        fast_task::unique_lock ul(m);
        EXPECT_FALSE(m.try_lock());
    }
    EXPECT_TRUE(m.try_lock());
    m.unlock();
}

TEST(SharedLock, BasicReadLockUnlock) {
    fast_task::native::rw_mutex m;
    {
        fast_task::shared_lock sl(m);
        EXPECT_TRUE(m.try_lock_shared());
        m.unlock_shared();
    }
    EXPECT_TRUE(m.try_lock());
    m.unlock();
}

TEST(SharedLock, DeferLock) {
    fast_task::native::rw_mutex m;
    fast_task::shared_lock sl(m, fast_task::defer_lock);
    EXPECT_TRUE(m.try_lock());
    m.unlock();
    sl.lock();
    sl.unlock();
}

TEST(RelockGuard, UnlocksAndRelocks) {
    fast_task::native::mutex m;
    m.lock();
    {
        fast_task::relock_guard rg(m);
        bool acquired = m.try_lock();
        if (acquired) m.unlock();
        EXPECT_TRUE(acquired);
    }
    m.unlock();
}
