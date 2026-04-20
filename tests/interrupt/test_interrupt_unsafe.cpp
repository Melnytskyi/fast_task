// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <atomic>
#include <helpers.hpp>
#include <interput.hpp>

class InterruptUnsafeTest : public SchedulerFixture {};

TEST_F(InterruptUnsafeTest, RegionPreventsInterrupt) {
    std::atomic<bool> interrupted_inside{false};

    // Pre-cancel the task; inside interrupt_unsafe_region check_cancellation should NOT throw
    auto t = std::make_shared<fast_task::task>([&] {
        fast_task::interrupt_unsafe_region region;
        try {
            fast_task::this_task::check_cancellation();
        } catch (...) {
            interrupted_inside = true;
        }
    });
    t->notify_cancel();
    fast_task::scheduler::start(t);
    t->await_task();

    EXPECT_FALSE(interrupted_inside.load());
}

TEST_F(InterruptUnsafeTest, RegionLockUnlock) {
    run_task([&] {
        fast_task::interrupt_unsafe_region region;
        // double-lock is valid
        region.lock();
        region.unlock();
        region.unlock();
    });
}

TEST_F(InterruptUnsafeTest, LockSwap) {
    run_task([&] {
        fast_task::interrupt_unsafe_region r1;
        // lock_swap(n) swaps the current lock count with n and returns the old count
        std::size_t old = fast_task::interrupt_unsafe_region::lock_swap(0);
        // restore the original lock count
        fast_task::interrupt_unsafe_region::lock_swap(old);
    });
}

TEST_F(InterruptUnsafeTest, NestedRegions) {
    run_task([&] {
        fast_task::interrupt_unsafe_region outer;
        {
            fast_task::interrupt_unsafe_region inner;
            // nested: both hold the lock
        }
        // outer still holds lock
    });
}
