// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)
//
// Unit tests for fast_task::scheduler_event, the S1 eventcount
// (plans/pool-architecture.md §2.8). This is the primitive every idle path
// waits on, so its edge cases matter more than most: a lost wake here stalls a
// worker forever, and a spurious wake here burns a core.
//
// These tests reach the private headers under src/ (the CMake target adds
// ${CMAKE_SOURCE_DIR}/src to the include path), because the eventcount is an
// internal detail and must not become part of the public API just to be tested.

#include <atomic>
#include <chrono>
#include <cstdint>
#include <thread>
#include <vector>

#include <helpers.hpp>
#include <tasks/core/event.hpp>

namespace {
    using namespace std::chrono_literals;

    // Polls `pred` until it holds or `limit` elapses. Waiting on observable
    // state instead of sleeping makes the cooperative parts deterministic while
    // still bounding the test: a real hang fails the assertion, not the run.
    template <class Pred>
    bool eventually(Pred&& pred, std::chrono::milliseconds limit = 5000ms) {
        const auto deadline = fast_task::clock::now() + limit;
        while (!pred()) {
            if (fast_task::clock::now() >= deadline)
                return false;
            std::this_thread::sleep_for(1ms);
        }
        return true;
    }
}

// The core contract: a waiter parked with an unsatisfied predicate is woken by
// notify_one() and observes the producer's payload. The payload here is a plain
// atomic store made by the producer, which is exactly the ordering the epoch
// bump has to establish -- and the reason notify_one() may not take its
// `sleepers == 0` early-out until that store is ordered before the sleeper
// sample (see the fence in notify_one()).
TEST(SchedulerEvent, NotifyOneWakesWaiter) {
    fast_task::scheduler_event ev;
    std::atomic<bool> flag{false};
    std::atomic<bool> returned{false};

    std::thread waiter([&] {
        ev.wait([&] { return flag.load(std::memory_order_acquire); }, fast_task::time_point::max());
        returned.store(true);
    });

    // Park the waiter before notifying.
    ASSERT_TRUE(eventually([&] { return ev.has_sleepers(); }));

    flag.store(true, std::memory_order_release);
    ev.notify_one();

    EXPECT_TRUE(eventually([&] { return returned.load(); }, 2000ms));
    waiter.join();
}

// notify_one() must release exactly one of several sleepers. Waking everybody
// would defeat the point of the eventcount (every publish would stampede every
// idle worker), and the handoff predicate `!driver_lock.is_locked()` relies on
// the single-target behaviour.
TEST(SchedulerEvent, NotifyOneWakesExactlyOneWaiter) {
    fast_task::scheduler_event ev;
    std::atomic<bool> flag{false};
    std::atomic<int> released{0};
    std::atomic<int> entered{0};

    auto waiter = [&] {
        entered.fetch_add(1);
        ev.wait([&] { return flag.load(std::memory_order_acquire); }, fast_task::time_point::max());
        released.fetch_add(1);
    };

    std::thread a(waiter);
    std::thread b(waiter);

    // Both waiters must be parked, not merely started.
    ASSERT_TRUE(eventually([&] { return entered.load() == 2 && ev.has_sleepers(); }));
    std::this_thread::sleep_for(100ms);

    flag.store(true, std::memory_order_release);
    ev.notify_one();

    EXPECT_TRUE(eventually([&] { return released.load() >= 1; }, 2000ms));
    // Give a second wake the chance to show up if the implementation is wrong.
    std::this_thread::sleep_for(100ms);
    EXPECT_EQ(released.load(), 1);

    // The second waiter is still parked with a true predicate; notify_all() is
    // what releases it.
    ev.notify_all();
    EXPECT_TRUE(eventually([&] { return released.load() == 2; }, 2000ms));

    a.join();
    b.join();
}

TEST(SchedulerEvent, NotifyAllWakesEveryWaiter) {
    constexpr int N = 4;
    fast_task::scheduler_event ev;
    std::atomic<bool> flag{false};
    std::atomic<int> released{0};
    std::atomic<int> entered{0};
    std::vector<std::thread> waiters;

    for (int i = 0; i < N; ++i) {
        waiters.emplace_back([&] {
            entered.fetch_add(1);
            ev.wait([&] { return flag.load(std::memory_order_acquire); }, fast_task::time_point::max());
            released.fetch_add(1);
        });
    }

    ASSERT_TRUE(eventually([&] { return entered.load() == N && ev.has_sleepers(); }));
    std::this_thread::sleep_for(100ms);
    EXPECT_EQ(released.load(), 0);

    flag.store(true, std::memory_order_release);
    ev.notify_all();

    EXPECT_TRUE(eventually([&] { return released.load() == N; }, 3000ms));

    for (auto& t : waiters)
        t.join();
}

// A bounded wait must actually block for the requested time and then report the
// (still false) predicate. The idle paths cap their waits with the next timer
// deadline, so a broken timeout here turns into either a busy spin or a stalled
// timer.
TEST(SchedulerEvent, WaitTimesOut) {
    fast_task::scheduler_event ev;
    const auto start = fast_task::clock::now();
    const bool got = ev.wait([] { return false; }, start + 50ms);
    const auto elapsed = fast_task::clock::now() - start;

    EXPECT_FALSE(got);
    EXPECT_GE(elapsed, 40ms);
    EXPECT_LT(elapsed, 2000ms);
    // The sleeper must have deregistered itself on the way out, otherwise a
    // later notify would issue a pointless syscall forever.
    EXPECT_FALSE(ev.has_sleepers());
}

// A satisfied predicate must return immediately without parking. The driver's
// park path samples the epoch and *then* re-checks its predicate; if this
// short-circuit regressed, every poll would pay a sleep.
TEST(SchedulerEvent, SatisfiedPredicateDoesNotPark) {
    fast_task::scheduler_event ev;
    const auto start = fast_task::clock::now();
    const bool got = ev.wait([] { return true; }, fast_task::time_point::max());
    const auto elapsed = fast_task::clock::now() - start;

    EXPECT_TRUE(got);
    EXPECT_LT(elapsed, 50ms);
    EXPECT_FALSE(ev.has_sleepers());
}

// A notify that lands *before* the waiter parks must not be lost: the waiter
// samples the epoch, then checks the predicate, then re-checks both under the
// sleeper count. This is the "publish while the consumer is between the
// predicate check and the futex call" window, which is the only way a wake can
// be dropped in an eventcount.
TEST(SchedulerEvent, NoLostWakeWhenNotifiedBeforeWait) {
    for (int i = 0; i < 200; ++i) {
        fast_task::scheduler_event ev;
        std::atomic<bool> flag{false};

        // Bump the epoch first: the wake arrives before anybody is sleeping.
        ev.notify_one();
        flag.store(true, std::memory_order_release);

        const bool got = ev.wait([&] { return flag.load(std::memory_order_acquire); }, fast_task::clock::now() + 2000ms);
        ASSERT_TRUE(got) << "lost wake on iteration " << i;
    }
}

// The epoch is the witness the parked driver compares against its pre-poll
// snapshot, so a notify that reaches a sleeper must move it forward by exactly
// one step. A notify that finds nobody parked deliberately moves nothing: it
// costs no epoch bump and no system call, because a worker that is still
// running -- or still probing the queues before it parks -- observes the
// payload by itself. Both halves are asserted here because the second is what
// licenses the first, and dropping the bump while a sleeper *is* parked would
// silently reintroduce the lost wake.
TEST(SchedulerEvent, EpochAdvancesOnlyWhenSomebodyIsParked) {
    fast_task::scheduler_event ev;
    const uint32_t start = ev.current_epoch();

    // Nobody is parked: the hot enqueue path must leave the epoch untouched.
    ev.notify_one();
    EXPECT_EQ(ev.current_epoch(), start);
    EXPECT_FALSE(ev.has_sleepers());

    // notify_all() is not on the enqueue path -- it is the control broadcast --
    // so it stays unconditional and always advances.
    ev.notify_all();
    EXPECT_EQ(ev.current_epoch(), start + 1u);
    EXPECT_FALSE(ev.has_sleepers());

    // Now park a real waiter. The epoch must step exactly once for the notify
    // that releases it, and it must never repeat a value the driver may be
    // holding.
    std::atomic<bool> flag{false};
    std::atomic<bool> returned{false};
    std::thread waiter([&] {
        ev.wait([&] { return flag.load(std::memory_order_acquire); }, fast_task::time_point::max());
        returned.store(true);
    });
    ASSERT_TRUE(eventually([&] { return ev.has_sleepers(); }));

    const uint32_t before = ev.current_epoch();
    flag.store(true, std::memory_order_release);
    ev.notify_one();

    EXPECT_TRUE(eventually([&] { return returned.load(); }, 2000ms));
    waiter.join();
    EXPECT_EQ(ev.current_epoch(), before + 1u);
    EXPECT_FALSE(ev.has_sleepers());

    // With the sleeper gone the fast path is back: no bump, no wake.
    ev.notify_one();
    EXPECT_EQ(ev.current_epoch(), before + 1u);
}
