// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <atomic>
#include <chrono>
#include <cstdint>
#include <thread>
#include <vector>

#include <helpers.hpp>
#include <tasks/core/notify/event.hpp>

namespace {
    using namespace std::chrono_literals;

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

TEST(SchedulerEvent, NotifyOneWakesWaiter) {
    fast_task::scheduler_event ev;
    std::atomic<bool> flag{false};
    std::atomic<bool> returned{false};

    std::thread waiter([&] {
        ev.wait([&] { return flag.load(std::memory_order_acquire); }, fast_task::time_point::max());
        returned.store(true);
    });

    ASSERT_TRUE(eventually([&] { return ev.has_sleepers(); }));

    flag.store(true, std::memory_order_release);
    ev.notify_one();

    EXPECT_TRUE(eventually([&] { return returned.load(); }, 2000ms));
    waiter.join();
}

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

    ASSERT_TRUE(eventually([&] { return entered.load() == 2 && ev.has_sleepers(); }));
    std::this_thread::sleep_for(100ms);

    flag.store(true, std::memory_order_release);
    ev.notify_one();

    EXPECT_TRUE(eventually([&] { return released.load() >= 1; }, 2000ms));
    std::this_thread::sleep_for(100ms);
    EXPECT_EQ(released.load(), 1);

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

TEST(SchedulerEvent, WaitTimesOut) {
    fast_task::scheduler_event ev;
    const auto start = fast_task::clock::now();
    const bool got = ev.wait([] { return false; }, start + 50ms);
    const auto elapsed = fast_task::clock::now() - start;

    EXPECT_FALSE(got);
    EXPECT_GE(elapsed, 40ms);
    EXPECT_LT(elapsed, 2000ms);

    EXPECT_FALSE(ev.has_sleepers());
}

TEST(SchedulerEvent, SatisfiedPredicateDoesNotPark) {
    fast_task::scheduler_event ev;
    const auto start = fast_task::clock::now();
    const bool got = ev.wait([] { return true; }, fast_task::time_point::max());
    const auto elapsed = fast_task::clock::now() - start;

    EXPECT_TRUE(got);
    EXPECT_LT(elapsed, 50ms);
    EXPECT_FALSE(ev.has_sleepers());
}

TEST(SchedulerEvent, NoLostWakeWhenNotifiedBeforeWait) {
    for (int i = 0; i < 200; ++i) {
        fast_task::scheduler_event ev;
        std::atomic<bool> flag{false};

        ev.notify_one();
        flag.store(true, std::memory_order_release);

        const bool got = ev.wait([&] { return flag.load(std::memory_order_acquire); }, fast_task::clock::now() + 2000ms);
        ASSERT_TRUE(got) << "lost wake on iteration " << i;
    }
}

TEST(SchedulerEvent, EpochAdvancesOnlyWhenSomebodyIsParked) {
    fast_task::scheduler_event ev;
    const uint32_t start = ev.current_epoch();

    ev.notify_one();
    EXPECT_EQ(ev.current_epoch(), start);
    EXPECT_FALSE(ev.has_sleepers());

    ev.notify_all();
    EXPECT_EQ(ev.current_epoch(), start + 1u);
    EXPECT_FALSE(ev.has_sleepers());

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

    ev.notify_one();
    EXPECT_EQ(ev.current_epoch(), before + 1u);
}

TEST(SchedulerEvent, SpinnerTicketIsBounded) {
    fast_task::scheduler_event ev;
    fast_task::spinner_ticket first(ev.line());
    fast_task::spinner_ticket second(ev.line());
    fast_task::spinner_ticket third(ev.line());

    EXPECT_TRUE(first.try_acquire(2));
    EXPECT_TRUE(second.try_acquire(2));
    EXPECT_FALSE(third.try_acquire(2));

    first.release();
    first.release();
    EXPECT_TRUE(third.try_acquire(2));
    EXPECT_EQ(fast_task::pool_park_line::spinners_in(ev.line().load(std::memory_order_relaxed)), 2);
    EXPECT_FALSE(ev.has_sleepers());
}

TEST(SchedulerEvent, SkippedWakeIsHandedOnByTheSpinner) {
    fast_task::scheduler_event ev;
    std::atomic<bool> flag{false};
    std::atomic<int> released{0};

    std::thread waiter([&] {
        ev.wait([&] { return flag.load(std::memory_order_acquire); }, fast_task::time_point::max());
        released.fetch_add(1);
    });
    ASSERT_TRUE(eventually([&] { return ev.has_sleepers(); }));

    fast_task::spinner_ticket ticket(ev.line());
    ASSERT_TRUE(ticket.try_acquire(2));
    flag.store(true, std::memory_order_release);
    const uint32_t epoch_before = ev.current_epoch();
    EXPECT_TRUE(ev.notify_one());
    std::this_thread::sleep_for(50ms);
    EXPECT_EQ(released.load(), 0);
    EXPECT_EQ(ev.current_epoch(), epoch_before);
    EXPECT_FALSE(ev.has_pending());

    ticket.release();
    ev.cascade();
    EXPECT_TRUE(eventually([&] { return released.load() == 1; }, 2000ms));
    waiter.join();
}

TEST(SchedulerEvent, CascadeReleasesSecondSleeper) {
    fast_task::scheduler_event ev;
    std::atomic<int> units{0};
    std::atomic<int> released{0};

    auto consumer = [&] {
        ev.wait([&] { return units.load(std::memory_order_acquire) != 0; }, fast_task::time_point::max());
        units.fetch_sub(1);
        released.fetch_add(1);
    };
    std::thread a(consumer);
    std::thread b(consumer);
    ASSERT_TRUE(eventually([&] { return ev.line().sleepers() == 2; }));

    units.store(2, std::memory_order_release);
    EXPECT_TRUE(ev.notify_one());
    EXPECT_TRUE(eventually([&] { return released.load() == 1; }, 2000ms));

    std::this_thread::sleep_for(50ms);
    EXPECT_TRUE(ev.has_pending());
    ev.notify_one();
    std::this_thread::sleep_for(50ms);
    EXPECT_EQ(released.load(), 1);

    ev.cascade();
    EXPECT_TRUE(eventually([&] { return released.load() == 2; }, 2000ms));
    EXPECT_EQ(units.load(), 0);

    a.join();
    b.join();
}
