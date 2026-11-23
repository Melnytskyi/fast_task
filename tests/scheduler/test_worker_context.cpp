// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>
#include <atomic>
#include <chrono>
#include <thread>

namespace {
    struct joined_global {
        fast_task::scheduler::worker_context ctx;

        joined_global() {
            fast_task::scheduler::worker_pool::global().join_pool(ctx);
        }

        ~joined_global() {
            fast_task::scheduler::worker_pool::global().leave_pool(ctx);
        }

        joined_global(const joined_global&) = delete;
        joined_global& operator=(const joined_global&) = delete;

        fast_task::scheduler::worker_context& operator*() noexcept {
            return ctx;
        }

        fast_task::scheduler::worker_context* operator->() noexcept {
            return &ctx;
        }
    };
}

TEST(WorkerContext, ConstructAndDestruct) {
    {
        fast_task::scheduler::worker_context ctx;
        EXPECT_FALSE(ctx.is_joined());
        EXPECT_FALSE(ctx.is_shut_down());
    }

    {
        fast_task::scheduler::worker_context ctx;
        EXPECT_FALSE(ctx.is_joined());
    }
}

TEST(WorkerContext, UnjoinedPollThrows) {
    fast_task::scheduler::worker_context ctx;
    EXPECT_THROW(ctx.poll(1), std::logic_error);
    EXPECT_THROW(ctx.poll_all(), std::logic_error);
    EXPECT_THROW(ctx.poll_drained(), std::logic_error);
    EXPECT_THROW(ctx.poll_until(fast_task::clock::now()), std::logic_error);
    EXPECT_THROW(ctx.next(), std::logic_error);
    EXPECT_THROW(ctx.next_until(fast_task::clock::now()), std::logic_error);
}

TEST(WorkerContext, JoinAndLeave) {
    fast_task::scheduler::worker_context ctx;
    auto& pool = fast_task::scheduler::worker_pool::global();
    pool.join_pool(ctx);
    EXPECT_TRUE(ctx.is_joined());
    EXPECT_GE(pool.stats().foreign_workers, 1u);

    pool.leave_pool(ctx);
    EXPECT_FALSE(ctx.is_joined());

    EXPECT_THROW(ctx.poll(1), std::logic_error);
}


TEST(WorkerContext, DoubleJoinThrows) {
    fast_task::scheduler::worker_context first;
    fast_task::scheduler::worker_context second;
    fast_task::scheduler::worker_pool::global().join_pool(first);
    EXPECT_THROW(fast_task::scheduler::worker_pool::global().join_pool(second), std::logic_error);
    fast_task::scheduler::worker_pool::global().leave_pool(first);
}

TEST(WorkerContext, PollRunsTask) {
    joined_global context;

    std::atomic<int> ran{0};
    fast_task::task::create([&] { ran.fetch_add(1); }).start();

    auto deadline = fast_task::clock::now() + std::chrono::seconds(5);
    while (ran.load() == 0 && fast_task::clock::now() < deadline)
        context->poll(1);

    EXPECT_EQ(ran.load(), 1);
    fast_task::scheduler::shut_down();
}

TEST(WorkerContext, PollAllDrainsMany) {
    constexpr int N = 64;
    std::atomic<int> ran{0};
    for (int i = 0; i < N; ++i)
        fast_task::task::create([&] { ran.fetch_add(1); }).start();

    std::atomic<bool> registered{false};
    std::thread worker([&] {
        joined_global context;
        registered.store(true, std::memory_order_release);
        context->poll_all();
    });

    while (!registered.load(std::memory_order_acquire))
        std::this_thread::yield();

    auto deadline = fast_task::clock::now() + std::chrono::seconds(5);
    while (ran.load() < N && fast_task::clock::now() < deadline)
        std::this_thread::yield();

    EXPECT_EQ(ran.load(), N);

    fast_task::scheduler::shut_down();
    worker.join();
}

TEST(WorkerContext, NextUntilTimesOut) {
    joined_global context;

    auto start = fast_task::clock::now();
    bool got = context->next_until(start + std::chrono::milliseconds(50));
    auto elapsed = fast_task::clock::now() - start;

    EXPECT_FALSE(got);

    EXPECT_GE(elapsed, std::chrono::milliseconds(40));
    EXPECT_LT(elapsed, std::chrono::seconds(2));
}

TEST(WorkerContext, IdleOutsidePollDoesNotBlockStw) {
    ensure_global_workers(1);

    std::atomic<bool> stw_done{false};
    std::thread host([&] {
        joined_global context;

        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        context->poll(1);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    fast_task::scheduler::request_stw([&] { stw_done.store(true); });

    EXPECT_TRUE(stw_done.load());
    host.join();
    fast_task::scheduler::shut_down();
}

TEST(WorkerContext, StwWhilePollingIsObserved) {
    ensure_global_workers(1);

    std::atomic<bool> stop{false};
    std::atomic<size_t> polls{0};
    std::thread host([&] {
        joined_global context;
        while (!stop.load(std::memory_order_relaxed)) {
            context->poll(1);
            polls.fetch_add(1, std::memory_order_relaxed);
        }
    });

    for (int i = 0; i < 20; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
        std::atomic<bool> ran{false};
        fast_task::scheduler::request_stw([&] { ran.store(true); });
        EXPECT_TRUE(ran.load());
    }

    stop.store(true, std::memory_order_relaxed);
    host.join();
    EXPECT_GT(polls.load(), 0u);
    fast_task::scheduler::shut_down();
}

TEST(WorkerContext, PollDrainedReturnsWhenQueueEmpties) {
    joined_global context;

    constexpr int N = 32;
    std::atomic<int> ran{0};
    for (int i = 0; i < N; ++i)
        fast_task::scheduler::worker_pool::global().post(
            fast_task::task::create([&] { ran.fetch_add(1); })
        );

    auto start = fast_task::clock::now();
    size_t total = 0;
    auto deadline = start + std::chrono::seconds(5);
    while (ran.load() < N && fast_task::clock::now() < deadline)
        total += context->poll_drained();
    auto elapsed = fast_task::clock::now() - start;

    EXPECT_EQ(ran.load(), N);
    EXPECT_GE(total, static_cast<size_t>(N));

    EXPECT_LT(elapsed, std::chrono::seconds(5));
    fast_task::scheduler::shut_down();
}

TEST(WorkerContext, NextUntilWakesOnTaskArrival) {
    joined_global context;

    std::atomic<bool> ran{false};
    std::thread producer([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        fast_task::task::create([&] { ran.store(true); }).start();
    });

    auto start = fast_task::clock::now();
    bool got = context->next_until(start + std::chrono::seconds(2));
    auto elapsed = fast_task::clock::now() - start;

    producer.join();

    EXPECT_TRUE(got);
    EXPECT_TRUE(ran.load());

    EXPECT_LT(elapsed, std::chrono::milliseconds(1500));
    fast_task::scheduler::shut_down();
}

TEST(WorkerContext, PreventThreadNamingStillRunsTasks) {
    fast_task::scheduler::worker_context_options opts;
    opts.prevent_thread_naming = true;
    fast_task::scheduler::worker_context ctx(opts);
    fast_task::scheduler::worker_pool::global().join_pool(ctx);

    std::atomic<int> ran{0};
    fast_task::task::create([&] { ran.fetch_add(1); }).start();

    auto deadline = fast_task::clock::now() + std::chrono::seconds(5);
    while (ran.load() == 0 && fast_task::clock::now() < deadline)
        ctx.poll(1);

    EXPECT_EQ(ran.load(), 1);
    fast_task::scheduler::worker_pool::global().leave_pool(ctx);
    fast_task::scheduler::shut_down();
}

namespace {
    template <class Pred>
    bool eventual(Pred&& pred, std::chrono::milliseconds limit = std::chrono::seconds(5)) {
        const auto deadline = fast_task::clock::now() + limit;
        while (!pred()) {
            if (fast_task::clock::now() >= deadline)
                return false;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        return true;
    }
}

TEST(WorkerContext, WakeWhileDriverParked) {
    ensure_global_workers(1);

    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    std::atomic<bool> ran{false};
    const auto start = fast_task::clock::now();
    fast_task::task::create([&] { ran.store(true); }).start();

    const bool executed = eventual([&] { return ran.load(); });
    const auto elapsed = fast_task::clock::now() - start;

    EXPECT_TRUE(executed) << "parked driver was never woken";
    EXPECT_LT(elapsed, std::chrono::seconds(1));

    fast_task::scheduler::shut_down();
}

TEST(WorkerContext, TimerFiresWhileDriverParked) {
    ensure_global_workers(1);

    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    std::atomic<bool> ran{false};
    const auto start = fast_task::clock::now();
    fast_task::scheduler::schedule(
        fast_task::task::create([&] { ran.store(true); }),
        std::chrono::milliseconds(150)
    );

    const bool executed = eventual([&] { return ran.load(); });
    const auto elapsed = fast_task::clock::now() - start;

    EXPECT_TRUE(executed) << "timer was armed but nothing drove the wheel";
    EXPECT_GE(elapsed, std::chrono::milliseconds(100));
    EXPECT_LT(elapsed, std::chrono::seconds(2));

    fast_task::scheduler::shut_down();
}

TEST(WorkerContext, ShutDownWakesIdlePollAll) {
    std::atomic<bool> registered{false};
    std::atomic<bool> returned{false};
    std::thread worker([&] {
        joined_global context;
        registered.store(true, std::memory_order_release);
        context->poll_all();
        returned.store(true);
    });

    while (!registered.load(std::memory_order_acquire))
        std::this_thread::yield();
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    ASSERT_FALSE(returned.load());

    const auto start = fast_task::clock::now();
    fast_task::scheduler::shut_down();

    const bool woke = eventual([&] { return returned.load(); });
    const auto elapsed = fast_task::clock::now() - start;

    EXPECT_TRUE(woke) << "control-plane wake did not reach the parked worker";
    EXPECT_LT(elapsed, std::chrono::seconds(1));

    worker.join();
}
