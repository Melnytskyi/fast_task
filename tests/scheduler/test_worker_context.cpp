// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>
#include <atomic>
#include <chrono>
#include <thread>

// scheduler::worker_context lets a foreign thread (UI loop, game loop) run
// tasks without becoming a permanent scheduler thread. The critical property
// is the STW quiescent state: the thread is only counted as active while it is
// inside poll*()/next*(), so request_stw() must never wait for a thread that is
// parked outside the scheduler.

TEST(WorkerContext, ConstructAndDestruct) {
    {
        fast_task::scheduler::worker_context ctx;
        EXPECT_FALSE(ctx.is_shut_down());
    }
    // A second context on the same thread must be allowed once the first is gone.
    {
        fast_task::scheduler::worker_context ctx;
        EXPECT_FALSE(ctx.is_shut_down());
    }
}

TEST(WorkerContext, DoubleConstructThrows) {
    fast_task::scheduler::worker_context ctx;
    EXPECT_THROW(fast_task::scheduler::worker_context second, std::logic_error);
}

TEST(WorkerContext, PollRunsTask) {
    fast_task::scheduler::worker_context ctx;

    std::atomic<int> ran{0};
    // create() only allocates the task; start() is what enqueues it.
    fast_task::task::create([&] { ran.fetch_add(1); }).start();

    auto deadline = fast_task::clock::now() + std::chrono::seconds(5);
    while (ran.load() == 0 && fast_task::clock::now() < deadline)
        ctx.poll(1);

    EXPECT_EQ(ran.load(), 1);
}

// poll_all() serves until shutdown, so it must be driven from a thread that is
// shut down afterwards; it is not a "drain and return" call. This exercises the
// many-task drain path through poll_all() and then shuts the scheduler down so
// the call can return.
TEST(WorkerContext, PollAllDrainsMany) {
    constexpr int N = 64;
    std::atomic<int> ran{0};
    for (int i = 0; i < N; ++i)
        fast_task::task::create([&] { ran.fetch_add(1); }).start();

    std::atomic<bool> registered{false};
    std::thread worker([&] {
        fast_task::scheduler::worker_context ctx;
        registered.store(true, std::memory_order_release);
        ctx.poll_all();
    });

    // shut_down() can only wait for the worker contexts that exist when it
    // drains them. A thread that has not constructed its worker_context yet is
    // invisible to that drain: if it registers after shut_down() has reset
    // executor_shutting_down, its poll_all() parks as the driver with an
    // infinite timeout and never returns, and join() hangs. Measured as a
    // 1-in-250 hang of this test on a loaded machine (the core showed the
    // thread inside io_uring in park_until while shut_down() had already
    // returned). So the context has to be up before the drain starts.
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
    fast_task::scheduler::worker_context ctx;

    auto start = fast_task::clock::now();
    bool got = ctx.next_until(start + std::chrono::milliseconds(50));
    auto elapsed = fast_task::clock::now() - start;

    EXPECT_FALSE(got);
    // Must actually wait, but not much longer than asked.
    EXPECT_GE(elapsed, std::chrono::milliseconds(40));
    EXPECT_LT(elapsed, std::chrono::seconds(2));
}

// The regression this whole phase exists for: a worker_context that is idle
// *outside* poll() must not block request_stw(). Before the stw_active_guard
// change, the context incremented glob.thread_count for its whole lifetime and
// request_stw() deadlocked waiting for a thread parked in the host's event loop.
TEST(WorkerContext, IdleOutsidePollDoesNotBlockStw) {
    fast_task::scheduler::create_executor(1);
    while (fast_task::scheduler::total_executors() < 1u)
        std::this_thread::yield();

    std::atomic<bool> stw_done{false};
    std::thread host([&] {
        fast_task::scheduler::worker_context ctx;
        // Simulate a UI thread: sit outside the scheduler for a while.
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        // Then poll once so the context is exercised.
        ctx.poll(1);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // This must complete promptly even though the host thread is alive and
    // parked outside poll().
    fast_task::scheduler::request_stw([&] { stw_done.store(true); });

    EXPECT_TRUE(stw_done.load());
    host.join();
    fast_task::scheduler::shut_down();
}

TEST(WorkerContext, StwWhilePollingIsObserved) {
    fast_task::scheduler::create_executor(1);
    while (fast_task::scheduler::total_executors() < 1u)
        std::this_thread::yield();

    std::atomic<bool> stop{false};
    std::atomic<size_t> polls{0};
    std::thread host([&] {
        fast_task::scheduler::worker_context ctx;
        while (!stop.load(std::memory_order_relaxed)) {
            ctx.poll(1);
            polls.fetch_add(1, std::memory_order_relaxed);
        }
    });

    // Let the host spin in poll() for a moment, then request STW repeatedly.
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

// poll_drained() is the worker_context equivalent of
// taskExecutor(end_in_task_out = true): it must run what is runnable and then
// hand control back, instead of blocking until shutdown like poll_all().
TEST(WorkerContext, PollDrainedReturnsWhenQueueEmpties) {
    fast_task::scheduler::worker_context ctx;

    constexpr int N = 32;
    std::atomic<int> ran{0};
    for (int i = 0; i < N; ++i)
        fast_task::task::create([&] { ran.fetch_add(1); }).start();

    auto start = fast_task::clock::now();
    size_t total = 0;
    auto deadline = start + std::chrono::seconds(5);
    while (ran.load() < N && fast_task::clock::now() < deadline)
        total += ctx.poll_drained();
    auto elapsed = fast_task::clock::now() - start;

    EXPECT_EQ(ran.load(), N);
    EXPECT_GE(total, static_cast<size_t>(N));
    // The whole point: it returns. poll_all() would still be blocked here.
    EXPECT_LT(elapsed, std::chrono::seconds(5));
}

// A worker parked in next_until() must wake when a task arrives, not sleep the
// full timeout. Before the park_waiter removal nothing ever notified the
// waiter, so this always took the whole 2 seconds.
TEST(WorkerContext, NextUntilWakesOnTaskArrival) {
    fast_task::scheduler::worker_context ctx;

    std::atomic<bool> ran{false};
    std::thread producer([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        fast_task::task::create([&] { ran.store(true); }).start();
    });

    auto start = fast_task::clock::now();
    bool got = ctx.next_until(start + std::chrono::seconds(2));
    auto elapsed = fast_task::clock::now() - start;

    producer.join();

    EXPECT_TRUE(got);
    EXPECT_TRUE(ran.load());
    // Woken by the producer, not by the deadline.
    EXPECT_LT(elapsed, std::chrono::milliseconds(1500));
}

// prevent_thread_naming must be accepted and must not disturb the host thread.
// The name itself is only observable through the internal _get_name_thread_dbg
// helper, which would drag the third-party include path into this target, so
// this asserts the contract that matters here: the option is honoured and the
// context still works.
TEST(WorkerContext, PreventThreadNamingStillRunsTasks) {
    fast_task::scheduler::worker_options opts;
    opts.prevent_thread_naming = true;
    fast_task::scheduler::worker_context ctx(opts);

    std::atomic<int> ran{0};
    fast_task::task::create([&] { ran.fetch_add(1); }).start();

    auto deadline = fast_task::clock::now() + std::chrono::seconds(5);
    while (ran.load() == 0 && fast_task::clock::now() < deadline)
        ctx.poll(1);

    EXPECT_EQ(ran.load(), 1);
}

// ---------------------------------------------------------------------------
// S1 notification tests (plans/pool-architecture.md §2.8 and §2.9).
//
// These cover the wake paths that the old 10 ms safety slices used to paper
// over. Each one is a genuine lost-wake / lost-handoff scenario: before S1 the
// slice made them merely slow, with the slices gone a miss is permanent.
// ---------------------------------------------------------------------------

namespace {
    // Waits for `pred` with a generous bound so a slow machine fails on the
    // timing assertion (below) rather than on a hard hang.
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

// §2.8 parked-pool handshake: a worker that has parked as the driver inside
// io_uring blocks with an indefinite timeout, so publishing a task for its pool
// must poke it explicitly (wake_work compares glob.driver.parked_pool) *or*
// leave a witness the driver re-checks (the work_event epoch). Without either,
// the publish lands in the queue and nobody ever looks at it.
TEST(WorkerContext, WakeWhileDriverParked) {
    fast_task::scheduler::create_executor(1);
    while (fast_task::scheduler::total_executors() < 1u)
        std::this_thread::yield();

    // Let the only worker drain the queue, become the driver and park with
    // timeout -1: there is nothing else for it to do.
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

// §2.9 handoff: the driver leaves its loop to run user code and to sleep in
// io_uring. Arming a deadline after it parked must therefore wake it
// (schedule_until -> ensure_driver), otherwise a timer scheduled while nothing
// is runnable is only serviced by whichever unrelated event happens to wake the
// driver next -- or never, if the system then goes idle.
TEST(WorkerContext, TimerFiresWhileDriverParked) {
    fast_task::scheduler::create_executor(1);
    while (fast_task::scheduler::total_executors() < 1u)
        std::this_thread::yield();

    // Old 10 ms slices are gone: this really is an indefinite park.
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    std::atomic<bool> ran{false};
    const auto start = fast_task::clock::now();
    // Not runnable at all until the wheel expires: only the timer can make this
    // task visible to a worker.
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

// §2.8 dormant/active split: shut_down() touches no work queue, so it can only
// reach a parked worker through the control plane (dormant_event + the driver
// token). If control wakes were routed through the work eventcount the way the
// old single notifier did, an idle worker would have to be re-notified by a
// subsequent publish to notice.
TEST(WorkerContext, ShutDownWakesIdlePollAll) {
    std::atomic<bool> registered{false};
    std::atomic<bool> returned{false};
    std::thread worker([&] {
        fast_task::scheduler::worker_context ctx;
        registered.store(true, std::memory_order_release);
        ctx.poll_all();
        returned.store(true);
    });

    // The worker must be registered (and parked in poll_all()), not on its way
    // in: a context created after shut_down() has drained the executors parks
    // for good and this test then hangs in join() instead of failing.
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
