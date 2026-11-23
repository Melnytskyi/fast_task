// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <atomic>
#include <thread>

#include <helpers.hpp>

namespace {
    fast_task::scheduler::worker_pool_options control_options(uint16_t workers) {
        fast_task::scheduler::worker_pool_options o;
        o.initial_workers = workers;
        o.start_with_worker_per_core = false;
        o.min_workers = 0;
        return o;
    }

    template <class Pred>
    bool eventually(Pred&& pred, std::chrono::milliseconds limit = std::chrono::seconds(5)) {
        const auto deadline = fast_task::clock::now() + limit;
        while (fast_task::clock::now() < deadline) {
            if (pred())
                return true;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        return pred();
    }

    void wait_workers(fast_task::scheduler::worker_pool& pool, uint16_t n) {
        const bool ok = eventually([&pool, n] { return pool.stats().active_workers >= n; });
        ASSERT_TRUE(ok) << "the pool did not reach " << n << " active workers";
    }
}

TEST(PoolControl, PauseHoldsWorkUntilResume) {
    auto pool = fast_task::scheduler::worker_pool::create(control_options(1));
    wait_workers(pool, 1);

    pool.pause();
    EXPECT_TRUE(pool.is_paused());
    EXPECT_TRUE(pool.stats().paused);

    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    constexpr int N = 4;
    std::atomic<int> ran{0};
    for (int i = 0; i < N; ++i)
        pool.post(fast_task::task::create([&ran] { ran.fetch_add(1); }));

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_EQ(ran.load(), 0);
    EXPECT_EQ(pool.stats().in_run_tasks, 0u);
    EXPECT_NE(pool.stats().queued_tasks_approx, 0u);

    pool.resume();
    EXPECT_FALSE(pool.is_paused());

    EXPECT_TRUE(eventually([&ran] { return ran.load() == N; }));
    EXPECT_EQ(ran.load(), N);
    fast_task::scheduler::shut_down();
}

TEST(PoolControl, PauseStopsBusySpinWorker) {
    auto opts = control_options(1);
    opts.idle = fast_task::scheduler::idle_policy::busy_spin;
    auto pool = fast_task::scheduler::worker_pool::create(opts);
    wait_workers(pool, 1);

    pool.pause();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    constexpr int N = 3;
    std::atomic<int> ran{0};
    for (int i = 0; i < N; ++i)
        pool.post(fast_task::task::create([&ran] { ran.fetch_add(1); }));

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_EQ(ran.load(), 0);

    pool.resume();
    EXPECT_TRUE(eventually([&ran] { return ran.load() == N; }));
    fast_task::scheduler::shut_down();
}

TEST(PoolControl, LiveWorkerLimits) {
    auto opts = control_options(1);
    opts.max_workers = 4;
    auto pool = fast_task::scheduler::worker_pool::create(opts);
    wait_workers(pool, 1);

    EXPECT_EQ(pool.stats().min_workers, 0);
    EXPECT_EQ(pool.stats().max_workers, 4);

    pool.add_workers(3);
    EXPECT_TRUE(eventually([&pool] { return pool.stats().target_workers == 4; }));
    EXPECT_TRUE(eventually([&pool] { return pool.stats().active_workers == 4; }));

    pool.add_workers(4);
    EXPECT_EQ(pool.stats().target_workers, 4);

    pool.set_max_workers(2);
    EXPECT_EQ(pool.stats().max_workers, 2);
    EXPECT_TRUE(eventually([&pool] { return pool.stats().target_workers == 2; }));
    EXPECT_TRUE(eventually([&pool] { return pool.stats().active_workers <= 2; }));

    pool.request_workers(4);
    EXPECT_EQ(pool.stats().target_workers, 2);

    pool.set_max_workers(6);
    pool.request_workers(3);
    EXPECT_TRUE(eventually([&pool] { return pool.stats().target_workers == 3; }));

    pool.set_min_workers(2);
    EXPECT_EQ(pool.stats().min_workers, 2);
    pool.remove_workers(10);
    EXPECT_EQ(pool.stats().target_workers, 2);

    fast_task::scheduler::shut_down();
}

TEST(PoolControl, SetMinWorkersGrowsThePool) {
    auto opts = control_options(0);
    opts.max_workers = 2;
    auto pool = fast_task::scheduler::worker_pool::create(opts);

    EXPECT_EQ(pool.stats().target_workers, 0);

    pool.set_min_workers(2);
    EXPECT_EQ(pool.stats().min_workers, 2);
    EXPECT_TRUE(eventually([&pool] { return pool.stats().target_workers == 2; }));
    EXPECT_TRUE(eventually([&pool] { return pool.stats().active_workers == 2; }));

    fast_task::scheduler::shut_down();
}

TEST(PoolControl, ShutDownLiftsPauseDuringDrain) {
    auto pool = fast_task::scheduler::worker_pool::create(control_options(1));
    wait_workers(pool, 1);

    std::atomic<bool> done{false};
    pool.pause();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    pool.post(fast_task::task::create([&done] { done.store(true); }));

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    ASSERT_FALSE(done.load());

    fast_task::scheduler::shut_down();
    EXPECT_TRUE(done.load());
}
