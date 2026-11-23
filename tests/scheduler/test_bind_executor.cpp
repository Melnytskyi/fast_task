// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <atomic>
#include <helpers.hpp>
#include <memory>
#include <span>
#include <vector>

namespace {
    fast_task::scheduler::worker_pool_options pool_options(uint16_t workers) {
        fast_task::scheduler::worker_pool_options o;
        o.initial_workers = workers;
        o.start_with_worker_per_core = false;
        o.min_workers = 0;
        return o;
    }

    void wait_workers(fast_task::scheduler::worker_pool& pool, uint16_t n) {
        const auto deadline = fast_task::clock::now() + std::chrono::seconds(5);
        while (pool.stats().active_workers < n && fast_task::clock::now() < deadline)
            std::this_thread::yield();
    }
}

TEST(BindExecutor, CreateAndClose) {
    auto pool = fast_task::scheduler::worker_pool::create(pool_options(1));
    EXPECT_FALSE(pool.is_global());
    wait_workers(pool, 1);
    EXPECT_EQ(pool.stats().active_workers, 1);
}

TEST(BindExecutor, TaskRunsOnBindExecutor) {
    auto pool = fast_task::scheduler::worker_pool::create(pool_options(1));
    wait_workers(pool, 1);

    std::atomic<bool> ran{false};
    auto t = fast_task::task::create([&] { ran = true; });
    pool.post(t);
    t.await_task();

    EXPECT_TRUE(ran.load());
    EXPECT_EQ(fast_task::this_task::get_id() != 0, true);
}

TEST(BindExecutor, BindDoesNotSchedule) {
    auto pool = fast_task::scheduler::worker_pool::create(pool_options(1));
    wait_workers(pool, 1);

    std::atomic<bool> ran{false};
    auto t = fast_task::task::create([&] { ran = true; });
    pool.bind(t);
    EXPECT_FALSE(ran.load());

    t.start();
    t.await_task();

    EXPECT_TRUE(ran.load());
}

TEST(BindExecutor, PostSpanRunsEveryTask) {
    auto pool = fast_task::scheduler::worker_pool::create(pool_options(2));
    wait_workers(pool, 2);

    constexpr int N = 16;
    std::atomic<int> ran{0};
    std::vector<fast_task::task> tasks;
    tasks.reserve(N);
    for (int i = 0; i < N; ++i)
        tasks.push_back(fast_task::task::create([&] { ran.fetch_add(1, std::memory_order_relaxed); }));

    pool.post(std::span<const fast_task::task>(tasks.data(), tasks.size()));

    for (auto& t : tasks)
        t.await_task();
    EXPECT_EQ(ran.load(), N);
}

TEST(BindExecutor, PoolTableExhaustionThrows) {
    std::vector<std::unique_ptr<fast_task::scheduler::worker_pool>> pools;
    pools.reserve(255);
    for (int i = 0; i < 255; ++i)
        pools.push_back(std::make_unique<fast_task::scheduler::worker_pool>(pool_options(0)));

    EXPECT_THROW((void)std::make_unique<fast_task::scheduler::worker_pool>(pool_options(0)), std::length_error);

    pools.clear();
    auto again = std::make_unique<fast_task::scheduler::worker_pool>(pool_options(0));
    EXPECT_FALSE(again->is_global());
}

TEST(BindExecutor, CloseAbortTasksAbortsQueuedAndAllowsShutdown) {
    std::atomic<bool> queued_ran{false};
    {
        auto opts = pool_options(0);
        opts.abort_tasks_on_shutdown = true;
        auto pool = fast_task::scheduler::worker_pool::create(opts);

        auto queued = fast_task::task::create([&] { queued_ran.store(true); });
        pool.bind(queued);
        queued.start();
    }
    EXPECT_FALSE(queued_ran.load());

    fast_task::scheduler::shut_down();
}

TEST(BindExecutor, SetPoolMovesTaskOnNextReschedule) {
    auto pool = fast_task::scheduler::worker_pool::create(pool_options(1));
    wait_workers(pool, 1);
    ensure_global_workers(1);

    std::atomic<fast_task::scheduler::worker_pool*> where{nullptr};
    auto t = fast_task::task::create([&] {
        fast_task::this_task::set_pool(pool);
        fast_task::this_task::yield();
        where.store(&fast_task::this_task::current_pool());
    });
    t.start();
    t.await_task();

    EXPECT_EQ(where.load(), &pool);
    fast_task::scheduler::shut_down();
}

TEST(BindExecutor, SwitchToMovesTask) {
    auto pool = fast_task::scheduler::worker_pool::create(pool_options(1));
    wait_workers(pool, 1);
    ensure_global_workers(1);

    std::atomic<fast_task::scheduler::worker_pool*> where{nullptr};
    auto t = fast_task::task::create([&] {
        fast_task::this_task::switch_to(pool);
        where.store(&fast_task::this_task::current_pool());
    });
    t.start();
    t.await_task();

    EXPECT_EQ(where.load(), &pool);
    fast_task::scheduler::shut_down();
}

TEST(BindExecutor, SwitchToThrowsOnStacklessTask) {
    auto pool = fast_task::scheduler::worker_pool::create(pool_options(1));
    wait_workers(pool, 1);
    ensure_global_workers(1);

    std::atomic<bool> threw{false};
    auto coro = [](std::atomic<bool>& threw,
                   fast_task::scheduler::worker_pool& pool) -> fast_task::task_coro<void> {
        try {
            fast_task::this_task::switch_to(pool);
        } catch (const std::logic_error&) {
            threw.store(true);
        }
        co_return;
    }(threw, pool);

    fast_task::scheduler::start(coro.get_task());
    coro->await_task();

    EXPECT_TRUE(threw.load());
    fast_task::scheduler::shut_down();
}

TEST(BindExecutor, FutureStartRunsOnGivenPool) {
    auto pool = fast_task::scheduler::worker_pool::create(pool_options(1));
    wait_workers(pool, 1);
    ensure_global_workers(1);

    auto f = fast_task::future<int>::start(
        [&] {
            return &fast_task::this_task::current_pool() == &pool ? 1 : 0;
        },
        &pool
    );

    EXPECT_EQ(f->get(), 1);
    fast_task::scheduler::shut_down();
}
