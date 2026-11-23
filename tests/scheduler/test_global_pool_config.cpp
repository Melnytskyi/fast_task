// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <atomic>

#include <helpers.hpp>

namespace {
    fast_task::scheduler::worker_pool_options global_options(fast_task::scheduler::queue_policy queue, fast_task::scheduler::idle_policy idle, fast_task::scheduler::worker_balancer balancer) {
        fast_task::scheduler::worker_pool_options options;
        options.queue = queue;
        options.idle = idle;
        options.balancer = balancer;
        options.min_workers = 0;
        options.max_workers = 4;
        options.initial_workers = 0;
        options.start_with_worker_per_core = false;
        options.allow_implicit_start = false;
        return options;
    }

    void expect_policy(const fast_task::scheduler::worker_pool_stats& stats, fast_task::scheduler::queue_policy queue, fast_task::scheduler::idle_policy idle, fast_task::scheduler::worker_balancer balancer) {
        EXPECT_EQ(stats.queue, queue);
        EXPECT_EQ(stats.idle, idle);
        EXPECT_EQ(stats.balancer, balancer);
    }
}

TEST(GlobalPoolConfig, AcceptsNonDefaultPolicyBeforeUse) {
    fast_task::scheduler::shut_down();
    auto& pool = fast_task::scheduler::worker_pool::global();

    fast_task::scheduler::worker_pool::configure_global(global_options(
        fast_task::scheduler::queue_policy::priority_fifo,
        fast_task::scheduler::idle_policy::busy_spin,
        fast_task::scheduler::worker_balancer::hill_climb
    ));

    ASSERT_TRUE(pool.is_global());
    const auto stats = pool.stats();
    expect_policy(stats, fast_task::scheduler::queue_policy::priority_fifo, fast_task::scheduler::idle_policy::busy_spin, fast_task::scheduler::worker_balancer::hill_climb);
    EXPECT_EQ(stats.name, std::string("global"));
    EXPECT_EQ(stats.max_workers, 4u);
    fast_task::scheduler::shut_down();
}

TEST(GlobalPoolConfig, LastConfigurationWinsBeforeUse) {
    fast_task::scheduler::shut_down();
    auto& pool = fast_task::scheduler::worker_pool::global();

    fast_task::scheduler::worker_pool::configure_global(global_options(
        fast_task::scheduler::queue_policy::priority_fifo,
        fast_task::scheduler::idle_policy::busy_spin,
        fast_task::scheduler::worker_balancer::hill_climb
    ));
    fast_task::scheduler::worker_pool::configure_global(global_options(
        fast_task::scheduler::queue_policy::priority_fifo,
        fast_task::scheduler::idle_policy::wait,
        fast_task::scheduler::worker_balancer::none
    ));

    std::atomic<int> done{0};
    auto t = fast_task::task::create([&] { ++done; });
    fast_task::scheduler::start(t);
    fast_task::scheduler::await_no_tasks();

    EXPECT_EQ(done.load(), 1);
    expect_policy(pool.stats(), fast_task::scheduler::queue_policy::priority_fifo, fast_task::scheduler::idle_policy::wait, fast_task::scheduler::worker_balancer::none);
    fast_task::scheduler::shut_down();
}

TEST(GlobalPoolConfig, RejectsReconfigurationAfterUse) {
    ensure_global_workers(1);
    const auto before = fast_task::scheduler::worker_pool::global().stats();

    EXPECT_THROW(fast_task::scheduler::worker_pool::configure_global(global_options(fast_task::scheduler::queue_policy::work_stealing_lifo, fast_task::scheduler::idle_policy::wait, fast_task::scheduler::worker_balancer::none)), std::logic_error);

    const auto after = fast_task::scheduler::worker_pool::global().stats();
    expect_policy(after, before.queue, before.idle, before.balancer);
    fast_task::scheduler::shut_down();
}
