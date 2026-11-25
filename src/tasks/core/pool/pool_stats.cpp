// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <chrono>
#include <thread>

#include <tasks/_internal.hpp>

namespace fast_task::scheduler {
    namespace {
        worker_pool_stats describe(const worker_pool_storage& pool) {
            const pool_worker_counts counts = pool.threads.snapshot();
            worker_pool_stats ws;
            ws.name = pool.config.name;
            ws.ordinal = pool.pool_index;
            ws.is_global = pool.is_global;
            ws.queue = pool.config.queue;
            ws.idle = pool.config.idle;
            ws.balancer = pool.config.balancer;
            ws.min_workers = pool.threads.min_limit();
            ws.max_workers = pool.threads.max_limit();
            ws.target_workers = counts.target;
            ws.active_workers = counts.active;
            ws.foreign_workers = counts.foreign;
            ws.dormant_workers = counts.dormant;
            ws.borrowed_in = counts.borrowed_in;
            ws.borrowed_out = counts.borrowed_out;
            ws.live_threads = counts.live;
            ws.queued_tasks_approx = pool.ops.queue.pending(pool);
            ws.executing_tasks = pool.runtime.executing_tasks.load(std::memory_order_relaxed);
            ws.in_run_tasks = pool_in_run_tasks(pool);
            ws.completed_tasks = pool.runtime.completed_tasks.load(std::memory_order_relaxed);
            ws.balance_samples = pool.ops.balancer.samples(pool);
            ws.affinity_failures = pool.runtime.affinity_failures.load(std::memory_order_relaxed);
            ws.paused = pool.runtime.paused.load(std::memory_order_relaxed);
            ws.shutting_down = pool.closing;
            return ws;
        }
    }

    worker_pool_stats worker_pool::stats() const noexcept {
        return describe(storage_of(*this));
    }

    bool worker_pool::wait_idle(fast_task::time_point deadline) {
        auto* pool = &storage_of(*this);
        while (pool->runtime.executing_tasks.load(std::memory_order_acquire) != 0 ||
               pool_in_run_tasks(*pool) != 0) {
            if (fast_task::clock::now() >= deadline)
                return false;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        return true;
    }

    runtime_stats get_runtime_stats() {
        runtime_stats stats;
        stats.shutting_down =
            glob.shutdown.executors_down.load(std::memory_order_acquire) ||
            glob.shutdown.requested.load(std::memory_order_acquire);
        stats.timers_pending = glob.timing.wheel.size();

        for (uint16_t i = 0; i < pool_table_size; ++i) {
            auto pool = acquire_pool_ref(static_cast<uint8_t>(i));
            if (!pool)
                continue;

            worker_pool_stats ws = describe(*pool);
            stats.active_pools += 1;
            stats.total_active_workers += ws.active_workers;
            stats.total_foreign_workers += ws.foreign_workers;
            stats.total_dormant_workers += ws.dormant_workers;
            stats.total_live_threads += ws.live_threads;
            stats.executing_tasks += ws.executing_tasks;
            stats.in_run_tasks += ws.in_run_tasks;
            stats.pools.push_back(std::move(ws));
        }
        return stats;
    }
}
