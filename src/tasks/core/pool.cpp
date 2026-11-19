// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)
//
// Pool layer implementation (plans/pool-architecture.md §2.2/§2.11): storage
// initialisation, table slot allocation and the aggregate runtime view.

#include <stdexcept>

#include <tasks/_internal.hpp>

namespace fast_task {
    void init_pool_storage(worker_pool_storage& storage, uint8_t index, bool is_global) noexcept {
        storage.pool_index = index;
        storage.is_global = is_global;
        init_registry_slot(storage.entry, index);
        if (is_global) {
            // The global pool's registry lives in the runtime (1024 slots);
            // its inline 64-slot entry stays unused.
            storage.registry = glob.global_registry.view();
        } else {
            storage.registry = storage.entry.registry.view();
        }
    }

    uint8_t allocate_pool_slot(worker_pool_storage* storage) {
        fast_task::unique_lock guard(glob.pools_safety);
        for (uint8_t i = 0; i < user_pool_count; ++i) {
            worker_pool_storage* expected = nullptr;
            if (glob.pools[i].compare_exchange_strong(expected, storage, std::memory_order_acq_rel)) {
                init_pool_storage(*storage, i, false);
                return i;
            }
        }
        // Table exhaustion is a configuration error, not a transient failure
        // (§2.2).
        throw std::length_error("fast_task: worker pool table is full (255 user pools)");
    }

    worker_pool_storage* release_pool_slot(uint8_t index) noexcept {
        if (index >= user_pool_count)
            return nullptr;
        worker_pool_storage* released = glob.pools[index].exchange(nullptr, std::memory_order_acq_rel);
        if (released && released->config.allow_implicit_start)
            refresh_implicit_pool();
        return released;
    }

    void refresh_implicit_pool() {
        fast_task::unique_lock guard(glob.pools_safety);
        worker_pool_storage* first = nullptr;
        for (uint8_t i = 0; i < user_pool_count; ++i) {
            auto* candidate = glob.pools[i].load(std::memory_order_acquire);
            if (candidate && candidate->config.allow_implicit_start && !candidate->closing) {
                first = candidate;
                break;
            }
        }
        glob.implicit_pool.store(first, std::memory_order_release);
    }

    void retarget_task(task_object& t, worker_pool_storage& to) noexcept {
        fast_task::lock_guard guard(t);
        worker_pool_storage* from = t.get_pool_assigned() ? pool_for_index(t.pool_index) : nullptr;
        if (from == &to) {
            t.set_pool_assigned(true);
            return;
        }
        if (!t.is_created() && !t.get_completed()) {
            // Destination first: the sum across pools must never transiently
            // reach zero (§2.11).
            to.runtime.executing_tasks.fetch_add(1, std::memory_order_acq_rel);
            if (from) {
                auto rem_old = from->runtime.executing_tasks.fetch_sub(1, std::memory_order_acq_rel);
                if (rem_old == 1)
                    glob.completion_event.notify_all();
            }
        }
        t.pool_index = to.pool_index;
        t.set_pool_assigned(true);
    }
}

namespace fast_task::scheduler {
    runtime_stats get_runtime_stats() {
        runtime_stats stats;
        stats.shutting_down =
            glob.executor_shutting_down.load(std::memory_order_acquire) ||
            glob.shutdown_requested.load(std::memory_order_acquire);
        stats.timers_pending = glob.timed_wheel.size();

        for (uint8_t i = 0; i < pool_table_size; ++i) {
            auto* pool = pool_for_index(i);
            if (!pool)
                continue;

            worker_pool_stats ws;
            ws.name = pool->config.name;
            ws.ordinal = pool->entry.ordinal;
            ws.is_global = pool->is_global;
            ws.queue = pool->config.queue;
            ws.idle = pool->config.idle;
            ws.target_workers = pool->runtime.target_workers.load(std::memory_order_relaxed);
            ws.active_workers = pool->runtime.active_workers.load(std::memory_order_relaxed);
            ws.foreign_workers = pool->runtime.foreign_workers.load(std::memory_order_relaxed);
            ws.dormant_workers = pool->runtime.dormant_workers.load(std::memory_order_relaxed);
            ws.borrowed_in = pool->runtime.borrowed_in.load(std::memory_order_relaxed);
            ws.borrowed_out = pool->runtime.borrowed_out.load(std::memory_order_relaxed);
            ws.live_threads = pool->runtime.live_threads.load(std::memory_order_relaxed);
            ws.queued_tasks_approx = pool->ops.pending(*pool);
            ws.executing_tasks = pool->runtime.executing_tasks.load(std::memory_order_relaxed);
            ws.in_run_tasks = pool->runtime.in_run_tasks.load(std::memory_order_relaxed);
            ws.completed_tasks = pool->runtime.completed_tasks.load(std::memory_order_relaxed);
            ws.affinity_failures = pool->runtime.affinity_failures.load(std::memory_order_relaxed);
            ws.paused = pool->runtime.paused.load(std::memory_order_relaxed);
            ws.shutting_down = pool->closing;

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
