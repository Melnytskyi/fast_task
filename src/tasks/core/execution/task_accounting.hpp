// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_CORE_TASK_ACCOUNTING
#define FAST_TASK_CORE_TASK_ACCOUNTING

#include <cassert>
#include <cstdint>

#include <tasks/core/execution/worker.hpp>
#include <tasks/core/pool/pool.hpp>
#include <tasks/core/runtime/runtime.hpp>

namespace fast_task {
    inline worker_pool_storage& task_account_pool(task_object& t) noexcept {
        if (!t.get_pool_assigned()) {
            auto* loc = get_loc();
            t.pool_index = loc ? loc->pool_index : global_pool_index;
            t.set_pool_assigned(true);
        }
        auto* pool = pool_for_index(t.pool_index);
        return pool ? *pool : global_storage();
    }

    inline void task_mark_created(task_object& t) noexcept {
        task_account_pool(t).runtime.executing_tasks.fetch_add(1, std::memory_order_acq_rel);
    }

    inline void notify_no_tasks_waiters() noexcept {
        if (glob.no_tasks.waiters.load(std::memory_order_acquire) == 0)
            return;
        fast_task::shared_lock guard(glob.no_tasks.guard);
        glob.no_tasks.notifier.notify_all();
    }

    constexpr uint32_t completed_batch_flush = 64;

    inline void flush_completed_batch(executors_local& loc, worker_pool_storage* pool) noexcept {
        const uint32_t batch = loc.batch.completed;
        if (batch == 0)
            return;
        loc.batch.completed = 0;
        if (pool)
            pool->runtime.completed_tasks.fetch_add(batch, std::memory_order_relaxed);
    }

    inline void release_executing_tasks(worker_pool_storage& pool, uint32_t count) noexcept {
        const size_t before = pool.runtime.executing_tasks.fetch_sub(count, std::memory_order_acq_rel);
        assert(before >= count && "executing_tasks underflow");
        if (before == count)
            notify_no_tasks_waiters();
    }

    inline void flush_executing_batch(executors_local& loc, worker_pool_storage* pool) noexcept {
        const uint32_t batch = loc.batch.executing;
        if (batch == 0)
            return;
        loc.batch.executing = 0;
        if (pool)
            release_executing_tasks(*pool, batch);
    }

    inline void task_run_enter(executors_local* loc) noexcept {
        if (loc && loc->owner_pool)
            loc->owner_pool->runtime.in_run_tasks.fetch_add(1, std::memory_order_relaxed);
    }

    inline void task_run_exit(executors_local* loc) noexcept {
        if (loc && loc->owner_pool)
            loc->owner_pool->runtime.in_run_tasks.fetch_sub(1, std::memory_order_release);
    }

    inline uint32_t pool_in_run_tasks(const worker_pool_storage& pool) noexcept {
        return static_cast<uint32_t>(pool.runtime.in_run_tasks.load(std::memory_order_acquire));
    }

    inline void task_mark_completed(task_object& t, executors_local* loc = nullptr) noexcept {
        worker_pool_storage* pool = t.get_pool_assigned() ? pool_for_index(t.pool_index) : nullptr;
        if (!pool)
            pool = &global_storage();
        if (!loc)
            loc = get_loc();

        if (loc && loc->owner_pool == pool) {
            ++loc->batch.completed;
            if (loc->batch.completed >= completed_batch_flush)
                flush_completed_batch(*loc, pool);
            ++loc->batch.executing;
            if (loc->batch.executing >= completed_batch_flush)
                flush_executing_batch(*loc, pool);
            return;
        }
        release_executing_tasks(*pool, 1);
        pool->runtime.completed_tasks.fetch_add(1, std::memory_order_relaxed);
    }
}

#endif /* FAST_TASK_CORE_TASK_ACCOUNTING */
