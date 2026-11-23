// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_CORE_POOL_WAKE
#define FAST_TASK_CORE_POOL_WAKE

#include <tasks/core/pool/pool.hpp>
#include <tasks/core/runtime/runtime.hpp>

namespace fast_task {
    struct executors_local;

    inline void wake_driver_if_parked(uint8_t pool_index) noexcept {
        if (glob.driver.parked_pool.load(std::memory_order_seq_cst) == pool_index)
            glob.driver.wake();
    }

    inline void wake_work(worker_pool_storage& pool) noexcept {
        if (pool.work_event.notify_one())
            return;
        wake_driver_if_parked(pool.pool_index);
    }

    inline bool has_queued_work(const worker_pool_storage* pool, const executors_local* loc) noexcept {
        if (!pool)
            pool = &global_storage();
        return pool->ops.queue.has_queued_work(*pool, loc);
    }

    inline bool has_runnable_work(const worker_pool_storage* pool, const executors_local* loc) noexcept {
        if (!pool)
            pool = &global_storage();
        return pool->ops.queue.has_runnable_work(*pool, loc);
    }

    inline bool scheduler_stopping() noexcept {
        return glob.shutdown.executors_down.load(std::memory_order_acquire) ||
               glob.shutdown.requested.load(std::memory_order_acquire);
    }

    inline void wake_work_all(worker_pool_storage& pool) noexcept {
        pool.work_event.notify_all();
        wake_driver_if_parked(pool.pool_index);
    }

    inline void wake_control(worker_pool_storage& pool) noexcept {
        pool.work_event.notify_all();
        pool.dormant_event.notify_all();
        glob.driver.wake();
    }
}

#endif /* FAST_TASK_CORE_POOL_WAKE */
