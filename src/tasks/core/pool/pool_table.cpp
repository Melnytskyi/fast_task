// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <stdexcept>

#include <tasks/_internal.hpp>

namespace fast_task {
    pool_ref acquire_pool_ref(uint8_t index) noexcept {
        if constexpr (pool_table_size <= 255) {
            if (index >= pool_table_size)
                return {};
        }
        fast_task::shared_lock guard(glob.pools.safety);
        auto* pool = glob.pools.slots[index].load(std::memory_order_acquire);
        if (!pool)
            return {};
        pool->active_refs.fetch_add(1, std::memory_order_acq_rel);
        return pool_ref(pool);
    }

    pool_ref acquire_implicit_pool_ref() noexcept {
        fast_task::shared_lock guard(glob.pools.safety);
        auto* pool = glob.pools.implicit_pool.load(std::memory_order_acquire);
        if (!pool || pool->closing)
            return {};
        pool->active_refs.fetch_add(1, std::memory_order_acq_rel);
        return pool_ref(pool);
    }

    uint8_t allocate_pool_slot(worker_pool_storage* storage) {
        fast_task::unique_lock guard(glob.pools.safety);
        for (uint8_t i = 0; i < user_pool_count; ++i) {
            worker_pool_storage* expected = nullptr;
            if (glob.pools.slots[i].compare_exchange_strong(expected, storage, std::memory_order_acq_rel)) {
                storage->pool_index = i;
                storage->is_global = false;
                return i;
            }
        }
        throw std::length_error("fast_task: worker pool table is full (255 user pools)");
    }

    worker_pool_storage* release_pool_slot(uint8_t index) noexcept {
        if (index >= user_pool_count)
            return nullptr;
        worker_pool_storage* released = nullptr;
        {
            fast_task::unique_lock guard(glob.pools.safety);
            released = glob.pools.slots[index].exchange(nullptr, std::memory_order_acq_rel);
        }
        if (released) {
            if (released->config.allow_implicit_start)
                refresh_implicit_pool();
            if (released->config.allow_dormant_sharing)
                refresh_dormant_sharing();
        }
        return released;
    }

    void refresh_implicit_pool() {
        fast_task::unique_lock guard(glob.pools.safety);
        worker_pool_storage* first = nullptr;
        for (uint8_t i = 0; i < user_pool_count; ++i) {
            auto* candidate = glob.pools.slots[i].load(std::memory_order_acquire);
            if (candidate && candidate->config.allow_implicit_start && !candidate->closing) {
                first = candidate;
                break;
            }
        }
        glob.pools.implicit_pool.store(first, std::memory_order_release);
    }

    bool pool_pristine(const worker_pool_storage& pool) noexcept {
        if (pool.closing)
            return false;
        if (pool.runtime.executing_tasks.load(std::memory_order_acquire) != 0)
            return false;
        if (pool.runtime.in_run_tasks.load(std::memory_order_acquire) != 0)
            return false;
        if (pool.threads.live() != 0 || pool.threads.foreign() != 0 || pool.threads.dormant() != 0)
            return false;
        if (pool.threads.borrowed_in() != 0 || pool.threads.borrowed_out() != 0 || pool.threads.pending_leases() != 0)
            return false;
        if (pool.ops.queue.pending(pool) != 0)
            return false;
        if (pool.ops.executors.active(pool) != 0)
            return false;
        return true;
    }

    void retarget_task(task_object& t, worker_pool_storage& to) noexcept {
        fast_task::lock_guard guard(t);
        pool_ref from = t.get_pool_assigned() ? acquire_pool_ref(t.pool_index) : pool_ref{};
        if (from.get() == &to) {
            t.set_pool_assigned(true);
            return;
        }
        if (from && !t.is_created() && !t.get_completed()) {
            to.runtime.executing_tasks.fetch_add(1, std::memory_order_acq_rel);
            auto rem_old = from->runtime.executing_tasks.fetch_sub(1, std::memory_order_acq_rel);
            if (rem_old == 1)
                notify_no_tasks_waiters();
        }
        t.pool_index = to.pool_index;
        t.set_pool_assigned(true);
    }
}
