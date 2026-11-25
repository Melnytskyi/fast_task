// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <stdexcept>
#include <thread>

#include <tasks/_internal.hpp>

namespace fast_task::scheduler {
    static_assert(worker_pool_storage_size == 8192, "worker_pool::storage_size must match worker_pool_storage_size");

    worker_pool::worker_pool(global_pool_tag) {
        ::new (static_cast<void*>(storage)) worker_pool_impl();
        global_storage().public_handle = this;
    }

    worker_pool::worker_pool(worker_pool_options options) {
        auto& impl = *::new (static_cast<void*>(storage)) worker_pool_impl();
        auto* pool = construct_pool_storage(storage + worker_pool_impl::layer_offset, options.queue, options.idle, options.balancer, options.max_workers <= 1);
        impl.base = pool;
        pool->config = std::move(options);
        pool->started = true;

        if (pool->config.affinity.mode == scheduler::pool_affinity_mode::round_robin &&
            pool->config.affinity.cpus.empty()) {
            pool->ops.queue.destroy(*pool);
            throw std::invalid_argument("worker_pool: round_robin affinity requires at least one cpu");
        }
        pool->threads.set_limits(pool->config.min_workers, pool->config.max_workers);
        pool->ops.balancer.arm(*pool);

        uint8_t slot = 0;
        try {
            slot = allocate_pool_slot(pool);
        } catch (...) {
            pool->ops.queue.destroy(*pool);
            throw;
        }
        pool->public_handle = this;
        if (pool->config.name.empty())
            pool->config.name = "pool " + std::to_string(slot);
        if (pool->config.allow_implicit_start)
            refresh_implicit_pool();
        refresh_dormant_sharing();

        uint16_t initial = pool->config.initial_workers;
        if (initial == 0 && pool->config.start_with_worker_per_core) {
            unsigned cores = std::thread::hardware_concurrency();
            if (cores == 0)
                cores = 1;
            if (cores > pool->config.max_workers)
                cores = pool->config.max_workers;
            if (cores < pool->config.min_workers)
                cores = pool->config.min_workers;
            initial = static_cast<uint16_t>(cores);
        }
        if (initial != 0)
            spawn_pool_worker(*pool, initial);
    }

    worker_pool::~worker_pool() {
        auto& impl = worker_pool_impl::of(*this);
        if (impl.is_global())
            return;
        auto* pool = impl.base;
        auto* loc = get_loc();
        if (loc && loc->owner_pool == pool) {
            if (loc->is_task_thread)
                std::abort();
            if (loc->host_context)
                worker_context_impl::of(*loc->host_context).leave(true, true);
        }

        shutdown_pool(*pool, pool->config.abort_tasks_on_shutdown);
        pool->public_handle = nullptr;
        pool->ops.queue.destroy(*pool);
    }

    worker_pool& worker_pool::global() {
        auto* handle = glob.pools.global_handle.load(std::memory_order_acquire);
        if (handle)
            return *handle;
        fast_task::unique_lock guard(glob.pools.safety);
        handle = glob.pools.global_handle.load(std::memory_order_relaxed);
        if (!handle) {
            handle = new worker_pool(global_pool_tag{});
            glob.pools.global_handle.store(handle, std::memory_order_release);
        }
        return *handle;
    }

    void worker_pool::configure_global(worker_pool_options options) {
        validate_pool_policies(options.queue, options.idle);
        if (options.affinity.mode == scheduler::pool_affinity_mode::round_robin &&
            options.affinity.cpus.empty())
            throw std::invalid_argument("worker_pool: round_robin affinity requires at least one cpu");

        {
            fast_task::unique_lock guard(glob.pools.safety);
            auto* current = &global_storage();
            if (!pool_pristine(*current))
                throw std::logic_error("worker_pool: the global pool is already in use");

            const uint8_t index = current->pool_index;
            scheduler::worker_pool* handle = current->public_handle;
            current->ops.queue.destroy(*current);

            auto* storage = construct_global_pool_storage(glob.pools.global_storage_buffer, options.queue, options.idle, options.balancer, options.max_workers <= 1);
            if (options.name.empty())
                options.name = "global";
            options.allow_driver_polling = true;
            storage->pool_index = index;
            storage->is_global = true;
            storage->started = true;
            storage->explicitly_configured = true;
            storage->public_handle = handle;
            storage->config = std::move(options);
            glob.pools.slots[index].store(storage, std::memory_order_release);

            storage->threads.set_limits(storage->config.min_workers, storage->config.max_workers);
            storage->ops.balancer.arm(*storage);
        }
        refresh_dormant_sharing();
    }

    bool worker_pool::is_global() const noexcept {
        return worker_pool_impl::of(const_cast<worker_pool&>(*this)).is_global();
    }

    void worker_pool::join_pool(worker_context& ctx) {
        worker_context_impl::of(ctx).join(storage_of(*this), false, true);
    }

    void worker_pool::leave_pool(worker_context& ctx) noexcept {
        worker_context_impl::of(ctx).leave(true, true);
    }

    void worker_pool::bind(const task& t) noexcept {
        if (!t)
            return;
        retarget_task(get_data(t), storage_of(*this));
    }

    void worker_pool::post(task&& t) {
        auto* pool = &storage_of(*this);
        bind(t);
        transfer_task(std::move(t));
        ensure_pool_worker(*pool);
        try_borrow_dormant(*pool);
    }

    void worker_pool::post(const task& t) {
        task copy = t;
        post(std::move(copy));
    }

    void worker_pool::post(std::span<const task> tasks) {
        if (tasks.empty())
            return;
        auto* pool = &storage_of(*this);
        const bool wake = !pool->runtime.paused.load(std::memory_order_acquire);
        for (const auto& t : tasks) {
            if (!t)
                continue;
            bind(t);
            transfer_task(task(t));
        }
        if (wake)
            wake_work_all(*pool);
        ensure_pool_worker(*pool);
        try_borrow_dormant(*pool);
    }

    void worker_pool::schedule_until(task&& t, fast_task::time_point time_point) {
        auto* pool = &storage_of(*this);
        bind(t);
        if (!pool->runtime.paused.load(std::memory_order_acquire) && pool->threads.live() == 0)
            spawn_pool_worker(*pool, 1);
        scheduler::schedule_until(std::move(t), time_point);
    }

    void worker_pool::schedule_until(const task& t, fast_task::time_point time_point) {
        task copy = t;
        schedule_until(std::move(copy), time_point);
    }

    void worker_pool::add_workers(uint16_t count) {
        auto* pool = &storage_of(*this);
        {
            fast_task::lock_guard guard(pool->no_race);
            if (pool->closing)
                throw std::logic_error("worker_pool: cannot add workers to a stopping pool");
        }
        spawn_pool_worker(*pool, count);
    }

    void worker_pool::remove_workers(uint16_t count) {
        shrink_pool_workers(storage_of(*this), count);
    }

    void worker_pool::request_workers(uint16_t target) {
        auto* pool = &storage_of(*this);
        const uint16_t min = pool->threads.min_limit();
        const uint16_t max = pool->threads.max_limit();
        if (target < min)
            target = min;
        if (target > max)
            target = max;
        const uint16_t current = pool->threads.target();
        if (target > current)
            add_workers(static_cast<uint16_t>(target - current));
        else if (target < current)
            remove_workers(static_cast<uint16_t>(current - target));
    }

    void worker_pool::pause() {
        auto* pool = &storage_of(*this);
        pool->runtime.paused.store(true, std::memory_order_release);
        wake_control(*pool);
    }

    void worker_pool::resume() {
        auto* pool = &storage_of(*this);
        pool->runtime.paused.store(false, std::memory_order_release);
        wake_control(*pool);
        ensure_pool_worker(*pool);
    }

    bool worker_pool::is_paused() const noexcept {
        return storage_of(*this).runtime.paused.load(std::memory_order_acquire);
    }

    void worker_pool::set_min_workers(uint16_t min) {
        auto* pool = &storage_of(*this);
        {
            fast_task::lock_guard guard(pool->no_race);
            if (pool->closing)
                throw std::logic_error("worker_pool: cannot reconfigure a stopping pool");
        }
        pool->threads.set_min(min);
        const uint16_t target = pool->threads.target();
        if (target < min)
            spawn_pool_worker(*pool, static_cast<uint16_t>(min - target));
    }

    void worker_pool::set_max_workers(uint16_t max) {
        auto* pool = &storage_of(*this);
        {
            fast_task::lock_guard guard(pool->no_race);
            if (pool->closing)
                throw std::logic_error("worker_pool: cannot reconfigure a stopping pool");
        }
        if (max > 1 && pool->config.queue == scheduler::queue_policy::work_stealing_lifo && pool->ops.queue.multi_worker_steal)
            pool->ops.queue.steal = pool->ops.queue.multi_worker_steal;
        pool->threads.set_max(max);
        const uint16_t target = pool->threads.target();
        if (target > max)
            remove_workers(static_cast<uint16_t>(target - max));
    }
}
