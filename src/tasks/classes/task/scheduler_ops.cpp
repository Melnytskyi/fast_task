// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)
//
// Scheduler operations. S2a (plans/pool-architecture.md §2.2/§2.10/§2.11)
// re-based the legacy bind-executor API onto the storage pointer table:
// `create_bind_only_executor` allocates a table slot and heap storage,
// `close_bind_only_executor` retires the workers, drains the pool and releases
// the slot, and `total_executors()` is the sum of the per-pool active worker
// counters instead of the removed global `executors` counter.

#include <chrono>
#include <thread>

#include <fast_task/task.hpp>
#include <tasks/_internal.hpp>

namespace fast_task::scheduler {
    namespace {
        // Sum of every live pool's executing_tasks (§2.11). Used by the
        // await/shutdown loops; the hot paths never call it.
        size_t total_executing_tasks() {
            size_t total = 0;
            for (auto& slot : glob.pools) {
                auto* pool = slot.load(std::memory_order_acquire);
                if (pool)
                    total += pool->runtime.executing_tasks.load(std::memory_order_acquire);
            }
            return total;
        }

        // Is anything queued (pool queues, cold queue, or a worker's inline
        // deque) in any pool?
        bool any_pool_work() {
            for (auto& slot : glob.pools) {
                auto* pool = slot.load(std::memory_order_acquire);
                if (!pool)
                    continue;
                if (pool->ops.pending(*pool) != 0)
                    return true;
                if (pool->registry.any_work())
                    return true;
            }
            return false;
        }

        void wake_all_pools() {
            for (auto& slot : glob.pools) {
                auto* pool = slot.load(std::memory_order_acquire);
                if (pool)
                    wake_control(pool->work_event, pool->dormant_event);
            }
        }
    }

    void schedule_until(task&& task, fast_task::time_point time_point) {
        schedule_until(task, time_point);
    }

    void schedule_until(const task& _task, fast_task::time_point time_point) {
        if (!total_executors())
            create_executor(1);
        task lgr_task = _task;
        {
            fast_task::lock_guard guard(get_data(_task));
            if (get_data(_task).is_running() || get_data(_task).is_ended()) {
#ifdef FT_ENABLE_ABORT_IF_ALREADY_STARTED
                assert(false && "The task is already running or stopped.");
                std::abort();
#endif
                return;
            }
            if (get_data(_task).is_scheduled() && (!get_data(_task).is_suspended() && get_data(_task).get_is_on_scheduler())) {
#ifdef FT_ENABLE_ABORT_IF_ALREADY_STARTED
                assert(false && "The task is already started.");
                std::abort();
#endif
                return;
            }
        }
        // Assign the destination pool now (the timer may fire on the global
        // driver) and account the task there, so the completion decrement in
        // task_mark_completed() lands on the same counter.
        if (get_data(lgr_task).is_created()) {
            task_account_pool(get_data(lgr_task)).runtime.executing_tasks.fetch_add(1, std::memory_order_acq_rel);
        }

        get_data(lgr_task).set_status(task_object::status_e::scheduled);


        if (glob.shutdown_requested.load(std::memory_order_acquire)) {
            transfer_task(std::move(lgr_task));
            return;
        }

        startTimeController();


        uint64_t ticks = glob.timed_wheel.to_ticks(time_point);
        glob.timed_wheel.insert(ticks, lgr_task, get_data(lgr_task).awake_check, !can_be_scheduled_task_to_hot());

        // Unconditional: the driver may have already read next_deadline() and
        // be about to park, so it must always be woken to re-evaluate. When no
        // thread is driving at all, this also wakes one idle worker to take the
        // driver, otherwise nothing would ever poll that wheel. No work_event
        // notify is needed for the task itself: it went into the timing wheel,
        // not a pool queue.
        glob.driver.ensure_driver();
    }

    void start(std::list<task>& tasks) {
        for (auto& it : tasks)
            start(it);
    }

    void start(std::vector<task>& tasks) {
        for (auto& it : tasks)
            start(it);
    }

    void start(task&& lgr_task) {
        start(lgr_task);
    }

    void start(const task& tsk) {
        if (!total_executors())
            create_executor(1);

        assert(tsk && "Cannot start an empty task");

        {
            fast_task::lock_guard guard(get_data(tsk));

            // Reject if currently executing or completely dead
            if (get_data(tsk).is_running() || get_data(tsk).is_ended()) {
#ifdef FT_ENABLE_ABORT_IF_ALREADY_STARTED
                assert(false && "The task is already running or stopped.");
                std::abort();
#endif
                return;
            }

            // Reject if it is already scheduled but not yet executing
            if (get_data(tsk).is_scheduled() && !get_data(tsk).is_suspended()) {
#ifdef FT_ENABLE_ABORT_IF_ALREADY_STARTED
                assert(false && "The task is already started.");
                std::abort();
#endif
                return;
            }
        }

        transfer_task(task(tsk));
    }

    uint16_t create_bind_only_executor(uint16_t fixed_count, bool allow_implicit_start, preemption_policy policy) {
        // The concrete type carries the queue and idle policy; the public
        // handle stays a `worker_pool_storage*` (S2b, §2.5).
        auto* storage = new default_pool_storage();
        uint8_t slot = 0;
        try {
            slot = allocate_pool_slot(storage);
        } catch (...) {
            storage->ops.deallocate(*storage);
            throw;
        }

        storage->config.name = "bind " + std::to_string(slot);
        storage->config.allow_implicit_start = allow_implicit_start;
        storage->config.policy = policy;
        storage->config.min_workers = fixed_count;
        storage->started = true;
        storage->runtime.target_workers.store(fixed_count, std::memory_order_release);
        if (allow_implicit_start)
            refresh_implicit_pool();

        for (size_t i = 0; i < fixed_count; i++) {
            ++glob.thread_count;
            fast_task::native::thread(bindedTaskExecutor, static_cast<uint16_t>(slot)).detach();
        }
        return slot;
    }

    void assign_bind_only_executor(uint16_t id, uint16_t fixed_count, bool allow_implicit_start, preemption_policy policy) {
        if (id == (uint16_t)-1)
            throw std::runtime_error("Invalid id");

        const uint8_t slot = bind_pool_index(id);
        worker_pool_storage* pool = pool_for_index(slot);
        if (!pool)
            throw std::runtime_error("Binded worker not found");

        uint16_t current_expected = 0;
        {
            fast_task::lock_guard ctx_guard(pool->no_race);
            if (pool->closing)
                throw std::runtime_error("Worker is closing");
            // Use target_workers (threads already spawned/committed), not
            // active_workers (threads that have actually started), so that
            // slow-starting threads are not spawned a second time.
            current_expected = pool->runtime.target_workers.load(std::memory_order_acquire);
            pool->config.allow_implicit_start = allow_implicit_start;
            pool->config.policy = policy;
            pool->runtime.target_workers.store(fixed_count, std::memory_order_release);
        }

        if (allow_implicit_start)
            refresh_implicit_pool();

        if (fixed_count > current_expected) {
            size_t diff = fixed_count - current_expected;
            for (size_t i = 0; i < diff; i++) {
                ++glob.thread_count;
                fast_task::native::thread(bindedTaskExecutor, static_cast<uint16_t>(slot)).detach();
            }
        }
    }

    void close_bind_only_executor(uint16_t id, bool abort_tasks) {
        const uint8_t slot = bind_pool_index(id);
        if (id >= user_pool_count)
            throw std::runtime_error("Binded worker not found");
        worker_pool_storage* pool = pool_for_index(slot);
        if (!pool)
            throw std::runtime_error("Binded worker not found");

        {
            fast_task::lock_guard guard(pool->no_race);
            if (pool->closing)
                return;
            pool->closing = true;
        }
        if (pool->config.allow_implicit_start)
            refresh_implicit_pool();

        // Wait until every requested worker has joined the pool, then hand each
        // of them one retire token. A worker is only retired while it is inside
        // poll_all(), so the tokens are queued behind the existing work and the
        // queued tasks still run (unless they are aborted below).
        const uint16_t expected = pool->runtime.target_workers.load(std::memory_order_acquire);
        while (pool->runtime.active_workers.load(std::memory_order_acquire) < expected)
            std::this_thread::yield();

        const uint16_t active = pool->runtime.active_workers.load(std::memory_order_acquire);
        for (uint16_t i = 0; i < active; ++i)
            pool->ops.requeue(*pool, nullptr);
        wake_control(pool->work_event, pool->dormant_event);

        // The destructor drains local deques back into the pool queue *before*
        // dropping active_workers, so once the counter reaches zero the queue is
        // complete. It is also the last moment the storage may be touched by a
        // worker (§2.17).
        while (pool->runtime.active_workers.load(std::memory_order_acquire) != 0)
            std::this_thread::yield();

        // Collect everything the pool still owns.
        std::vector<task_object*> drained;
        pool->ops.drain_all(*pool, drained);

        // Keep the slot registered while the drained tasks are accounted:
        // task_mark_completed() and retarget_task() resolve the owning pool
        // through the table, so clearing it first would push the decrement onto
        // the global counter and underflow it. The slot is the only way
        // route_task() reaches the storage, so it is released right before the
        // storage is destroyed.
        for (task_object* obj : drained) {
            task curr_task = task::adopt(obj);
            if (!curr_task)
                continue;
            if (!abort_tasks) {
                // Graceful close: move the task (and its accounting) to the
                // global pool and let a worker there run it.
                retarget_task(*obj, global_storage());
                transfer_task(std::move(curr_task));
                continue;
            }
            bool should_decrement = false;
            {
                fast_task::lock_guard task_guard(get_data(curr_task));
                if (!get_data(curr_task).get_completed()) {
                    get_data(curr_task).set_completed(true);
                    should_decrement = true;
                }
            }
            // Sets `ended`, so task_object::free() will not decrement a second
            // time when the last reference is released.
            get_data(curr_task).end_of_life_notify();
            if (should_decrement)
                task_mark_completed(get_data(curr_task));
        }

        release_pool_slot(slot);

        // `ops` is copied out before the destroy: deallocate reads the type of
        // the concrete storage, which only the vtable-carrying object knows.
        worker_pool_ops ops = pool->ops;
        ops.deallocate(*pool);
    }

    void create_executor(size_t count) {
        for (size_t i = 0; i < count; i++) {
            ++glob.thread_count;
            fast_task::native::thread(taskExecutor, false, false).detach();
        }
    }

    size_t total_executors() {
        // O(1): worker_context maintains the sum. This is called from the
        // publish path (start/schedule_until), so a table walk here would cost
        // hundreds of nanoseconds per task.
        return glob.total_active_workers.load(std::memory_order_acquire);
    }

    void reduce_executor(size_t count) {
        for (size_t i = 0; i < count; i++)
            transfer_task(task(nullptr));
    }

    void become_task_executor() {
        ++glob.thread_count;
        taskExecutor();
    }

    void await_no_tasks(bool be_executor) {
        if (be_executor && !get_loc()) {
            ++glob.thread_count;
            taskExecutor(true);
        } else {
            mutex_unify uni(glob.task_thread_safety);
            fast_task::unique_lock l(uni);

            while (any_pool_work() || !glob.timed_wheel.empty() || total_executing_tasks()) {
                if (!total_executors())
                    create_executor(1);

                // During shut_down() this loop runs while shutdown_requested is
                // set: that flag means "flush the timing wheel and drain". The
                // workers normally do that from driver_context::poll(), but if
                // the executor set is empty or every worker is parked, nobody
                // would ever clear the wheel and executing_tasks would never
                // reach zero. Drive one poll here, under driver_lock, to make
                // the drain independent of worker availability.
                if (glob.shutdown_requested.load(std::memory_order_acquire)) {
                    l.unlock();
                    if (glob.driver.driver_lock.try_lock()) {
                        std::unique_lock<fast_task::native::spin_lock> driver_guard(glob.driver.driver_lock, std::adopt_lock);
                        glob.driver.poll(nullptr);
                    }
                    l.lock();
                }

                // Bounded: the poll above can publish work that another thread
                // executes, and its notification can race with the unlock/lock
                // window around the poll.
                glob.no_tasks_execute_notifier.wait_for(l, std::chrono::milliseconds(10));
            }
        }
    }

    void await_end_tasks(bool be_executor) {
        if (be_executor && !get_loc()) {
            while (total_executing_tasks()) {
                try {
                    ++glob.thread_count;
                    taskExecutor(true, true);
                } catch (...) {
                    throw;
                }
            }
        } else {
            mutex_unify uni(glob.task_thread_safety);
            fast_task::unique_lock l(uni);

            if (get_loc())
                while (total_executing_tasks() != 1) {
                    if (!total_executors())
                        create_executor(1);
                    glob.no_tasks_execute_notifier.wait(l);
                }
            else
                while (total_executing_tasks()) {
                    if (!total_executors())
                        create_executor(1);
                    glob.no_tasks_execute_notifier.wait(l);
                }
        }
    }

    void explicit_start_timer() {
        startTimeController();
    }

    void shut_down() {
        {
            fast_task::unique_lock guard(glob.task_thread_safety);
            glob.shutdown_requested.store(true, std::memory_order_release);
            glob.driver.wake();
        }
        await_no_tasks();
        glob.shutdown_requested.store(false, std::memory_order_release);

        for (uint8_t i = 0; i < user_pool_count; ++i) {
            if (pool_for_index(i))
                close_bind_only_executor(i);
        }

        {
            fast_task::unique_lock guard(glob.task_thread_safety);
            glob.executor_shutting_down.store(true, std::memory_order_release);
            wake_all_pools();
            while (total_executors())
                glob.executor_shutdown_notifier.wait(guard);
        }

        glob.time_control_enabled.store(false);
        glob.driver.wake();

        {
            fast_task::unique_lock guard(glob.task_thread_safety);
            while (glob.thread_count.load())
                glob.executor_shutdown_notifier.wait(guard);
        }
        {
            // Release the last references: a drained task is adopted and
            // immediately dropped, which is what frees it.
            auto& global = global_storage();
            std::vector<task_object*> leftovers;
            global.ops.drain_all(global, leftovers);
            for (task_object* raw : leftovers)
                task::adopt(raw);
        }
        glob.executor_shutting_down.store(false, std::memory_order_release);
    }

    const task& current_context_task() {
        static const task empty;
        return get_loc() ? get_loc()->curr_task : empty;
    }

    void request_stw(const std::function<void()>& func) {
        if (!get_loc())
            unsafe_perform_stop_the_world(func);
        else
            throw invalid_native_context{};
    }

    void clean_up() {
        await_no_tasks();
        auto& loc = get_alloc_loc();
        loc.task_cache.release();
        loc.timing_cache.release();
        auto& global = global_storage();
        global.ops.drain_cold(global);
        glob.gba.claim_unused();
        glob.timing_alloc.claim_unused();
    }

    void local_clean_up() {
        auto& loc = get_alloc_loc();
        loc.task_cache.release();
        loc.timing_cache.release();
    }

    bool preemption_enabled() {
#ifdef FT_ENABLE_PREEMPTIVE_SCHEDULER
        return true;
#else
        return false;
#endif
    }
}
