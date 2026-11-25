// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)


#include <chrono>
#include <thread>

#include <fast_task/task.hpp>
#include <tasks/_internal.hpp>

namespace fast_task::scheduler {
    namespace {
        size_t total_executing_tasks() {
            size_t total = 0;
            for (auto& slot : glob.pools.slots) {
                auto* pool = slot.load(std::memory_order_acquire);
                if (pool)
                    total += pool->runtime.executing_tasks.load(std::memory_order_acquire);
            }
            return total;
        }

        bool any_pool_work() {
            for (auto& slot : glob.pools.slots) {
                auto* pool = slot.load(std::memory_order_acquire);
                if (!pool)
                    continue;
                if (pool->ops.queue.pending(*pool) != 0)
                    return true;
                if (pool->ops.executors.any_work(*pool))
                    return true;
            }
            return false;
        }

        void wake_all_pools() {
            for (auto& slot : glob.pools.slots) {
                auto* pool = slot.load(std::memory_order_acquire);
                if (pool)
                    wake_control(*pool);
            }
        }

        void resume_all_pools() {
            for (auto& slot : glob.pools.slots) {
                auto* pool = slot.load(std::memory_order_acquire);
                if (!pool)
                    continue;
                if (pool->runtime.paused.load(std::memory_order_acquire)) {
                    pool->runtime.paused.store(false, std::memory_order_release);
                    wake_control(*pool);
                }
            }
        }
    }

    void ensure_global_worker() {
        if (threads_manager::total_active() != 0)
            return;
        auto& storage = global_storage();
        if (storage.threads.live() == 0)
            spawn_pool_worker(storage, 1);
    }

    void schedule_until(task&& task, fast_task::time_point time_point) {
        schedule_until(task, time_point);
    }

    void schedule_until(const task& _task, fast_task::time_point time_point) {
        if (!_task)
            return;
        ensure_global_worker();
        task lgr_task = _task;
        uint16_t awake_check = 0;
        {
            auto& td = get_data(lgr_task);
            fast_task::lock_guard guard(td);
            if (td.is_running() || td.is_ended()) {
#ifdef FT_ENABLE_ABORT_IF_ALREADY_STARTED
                assert(false && "The task is already running or stopped.");
                std::abort();
#endif
                return;
            }
            if (td.is_scheduled() && (!td.is_suspended() && td.get_is_on_scheduler())) {
#ifdef FT_ENABLE_ABORT_IF_ALREADY_STARTED
                assert(false && "The task is already started.");
                std::abort();
#endif
                return;
            }
            if (td.is_created())
                task_account_pool(td).runtime.executing_tasks.fetch_add(1, std::memory_order_acq_rel);

            td.set_status(task_object::status_e::scheduled);
            awake_check = td.awake_check;
        }

        if (glob.shutdown.requested.load(std::memory_order_acquire)) {
            transfer_task(std::move(lgr_task));
            return;
        }

        startTimeController();

        uint64_t ticks = glob.timing.wheel.to_ticks(time_point);
        glob.timing.wheel.insert(ticks, lgr_task, awake_check, !can_be_scheduled_task_to_hot());

        notify_driver_of_timer(ticks);
    }

    void start(std::list<task>& tasks) {
        for (auto& it : tasks)
            start(it);
    }

    void start(std::vector<task>& tasks) {
        for (auto& it : tasks)
            start(it);
    }

    namespace {
        bool claim_created(const task& tsk) noexcept {
            task_object& raw = get_data(tsk);
            task_object::status_e expected = task_object::status_e::created;
            return raw.status.compare_exchange_strong(expected, task_object::status_e::scheduled, std::memory_order_acq_rel, std::memory_order_acquire);
        }
    }

    void start(task&& lgr_task) {
        if (!lgr_task) {
            start(static_cast<const task&>(lgr_task));
            return;
        }
        ensure_global_worker();
        if (claim_created(lgr_task)) {
            route_task(std::move(lgr_task), nullptr, true);
            return;
        }
        start(static_cast<const task&>(lgr_task));
    }

    void start(const task& tsk) {
        ensure_global_worker();

        assert(tsk && "Cannot start an empty task");
        if (!tsk)
            return;

        if (claim_created(tsk)) {
            route_task(task(tsk), nullptr, true);
            return;
        }

        bool pre_scheduled = false;
        {
            auto& td = get_data(tsk);
            fast_task::lock_guard guard(td);

            // Reject if currently executing or completely dead
            if (td.is_running() || td.is_ended()) {
#ifdef FT_ENABLE_ABORT_IF_ALREADY_STARTED
                assert(false && "The task is already running or stopped.");
                std::abort();
#endif
                return;
            }

            // Reject if it is already scheduled but not yet executing
            if (td.is_scheduled() && !td.is_suspended()) {
#ifdef FT_ENABLE_ABORT_IF_ALREADY_STARTED
                assert(false && "The task is already started.");
                std::abort();
#endif
                return;
            }

            pre_scheduled = td.is_created();
            td.set_status(task_object::status_e::scheduled);
        }

        if (pre_scheduled)
            route_task(task(tsk), nullptr, true);
        else
            transfer_task(task(tsk));
    }

    void become_task_executor() {
        threads_manager::count_thread_launch();
        taskExecutor();
    }

    namespace {
        struct no_tasks_waiter_guard {
            no_tasks_waiter_guard() noexcept {
                glob.no_tasks.waiters.fetch_add(1, std::memory_order_acq_rel);
            }

            ~no_tasks_waiter_guard() {
                glob.no_tasks.waiters.fetch_sub(1, std::memory_order_acq_rel);
            }

            no_tasks_waiter_guard(const no_tasks_waiter_guard&) = delete;
            no_tasks_waiter_guard& operator=(const no_tasks_waiter_guard&) = delete;
        };
    }

    void await_no_tasks(bool be_executor) {
        if (be_executor && !get_loc()) {
            threads_manager::count_thread_launch();
            taskExecutor({.mode = worker_entry::until_drained});
        } else {
            mutex_unify uni(glob.no_tasks.guard);
            fast_task::unique_lock l(uni);
            no_tasks_waiter_guard waiter;

            while (any_pool_work() || !glob.timing.wheel.empty() || total_executing_tasks()) {
                ensure_global_worker();

                if (glob.shutdown.requested.load(std::memory_order_acquire)) {
                    l.unlock();
                    if (glob.driver.driver_lock.try_lock()) {
                        std::unique_lock<fast_task::native::spin_lock> driver_guard(glob.driver.driver_lock, std::adopt_lock);
                        glob.driver.poll(nullptr);
                    }
                    l.lock();
                }

                glob.no_tasks.notifier.wait_for(l, std::chrono::milliseconds(10));
            }
        }
    }

    void await_end_tasks(bool be_executor) {
        if (be_executor && !get_loc()) {
            while (total_executing_tasks()) {
                threads_manager::count_thread_launch();
                taskExecutor({.mode = worker_entry::until_drained, .prevent_naming = true});
            }
        } else {
            mutex_unify uni(glob.no_tasks.guard);
            fast_task::unique_lock l(uni);
            no_tasks_waiter_guard waiter;

            if (auto* loc = get_loc(); loc && loc->is_task_thread)
                while (total_executing_tasks() != 1) {
                    ensure_global_worker();
                    glob.no_tasks.notifier.wait_for(l, std::chrono::milliseconds(1));
                }
            else
                while (total_executing_tasks()) {
                    ensure_global_worker();
                    glob.no_tasks.notifier.wait_for(l, std::chrono::milliseconds(1));
                }
        }
    }

    void explicit_start_timer() {
        startTimeController();
    }

    void shut_down() {
        close_dormant_broker();
        {
            fast_task::unique_lock guard(glob.no_tasks.guard);
            glob.shutdown.requested.store(true, std::memory_order_release);
            glob.driver.wake();
        }
        resume_all_pools();
        await_no_tasks();
        glob.shutdown.requested.store(false, std::memory_order_release);

        const size_t self_serving = get_loc() ? 1 : 0;

        {
            fast_task::unique_lock guard(glob.no_tasks.guard);
            glob.shutdown.executors_down.store(true, std::memory_order_release);
            wake_all_pools();
            while (threads_manager::total_active())
                glob.shutdown.notifier.wait_for(guard, std::chrono::milliseconds(1));

            for (auto& slot : glob.pools.slots) {
                if (auto* pool = slot.load(std::memory_order_acquire))
                    pool->threads.set_target(0);
            }
        }
        for (unsigned spins = 0; glob.stw.serving_contexts.load(std::memory_order_acquire) > self_serving; ++spins) {
            if (spins < 1024) {
                std::this_thread::yield();
                continue;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }

        glob.timing.enabled.store(false);
        glob.driver.wake();

        {
            fast_task::unique_lock guard(glob.no_tasks.guard);
            while (threads_manager::thread_count())
                glob.shutdown.notifier.wait_for(guard, std::chrono::milliseconds(1));
        }
        {
            auto& global = global_storage();
            std::vector<task_object*> leftovers;
            global.ops.queue.drain_all(global, leftovers);
            for (task_object* raw : leftovers)
                task::adopt(raw);
        }
        glob.shutdown.executors_down.store(false, std::memory_order_release);
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
        global.ops.queue.drain_cold(global);
        glob.allocators.gba.claim_unused();
        glob.allocators.timing_alloc.claim_unused();
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
