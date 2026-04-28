// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <task.hpp>
#include <tasks/_internal.hpp>

namespace fast_task::scheduler {
    void schedule_until(std::shared_ptr<task>&& task, std::chrono::high_resolution_clock::time_point time_point) {
        schedule_until(task, time_point);
    }

    void schedule_until(const std::shared_ptr<task>& _task, std::chrono::high_resolution_clock::time_point time_point) {
        if (!total_executors())
            create_executor(1);
        std::shared_ptr<task> lgr_task = _task;
        if (get_data(lgr_task).started)
            return;
        get_data(lgr_task).started = true;
        ++glob.executing_tasks;

        if (glob.shutdown_requested.load(std::memory_order_acquire)) {
            transfer_task(std::move(lgr_task));
            return;
        }

        if (!glob.time_control_enabled)
            startTimeController();
        fast_task::unique_lock guard(glob.task_timer_safety);
        if (can_be_scheduled_task_to_hot())
            unsafe_put_task_to_timed_queue(glob.timed_tasks, time_point, lgr_task);
        else
            unsafe_put_task_to_timed_queue(glob.cold_timed_tasks, time_point, lgr_task);
        glob.time_notifier.notify_one();
        glob.tasks_notifier.notify_one();
        guard.unlock();
    }

    void start(std::list<std::shared_ptr<task>>& tasks) {
        for (auto& it : tasks)
            start(it);
    }

    void start(std::vector<std::shared_ptr<task>>& tasks) {
        for (auto& it : tasks)
            start(it);
    }

    void start(std::shared_ptr<task>&& lgr_task) {
        start(lgr_task);
    }

    void start(const std::shared_ptr<task>& tsk) {
        if (!total_executors())
            create_executor(1);
        std::shared_ptr<task> lgr_task = tsk;
        if (get_data(lgr_task).started) {
#ifdef FT_ENABLE_ABORT_IF_ALREADY_STARTED
            assert(false && "The task is already started.");
            std::abort();
#endif
            return;
        }
        get_data(lgr_task).started = true;
        ++glob.executing_tasks;
        transfer_task(std::move(lgr_task));
    }

    uint16_t create_bind_only_executor(uint16_t fixed_count, bool allow_implicit_start, executor_policy policy) {
        fast_task::lock_guard guard(glob.binded_workers_safety);
        uint16_t try_count = 0;
        uint16_t id = (uint16_t)glob.binded_workers.size();
    is_not_id:
        while (glob.binded_workers.contains(id)) {
            if (try_count == UINT16_MAX)
                throw std::runtime_error("Too many binded workers");
            try_count++;
            id++;
        }
        if (id == (uint16_t)-1)
            goto is_not_id;
        glob.binded_workers[id].allow_implicit_start = allow_implicit_start;
        glob.binded_workers[id].fixed_size = (bool)fixed_count;
        glob.binded_workers[id].policy = policy;
        glob.binded_workers[id].expected_executors = fixed_count;
        for (size_t i = 0; i < fixed_count; i++) {
            ++glob.thread_count;
            fast_task::thread(bindedTaskExecutor, id).detach();
        }
        return id;
    }

    void assign_bind_only_executor(uint16_t id, uint16_t fixed_count, bool allow_implicit_start, executor_policy policy) {
        fast_task::lock_guard guard(glob.binded_workers_safety);
        if (id == (uint16_t)-1)
            throw std::runtime_error("Invalid id");

        uint16_t current_expected = 0;
        if (!glob.binded_workers.contains(id)) {
            glob.binded_workers[id].allow_implicit_start = allow_implicit_start;
            glob.binded_workers[id].fixed_size = (bool)fixed_count;
            glob.binded_workers[id].policy = policy;
        } else {
            fast_task::lock_guard ctx_guard(glob.binded_workers[id].no_race);
            if (glob.binded_workers[id].in_close)
                throw std::runtime_error("Worker is closing");
            // Use expected_executors (threads already spawned/committed), not
            // context.executors (threads that have actually started), so that
            // slow-starting threads are not spawned a second time.
            current_expected = glob.binded_workers[id].expected_executors;
            glob.binded_workers[id].allow_implicit_start = allow_implicit_start;
            glob.binded_workers[id].fixed_size = (bool)fixed_count;
            glob.binded_workers[id].policy = policy;
            glob.binded_workers[id].expected_executors = fixed_count;
        }

        if (fixed_count > current_expected) {
            size_t diff = fixed_count - current_expected;
            for (size_t i = 0; i < diff; i++) {
                ++glob.thread_count;
                fast_task::thread(bindedTaskExecutor, id).detach();
            }
        }
    }

    void close_bind_only_executor(uint16_t id) {
        mutex_unify unify(glob.binded_workers_safety);
        fast_task::unique_lock guard(unify);
        decltype(glob.binded_workers[id].tasks) transfer_tasks;
        if (!glob.binded_workers.contains(id)) {
            throw std::runtime_error("Binded worker not found");
        } else {
            auto& context = glob.binded_workers[id];
            // Wait for all spawned executor threads to start before closing.
            // They acquire binded_workers_safety before incrementing context.executors,
            // so we must release our lock temporarily to avoid deadlock.
            {
                uint16_t expected = context.expected_executors;
                while (context.executors < expected) {
                    guard.unlock();
                    std::this_thread::yield();
                    guard.lock();
                }
            }

            fast_task::unique_lock context_lock(context.no_race);
            if (context.in_close)
                return;
            context.in_close = true;

            std::swap(transfer_tasks, context.tasks);
            for (uint16_t i = 0; i < context.executors; i++) {
                std::shared_ptr<task> tsk = std::make_shared<task>(nullptr);
                tsk->set_worker_id(id);
                context.tasks.enqueue(tsk);
            }

            context.new_task_notifier.notify_all();
            {
                multiply_mutex mmut{unify, context.no_race};
                mutex_unify mmut_unify(mmut);
                fast_task::unique_lock re_lock(mmut_unify, fast_task::adopt_lock);
                while (context.executors != 0)
                    context.on_closed_notifier.wait(re_lock);
                re_lock.release();
            }

            context_lock.unlock();
            glob.binded_workers.erase(id);
        }
        std::shared_ptr<task> task;
        while (transfer_tasks.try_dequeue(task))
            transfer_task(std::move(task));
    }

    void create_executor(size_t count) {
        for (size_t i = 0; i < count; i++) {
            ++glob.thread_count;
            fast_task::thread(taskExecutor, false, false).detach();
        }
    }

    size_t total_executors() {
        return glob.executors;
    }

    void reduce_executor(size_t count) {
        for (size_t i = 0; i < count; i++) {
            start(std::make_shared<task>(nullptr));
        }
    }

    void become_task_executor() {
        try {
            ++glob.thread_count;
            taskExecutor();
            loc.context_in_swap = false;
            loc.is_task_thread = false;
            loc.curr_task = nullptr;
        } catch (...) {
            loc.context_in_swap = false;
            loc.is_task_thread = false;
            loc.curr_task = nullptr;
            throw;
        }
    }

    void await_no_tasks(bool be_executor) {
        if (be_executor && !loc.is_task_thread) {
            ++glob.thread_count;
            taskExecutor(true);
        } else {
            mutex_unify uni(glob.task_thread_safety);
            fast_task::unique_lock l(uni);

            static auto tasks_present = []() -> bool {
                auto queue = glob.executors_queues.load();
                if (!queue)
                    return false;
                for (auto& q : *queue)
                    if (q->size())
                        return true;
                return false;
            };

            while (tasks_present() || glob.cold_tasks.size_approx() || glob.timed_tasks.size() || glob.cold_timed_tasks.size() || glob.executing_tasks) {
                if (!total_executors())
                    create_executor(1);

                if (glob.shutdown_requested.load(std::memory_order_acquire)) {
                    //BUG
                    // If shutdown is requested and there is no runnable/waiting task state
                    // left in scheduler queues or runtime, do not block forever on a leaked
                    // accounting value in glob.executing_tasks.
                    // This solution is bad and just reduces the amount of stuck tasks. I would like to fix this in other way.
                    //TODO
                    // find the reason and way to safely shutdown the tasks
                    if (!tasks_present() &&
                        glob.cold_tasks.size_approx() == 0 &&
                        glob.timed_tasks.empty() &&
                        glob.cold_timed_tasks.empty() &&
                        glob.in_run_tasks.load() == 0 &&
                        glob.tasks_in_swap.load() == 0) {
                        break;
                    }
                }

                // Use timed wait to recover from rare lost-wakeup: notify_all()
                // moves resume_task under values.no_race (not task_thread_safety),
                // so a notification can be missed if it fires between the while
                // condition check and the wait registration.  A 1 ms timeout
                // ensures we re-check and exit even if the wake was lost.
                glob.no_tasks_execute_notifier.wait_until(l, std::chrono::high_resolution_clock::now() + std::chrono::milliseconds(1));
            }
        }
    }

    void await_end_tasks(bool be_executor) {
        if (be_executor && !loc.is_task_thread) {
            while (glob.executing_tasks) {
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

            if (loc.is_task_thread)
                while (glob.executing_tasks != 1) {
                    if (!total_executors())
                        create_executor(1);
                    glob.no_tasks_execute_notifier.wait_until(l, std::chrono::high_resolution_clock::now() + std::chrono::milliseconds(1));
                }
            else
                while (glob.executing_tasks) {
                    if (!total_executors())
                        create_executor(1);
                    glob.no_tasks_execute_notifier.wait_until(l, std::chrono::high_resolution_clock::now() + std::chrono::milliseconds(1));
                }
        }
    }

    void explicit_start_timer() {
        startTimeController();
    }

    void shut_down() {
        {
            fast_task::unique_lock guard(glob.task_thread_safety);
            fast_task::unique_lock lock(glob.task_timer_safety);
            glob.shutdown_requested.store(true, std::memory_order_release);
            glob.time_notifier.notify_all();
        }
        await_no_tasks();
        glob.shutdown_requested.store(false, std::memory_order_release);

        while (!glob.binded_workers.empty())
            close_bind_only_executor(glob.binded_workers.begin()->first);

        fast_task::unique_lock guard(glob.task_thread_safety);
        // All user tasks have finished (await_no_tasks above), so executors are
        // idle (in tasks_notifier.wait or in the retry spin).  Set the shutdown
        // flag before waiting so that both already-idle executors AND any threads
        // that started too late to receive a null-task will exit immediately when
        // they reach the flag check, instead of blocking on tasks_notifier.wait.
        glob.executor_shutting_down.store(true, std::memory_order_release);
        glob.tasks_notifier.notify_all();
        while (glob.executors)
            glob.executor_shutdown_notifier.wait(guard);
        glob.time_control_enabled = false;
        glob.time_notifier.notify_all();
        guard.unlock();

        while (glob.thread_count.load())
            std::this_thread::yield();
        // Drain any stray tasks that may have been queued before shutdown.
        {
            std::shared_ptr<task> tmp;
            while (glob.tasks.try_dequeue(tmp)) {}
            while (glob.cold_tasks.try_dequeue(tmp)) {}
        }
        glob.executor_shutting_down.store(false, std::memory_order_release);
    }

    const std::shared_ptr<task>& current_context_task() {
        return loc.curr_task;
    }

    void request_stw(const std::function<void()>& func) {
        if (!loc.is_task_thread)
            unsafe_perform_stop_the_world(func);
        else
            throw invalid_native_context{};
    }

    void clean_up() {
        await_no_tasks();
        decltype(glob.cold_tasks) cold;
        glob.executors_queues = nullptr;
        glob.cold_tasks.swap(cold);
        glob.timed_tasks.shrink_to_fit();
    }
}
