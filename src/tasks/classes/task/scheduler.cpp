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
        {
            fast_task::unique_lock guard(glob.task_thread_safety);
            if (get_data(lgr_task).started)
                return;
            if (!glob.time_control_enabled)
                startTimeController();
        }
        fast_task::unique_lock guard(glob.task_timer_safety);
        if (can_be_scheduled_task_to_hot())
            unsafe_put_task_to_timed_queue(glob.timed_tasks, time_point, lgr_task);
        else
            unsafe_put_task_to_timed_queue(glob.cold_timed_tasks, time_point, lgr_task);
        get_data(lgr_task).started = true;
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
        if (get_data(lgr_task).started)
            return;
        {
            fast_task::lock_guard guard(glob.task_thread_safety);
            if (get_data(lgr_task).started)
                return;
            if (can_be_scheduled_task_to_hot())
                glob.tasks.push(lgr_task);
            else
                glob.cold_tasks.push(lgr_task);
            get_data(lgr_task).started = true;
            glob.tasks_notifier.notify_one();
        }
    }

    uint16_t create_bind_only_executor(uint16_t fixed_count, bool allow_implicit_start) {
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
        for (size_t i = 0; i < fixed_count; i++) {
            ++glob.thread_count;
            fast_task::thread(bindedTaskExecutor, id).detach();
        }
        return id;
    }

    void assign_bind_only_executor(uint16_t id, uint16_t fixed_count, bool allow_implicit_start) {
        fast_task::lock_guard guard(glob.binded_workers_safety);
        if (glob.binded_workers.contains(id))
            throw std::runtime_error("Worker already assigned!");
        if (id == (uint16_t)-1)
            throw std::runtime_error("Invalid id");
        glob.binded_workers[id].allow_implicit_start = allow_implicit_start;
        glob.binded_workers[id].fixed_size = (bool)fixed_count;
        for (size_t i = 0; i < fixed_count; i++) {
            ++glob.thread_count;
            fast_task::thread(bindedTaskExecutor, id).detach();
        }
    }

    void close_bind_only_executor(uint16_t id) {
        mutex_unify unify(glob.binded_workers_safety);
        fast_task::unique_lock guard(unify);
        std::list<std::shared_ptr<task>> transfer_tasks;
        if (!glob.binded_workers.contains(id)) {
            throw std::runtime_error("Binded worker not found");
        } else {
            auto& context = glob.binded_workers[id];
            fast_task::unique_lock context_lock(context.no_race);
            if (context.in_close)
                return;
            context.in_close = true;

            std::swap(transfer_tasks, context.tasks);
            for (uint16_t i = 0; i < context.executors; i++) {
                std::shared_ptr<task> tsk = std::make_shared<task>(nullptr);
                tsk->set_worker_id(id);
                context.tasks.emplace_back(tsk);
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
        for (std::shared_ptr<task>& task : transfer_tasks) {
            get_data(task).bind_to_worker_id = (uint16_t)-1;
            transfer_task(task);
        }
    }

    void create_executor(size_t count) {
        for (size_t i = 0; i < count; i++) {
            ++glob.thread_count;
            fast_task::thread(taskExecutor, false, false).detach();
        }
    }

    size_t total_executors() {
        fast_task::lock_guard guard(glob.task_thread_safety);
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
            while (glob.tasks.size() || glob.cold_tasks.size() || glob.timed_tasks.size() || glob.cold_timed_tasks.size()) {
                if (!total_executors())
                    create_executor(1);
                glob.no_tasks_notifier.wait(l);
            }
        }
    }

    void await_end_tasks(bool be_executor) {
        if (be_executor && !loc.is_task_thread) {
            fast_task::unique_lock l(glob.task_thread_safety);
        binded_workers:
            while (glob.tasks.size() || glob.cold_tasks.size() || glob.timed_tasks.size() || glob.cold_timed_tasks.size() ||  glob.tasks_in_swap || glob.in_run_tasks) {
                l.unlock();
                try {
                    ++glob.thread_count;
                    taskExecutor(true, true);
                } catch (...) {
                    l.lock();
                    throw;
                }
                l.lock();
            }
            fast_task::lock_guard lock(glob.binded_workers_safety);
            bool binded_tasks_empty = true;
            for (auto& contexts : glob.binded_workers)
                if (contexts.second.tasks.size())
                    binded_tasks_empty = false;
            if (!binded_tasks_empty)
                goto binded_workers;
        } else {
        binded_workers_:;
            {
                mutex_unify uni(glob.task_thread_safety);
                fast_task::unique_lock l(uni);

                if (loc.is_task_thread)
                    while ((glob.tasks.size() || glob.cold_tasks.size() || glob.timed_tasks.size() || glob.cold_timed_tasks.size()) &&  glob.tasks_in_swap != 1 && glob.in_run_tasks != 1) {
                        if (!total_executors())
                            create_executor(1);
                        glob.no_tasks_execute_notifier.wait(l);
                    }
                else
                    while (glob.tasks.size() || glob.cold_tasks.size() || glob.timed_tasks.size() || glob.cold_timed_tasks.size() || glob.tasks_in_swap || glob.in_run_tasks) {
                        if (!total_executors())
                            create_executor(1);
                        glob.no_tasks_execute_notifier.wait(l);
                    }
            }
            {
                fast_task::lock_guard lock(glob.binded_workers_safety);
                bool binded_tasks_empty = true;
                for (auto& contexts : glob.binded_workers)
                    if (contexts.second.tasks.size())
                        binded_tasks_empty = false;
                if (binded_tasks_empty)
                    return;
            }
            goto binded_workers_;
        }
    }

    void explicit_start_timer() {
        startTimeController();
    }

    void shut_down() {
        while (!glob.binded_workers.empty())
            close_bind_only_executor(glob.binded_workers.begin()->first);

        fast_task::unique_lock guard(glob.task_thread_safety);
        size_t executors = glob.executors;
        for (size_t i = 0; i < executors; i++)
            glob.tasks.emplace(new task(nullptr, {}));
        glob.tasks_notifier.notify_all();
        while (glob.executors)
            glob.executor_shutdown_notifier.wait(guard);
        glob.time_control_enabled = false;
        glob.time_notifier.notify_all();
    }

    void FT_API request_stw(const std::function<void()>& func) {
        if (!loc.is_task_thread)
            unsafe_perform_stop_the_world(func);
        else
            throw invalid_native_context{};
    }

    void clean_up() {
        await_no_tasks();
        std::queue<std::shared_ptr<task>> e0;
        std::queue<std::shared_ptr<task>> e1;
        glob.tasks.swap(e0);
        glob.cold_tasks.swap(e1);
        glob.timed_tasks.shrink_to_fit();
    }
}