// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <tasks.hpp>
#include <tasks/_internal.hpp>

namespace fast_task {

    task::task(task&& mov) noexcept
        : fres(std::move(mov.fres)) {
        ex_handle = mov.ex_handle;
        func = mov.func;
        time_end_flag = mov.time_end_flag;
        awaked = mov.awaked;
        started = mov.started;
    }

    task::~task() {
        if (!started) {
            --glob.planned_tasks;
            if (task::max_running_tasks)
                glob.can_planned_new_notifier.notify_one();
        }
    }

    void task::set_auto_bind_worker(bool enable) {
        auto_bind_worker = enable;
        if (enable)
            bind_to_worker_id = -1;
    }

    void task::set_worker_id(uint16_t id) {
        bind_to_worker_id = id;
        auto_bind_worker = false;
    }

    void task::schedule(std::shared_ptr<task>&& task, size_t milliseconds) {
        schedule_until(task, std::chrono::high_resolution_clock::now() + std::chrono::milliseconds(milliseconds));
    }

    void task::schedule(const std::shared_ptr<task>& task, size_t milliseconds) {
        schedule_until(task, std::chrono::high_resolution_clock::now() + std::chrono::milliseconds(milliseconds));
    }

    void task::schedule_until(std::shared_ptr<task>&& task, std::chrono::high_resolution_clock::time_point time_point) {
        schedule_until(task, time_point);
    }

    void task::schedule_until(const std::shared_ptr<task>& _task, std::chrono::high_resolution_clock::time_point time_point) {
        if (!total_executors())
            create_executor(1);
        std::shared_ptr<task> lgr_task = _task;
        if (lgr_task->started)
            return;
        {
            std::unique_lock guard(glob.task_thread_safety);
            if (lgr_task->started)
                return;
        }
        std::unique_lock guard(glob.task_timer_safety);
        if (can_be_scheduled_task_to_hot())
            unsafe_put_task_to_timed_queue(glob.timed_tasks, time_point, lgr_task);
        else
            unsafe_put_task_to_timed_queue(glob.cold_timed_tasks, time_point, lgr_task);
        lgr_task->started = true;
        glob.tasks_notifier.notify_one();
        guard.unlock();
        if (!glob.time_control_enabled)
            startTimeController();
    }

    void task::start(std::list<std::shared_ptr<task>>& lgr_task) {
        for (auto& it : lgr_task)
            start(it);
    }

    void task::start(std::shared_ptr<task>&& lgr_task) {
        start(lgr_task);
    }

    bool task::has_result(std::shared_ptr<task>& lgr_task) {
        return !lgr_task->end_of_life;
    }

    void task::await_task(const std::shared_ptr<task>& lgr_task, bool make_start) {
        if (!total_executors())
            create_executor(1);

        if (!lgr_task->started && make_start)
            task::start(lgr_task);
        mutex_unify uni(lgr_task->no_race);
        std::unique_lock l(uni);
        lgr_task->fres.awaitEnd(l);
    }

    void task::start(const std::shared_ptr<task>& tsk) {
        if (!total_executors())
            create_executor(1);
        std::shared_ptr<task> lgr_task = tsk;
        if (lgr_task->started)
            return;
        {
            std::lock_guard guard(glob.task_thread_safety);
            if (lgr_task->started)
                return;
            if (can_be_scheduled_task_to_hot())
                glob.tasks.push(lgr_task);
            else
                glob.cold_tasks.push(lgr_task);
            lgr_task->started = true;
            glob.tasks_notifier.notify_one();
        }
    }

    uint16_t task::create_bind_only_executor(uint16_t fixed_count, bool allow_implicit_start) {
        std::lock_guard guard(glob.binded_workers_safety);
        uint16_t try_count = 0;
        uint16_t id = glob.binded_workers.size();
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
        for (size_t i = 0; i < fixed_count; i++)
            std::thread(bindedTaskExecutor, id).detach();
        return id;
    }

    void task::close_bind_only_executor(uint16_t id) {
        mutex_unify unify(glob.binded_workers_safety);
        std::unique_lock guard(unify);
        std::list<std::shared_ptr<task>> transfer_tasks;
        if (!glob.binded_workers.contains(id)) {
            throw std::runtime_error("Binded worker not found");
        } else {
            auto& context = glob.binded_workers[id];
            std::unique_lock context_lock(context.no_race);
            if (context.in_close)
                return;
            context.in_close = true;
            for (uint16_t i = 0; i < context.executors; i++) {
                context.tasks.emplace_back(new task(nullptr));
            }
            context.new_task_notifier.notify_all();
            {
                multiply_mutex mmut{unify, context.no_race};
                mutex_unify mmut_unify(mmut);
                std::unique_lock re_lock(mmut_unify, std::adopt_lock);
                while (context.executors != 0)
                    context.on_closed_notifier.wait(re_lock);
                re_lock.release();
            }
            std::swap(transfer_tasks, context.tasks);
            context_lock.unlock();
            glob.binded_workers.erase(id);
        }
        for (std::shared_ptr<task>& task : transfer_tasks) {
            task->bind_to_worker_id = -1;
            transfer_task(task);
        }
    }

    void task::create_executor(size_t count) {
        for (size_t i = 0; i < count; i++)
            std::thread(taskExecutor, false).detach();
    }

    size_t task::total_executors() {
        std::lock_guard guard(glob.task_thread_safety);
        return glob.executors;
    }

    void task::reduce_executor(size_t count) {
        for (size_t i = 0; i < count; i++) {
            start(std::make_shared<task>(nullptr));
        }
    }

    void task::become_task_executor() {
        try {
            taskExecutor();
            loc.context_in_swap = false;
            loc.is_task_thread = false;
            loc.curr_task = nullptr;
        } catch (...) {
            loc.context_in_swap = false;
            loc.is_task_thread = false;
            loc.curr_task = nullptr;
        }
    }

    void task::await_no_tasks(bool be_executor) {
        if (be_executor && !loc.is_task_thread)
            taskExecutor(true);
        else {
            mutex_unify uni(glob.task_thread_safety);
            std::unique_lock l(uni);
            while (glob.tasks.size() || glob.cold_tasks.size() || glob.timed_tasks.size() || glob.cold_timed_tasks.size()) {
                if (!total_executors())
                    create_executor(1);
                glob.no_tasks_notifier.wait(l);
            }
        }
    }

    void task::await_end_tasks(bool be_executor) {
        if (be_executor && !loc.is_task_thread) {
            std::unique_lock l(glob.task_thread_safety);
        binded_workers:
            while (glob.tasks.size() || glob.cold_tasks.size() || glob.timed_tasks.size() || glob.cold_timed_tasks.size() || glob.in_exec || glob.tasks_in_swap) {
                l.unlock();
                try {
                    taskExecutor(true);
                } catch (...) {
                    l.lock();
                    throw;
                }
                l.lock();
            }
            std::lock_guard lock(glob.binded_workers_safety);
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
                std::unique_lock l(uni);

                if (loc.is_task_thread)
                    while ((glob.tasks.size() || glob.cold_tasks.size() || glob.timed_tasks.size() || glob.cold_timed_tasks.size()) && glob.in_exec != 1 && glob.tasks_in_swap != 1) {
                        if (!total_executors())
                            create_executor(1);
                        glob.no_tasks_execute_notifier.wait(l);
                    }
                else
                    while (glob.tasks.size() || glob.cold_tasks.size() || glob.timed_tasks.size() || glob.cold_timed_tasks.size() || glob.in_exec || glob.tasks_in_swap) {
                        if (!total_executors())
                            create_executor(1);
                        glob.no_tasks_execute_notifier.wait(l);
                    }
            }
            {
                std::lock_guard lock(glob.binded_workers_safety);
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

    void task::await_multiple(std::list<std::shared_ptr<task>>& tasks, bool pre_started, bool release) {
        if (!pre_started) {
            for (auto& it : tasks)
                task::start(it);
        }
        if (release) {
            for (auto& it : tasks) {
                await_task(it, false);
                it = nullptr;
            }
        } else
            for (auto& it : tasks)
                await_task(it, false);
    }

    void task::await_multiple(std::shared_ptr<task>* tasks, size_t len, bool pre_started, bool release) {
        if (!pre_started) {
            std::shared_ptr<task>* iter = tasks;
            size_t count = len;
            while (count--)
                task::start(*iter++);
        }
        if (release) {
            while (len--) {
                await_task(*tasks, false);
                (*tasks++) = nullptr;
            }
        } else
            while (len--)
                await_task(*tasks, false);
    }

    void task::sleep(size_t milliseconds) {
        sleep_until(std::chrono::high_resolution_clock::now() + std::chrono::milliseconds(milliseconds));
    }

    void task::check_cancellation() {
        if (loc.is_task_thread)
            checkCancellation();
        else
            throw std::runtime_error("Thread attempted check cancellation in non task enviro");
    }

    void task::self_cancel() {
        if (loc.is_task_thread)
            throw task_cancellation();
        else
            throw std::runtime_error("Thread attempted cancel self, like task");
    }

    void task::notify_cancel(std::shared_ptr<task>& lgr_task) {
        lgr_task->make_cancel = true;
    }

    void task::notify_cancel(std::list<std::shared_ptr<task>>& tasks) {
        for (auto& it : tasks)
            notify_cancel(it);
    }

    size_t task::task_id() {
        if (!loc.is_task_thread)
            return 0;
        else
            return std::hash<size_t>()(reinterpret_cast<size_t>(&*loc.curr_task));
    }

    bool task::is_task() {
        return loc.is_task_thread;
    }

    void task::clean_up() {
        task::await_no_tasks();
        std::queue<std::shared_ptr<task>> e0;
        std::queue<std::shared_ptr<task>> e1;
        glob.tasks.swap(e0);
        glob.cold_tasks.swap(e1);
        glob.timed_tasks.shrink_to_fit();
    }

    std::shared_ptr<task> task::dummy_task() {
        return std::make_shared<task>([] {});
    }

    void task::explicitStartTimer() {
        startTimeController();
    }

    void task::shutDown() {
        while (!glob.binded_workers.empty())
            task::close_bind_only_executor(glob.binded_workers.begin()->first);

        std::unique_lock guard(glob.task_thread_safety);
        size_t executors = glob.executors;
        for (size_t i = 0; i < executors; i++)
            glob.tasks.emplace(new task(nullptr, {}));
        glob.tasks_notifier.notify_all();
        while (glob.executors)
            glob.executor_shutdown_notifier.wait(guard);
        glob.time_control_enabled = false;
        glob.time_notifier.notify_all();
    }

#pragma optimize("", off)
#if defined(__GNUC__) && !defined(__clang__)
    #pragma GCC push_options
    #pragma GCC optimize("O0")
#endif

    void task::sleep_until(std::chrono::high_resolution_clock::time_point time_point) {
        if (loc.is_task_thread) {
            std::lock_guard guard(loc.curr_task->no_race);
            makeTimeWait(time_point);
            swapCtxRelock(loc.curr_task->no_race);
        } else
            std::this_thread::sleep_until(time_point);
    }

    void task::yield() {
        if (loc.is_task_thread) {
            std::lock_guard guard(glob.task_thread_safety);
            glob.tasks.push(loc.curr_task);
            swapCtxRelock(glob.task_thread_safety);
        } else
            throw std::runtime_error("Thread attempt return yield task in non task enviro");
    }

#if defined(__GNUC__) && !defined(__clang__)
    #pragma GCC pop_options
#endif
#pragma optimize("", on)
}