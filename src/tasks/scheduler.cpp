// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <tasks.hpp>
#include <tasks/_internal.hpp>
#include <tasks/util/light_stack.hpp>

namespace fast_task {

    size_t task::max_running_tasks = 0;
    size_t task::max_planned_tasks = 1'000'000'000;

#pragma optimize("", off)
#if defined(__GNUC__) && !defined(__clang__)
    #pragma GCC push_options
    #pragma GCC optimize("O0")
#endif
#pragma region TaskExecutor

    void swapCtx() {
        if (loc.is_task_thread) {
            loc.context_in_swap = true;
            ++glob.tasks_in_swap;
            *loc.stack_current_context = std::move(*loc.stack_current_context).resume();
            loc.context_in_swap = true;
            auto relock_state_0 = loc.curr_task->relock_0;
            auto relock_state_1 = loc.curr_task->relock_1;
            auto relock_state_2 = loc.curr_task->relock_2;
            loc.curr_task->relock_0 = nullptr;
            loc.curr_task->relock_1 = nullptr;
            loc.curr_task->relock_2 = nullptr;
            relock_state_0.relock_end();
            relock_state_1.relock_end();
            relock_state_2.relock_end();
            loc.curr_task->awake_check++;
            --glob.tasks_in_swap;
            loc.context_in_swap = false;
            if (loc.curr_task->invalid_switch_caught) {
                loc.curr_task->invalid_switch_caught = false;
                throw std::runtime_error("Caught task that switched context but not scheduled or finalized self");
            }
        } else
            throw std::runtime_error("swapCtx() not allowed to call in non-task thread or in dispatcher");
    }

    void swapCtxRelock(const mutex_unify& mut0) {
        loc.curr_task->relock_0 = mut0;
        swapCtx();
    }

    void swapCtxRelock(const mutex_unify& mut0, const mutex_unify& mut1, const mutex_unify& mut2) {
        loc.curr_task->relock_0 = mut0;
        loc.curr_task->relock_1 = mut1;
        loc.curr_task->relock_2 = mut2;
        swapCtx();
    }

    void swapCtxRelock(const mutex_unify& mut0, const mutex_unify& mut1) {
        loc.curr_task->relock_0 = mut0;
        loc.curr_task->relock_1 = mut1;
        swapCtx();
    }

    void warmUpTheTasks() {
        if (!task::max_running_tasks && glob.tasks.empty()) {
            std::swap(glob.tasks, glob.cold_tasks);
        } else {
            //TODO: put to warm task asynchroniously, i.e. when task reach end of life state, push new task to warm
            size_t placed = glob.in_run_tasks;
            size_t max_tasks = std::min(task::max_running_tasks - placed, glob.cold_tasks.size());
            for (size_t i = 0; i < max_tasks; ++i) {
                glob.tasks.push(std::move(glob.cold_tasks.front()));
                glob.cold_tasks.pop();
            }
            if (task::max_running_tasks > placed && glob.cold_tasks.empty())
                glob.can_started_new_notifier.notify_all();
        }
    }

    boost::context::continuation context_exec(boost::context::continuation&& sink) {
        *loc.stack_current_context = std::move(sink);
        try {
            checkCancellation();
            loc.curr_task->func();
        } catch (task_cancellation& cancel) {
            forceCancelCancellation(cancel);
        } catch (const boost::context::detail::forced_unwind&) {
            throw;
        } catch (...) {
            loc.ex_ptr = std::current_exception();
        }
        std::lock_guard l(loc.curr_task->no_race);
        loc.curr_task->end_of_life = true;
        loc.curr_task->fres.end_of_life = true;
        loc.curr_task->fres.result_notify.notify_all();
        --glob.in_run_tasks;
        if (task::max_running_tasks)
            glob.can_started_new_notifier.notify_one();
        return std::move(*loc.stack_current_context);
    }

    boost::context::continuation context_ex_handle(boost::context::continuation&& sink) {
        *loc.stack_current_context = std::move(sink);
        try {
            checkCancellation();
            loc.curr_task->ex_handle(loc.ex_ptr);
        } catch (task_cancellation& cancel) {
            forceCancelCancellation(cancel);
        } catch (const boost::context::detail::forced_unwind&) {
            throw;
        } catch (...) {
            loc.ex_ptr = std::current_exception();
        }

        mutex_unify uni(loc.curr_task->no_race);
        std::unique_lock l(uni);
        loc.curr_task->end_of_life = true;
        loc.curr_task->fres.end_of_life = true;
        loc.curr_task->fres.result_notify.notify_all();
        --glob.in_run_tasks;
        if (task::max_running_tasks)
            glob.can_started_new_notifier.notify_one();
        return std::move(*loc.stack_current_context);
    }

    void transfer_task(std::shared_ptr<task>& task) {
        if (task->bind_to_worker_id == (uint16_t)-1) {
            std::lock_guard guard(glob.task_thread_safety);
            glob.tasks.push(std::move(task));
            glob.tasks_notifier.notify_one();
        } else {
            std::unique_lock initializer_guard(glob.binded_workers_safety);
            if (!glob.binded_workers.contains(task->bind_to_worker_id)) {
                initializer_guard.unlock();
                assert("Binded worker context not found");
                std::abort();
            }
            binded_context& extern_context = glob.binded_workers[task->bind_to_worker_id];
            initializer_guard.unlock();
            if (extern_context.in_close) {
                assert("Binded worker context is closed");
                std::abort();
            }
            std::lock_guard guard(extern_context.no_race);
            extern_context.tasks.emplace_back(std::move(task));
            extern_context.new_task_notifier.notify_one();
        }
    }

    void awake_task(std::shared_ptr<task>& task) {
        if (task->bind_to_worker_id == (uint16_t)-1) {
            if (task->auto_bind_worker) {
                std::unique_lock guard(glob.binded_workers_safety);
                for (auto& [id, context] : glob.binded_workers) {
                    if (context.allow_implicit_start) {
                        if (context.in_close)
                            continue;
                        guard.unlock();
                        std::unique_lock context_guard(context.no_race);
                        task->bind_to_worker_id = id;
                        context.tasks.push_back(std::move(task));
                        context.new_task_notifier.notify_one();
                        return;
                    }
                }
                throw std::runtime_error("No binded workers available");
            }
        }
        transfer_task(task);
    }

    void taskNotifyIfEmpty(std::unique_lock<std::recursive_mutex>& re_lock) {
        if (!loc.in_exec_decreased)
            --glob.in_exec;
        loc.in_exec_decreased = false;
        if (!glob.in_exec && glob.tasks.empty() && glob.timed_tasks.empty())
            glob.no_tasks_execute_notifier.notify_all();
    }

    bool loadTask() {
        ++glob.in_exec;
        size_t len = glob.tasks.size();
        if (!len)
            return true;
        auto tmp = std::move(glob.tasks.front());
        glob.tasks.pop();
        if (len == 1)
            glob.no_tasks_notifier.notify_all();
        loc.curr_task = std::move(tmp);

        if (task::max_running_tasks) {
            if (can_be_scheduled_task_to_hot()) {
                if (!glob.cold_tasks.empty()) {
                    glob.tasks.push(std::move(glob.cold_tasks.front()));
                    glob.cold_tasks.pop();
                }
            }
        } else {
            while (!glob.cold_tasks.empty()) {
                glob.tasks.push(std::move(glob.cold_tasks.front()));
                glob.cold_tasks.pop();
            }
        }
        loc.current_context = loc.curr_task->fres.context;
        loc.stack_current_context = &reinterpret_cast<boost::context::continuation&>(loc.current_context);
        return false;
    }

#define worker_mode_desk(old_name, mode) \
    if (task::enable_task_naming)        \
        worker_mode_desk_(old_name, mode);

    void worker_mode_desk_(const std::string& old_name, const std::string& mode) {
        if (old_name.empty())
            _set_name_thread_dbg("Worker " + std::to_string(_thread_id()) + ": " + mode);
        else
            _set_name_thread_dbg(old_name + " | (Temporal worker) " + std::to_string(_thread_id()) + ": " + mode);
    }

    bool execute_task(const std::string& old_name) {
        bool pseudo_handle_caught_ex = false;
        if (!loc.curr_task)
            return false;
        if (!loc.curr_task->func)
            return true;
        if (loc.curr_task->end_of_life)
            goto end_task;

        worker_mode_desk(old_name, "process task - " + std::to_string(loc.curr_task->task_id()));
        if (*loc.stack_current_context) {
            *loc.stack_current_context = std::move(*loc.stack_current_context).resume();
            loc.curr_task->relock_0.relock_start();
            loc.curr_task->relock_1.relock_start();
            loc.curr_task->relock_2.relock_start();
        } else {
            ++glob.in_run_tasks;
            --glob.planned_tasks;
            if (task::max_planned_tasks)
                glob.can_planned_new_notifier.notify_one();
            *loc.stack_current_context = boost::context::callcc(std::allocator_arg, light_stack(1048576 /*1 mb*/), context_exec);
            loc.curr_task->relock_0.relock_start();
            loc.curr_task->relock_1.relock_start();
            loc.curr_task->relock_2.relock_start();
        }
    caught_ex:
        if (loc.ex_ptr) {
            *loc.stack_current_context = boost::context::callcc(std::allocator_arg, light_stack(1048576 /*1 mb*/), context_exec);
            loc.curr_task->relock_0.relock_start();
            loc.curr_task->relock_1.relock_start();
            loc.curr_task->relock_2.relock_start();
            loc.ex_ptr = nullptr;
        }
    end_task:
        loc.curr_task->fres.context = loc.current_context;
        loc.current_context = nullptr;
        loc.is_task_thread = false;
        if (!loc.curr_task->fres.end_of_life && loc.curr_task.use_count() == 1) {
            loc.curr_task->invalid_switch_caught = true;
            glob.tasks.push(loc.curr_task);
        }
        loc.curr_task = nullptr;
        worker_mode_desk(old_name, "idle");
        return false;
    }

    bool taskExecutor_check_next(std::unique_lock<std::recursive_mutex>& guard, bool end_in_task_out) {
        loc.context_in_swap = false;
        loc.current_context = nullptr;
        loc.stack_current_context = nullptr;
        taskNotifyIfEmpty(guard);
        loc.is_task_thread = false;
        while (glob.tasks.empty()) {
            if (!glob.cold_tasks.empty()) {
                if (can_be_scheduled_task_to_hot()) {
                    warmUpTheTasks();
                    break;
                }
            }

            if (end_in_task_out)
                return true;
            glob.tasks_notifier.wait(guard);
        }
        loc.is_task_thread = true;
        return false;
    }

    void taskExecutor(bool end_in_task_out) {
        std::string old_name = end_in_task_out ? _get_name_thread_dbg(_thread_id()) : "";

        if (old_name.empty())
            _set_name_thread_dbg("Worker " + std::to_string(_thread_id()));
        else
            _set_name_thread_dbg(old_name + " | (Temporal worker) " + std::to_string(_thread_id()));

        std::unique_lock<std::recursive_mutex> guard(glob.task_thread_safety);
        ++glob.in_exec;
        ++glob.executors;

        while (true) {
            if (taskExecutor_check_next(guard, end_in_task_out)) {
                break;
            } else {
                if (loadTask())
                    continue;
                guard.unlock();
                if (loc.curr_task->bind_to_worker_id != (uint16_t)-1) {
                    transfer_task(loc.curr_task);
                    guard.lock();
                    continue;
                }
            }
            if (execute_task(old_name)) {
                guard.lock();
                break;
            }
            guard.lock();
        }
        --glob.executors;
        taskNotifyIfEmpty(guard);
        glob.executor_shutdown_notifier.notify_all();
    }

    void bindedTaskExecutor(uint16_t id) {
        std::string old_name = "Binded";
        std::unique_lock initializer_guard(glob.binded_workers_safety);
        if (!glob.binded_workers.contains(id)) {
            assert("Binded worker context not found");
            std::abort();
        }
        binded_context& context = glob.binded_workers[id];
        context.completions.push_front(0);
        auto to_remove_after_death = context.completions.begin();
        uint32_t& completions = context.completions.front();
        initializer_guard.unlock();

        std::list<std::shared_ptr<task>>& queue = context.tasks;
        std::recursive_mutex& safety = context.no_race;
        std::condition_variable_any& notifier = context.new_task_notifier;
        bool pseudo_handle_caught_ex = false;
        _set_name_thread_dbg("Binded worker " + std::to_string(_thread_id()) + ": " + std::to_string(id));

        std::unique_lock guard(safety);
        context.executors++;
        while (true) {
            while (queue.empty())
                notifier.wait(guard);
            loc.curr_task = std::move(queue.front());
            queue.pop_front();
            guard.unlock();

            if (loc.curr_task->bind_to_worker_id != (uint16_t)id) {
                transfer_task(loc.curr_task);
                guard.lock();
                continue;
            }
            loc.is_task_thread = true;
            loc.current_context = loc.curr_task->fres.context;
            loc.stack_current_context = &reinterpret_cast<boost::context::continuation&>(loc.current_context);
            if (execute_task(old_name))
                break;
            completions += 1;
            guard.lock();
        }
        guard.lock();
        --context.executors;
        if (context.executors == 0) {
            if (context.in_close) {
                context.on_closed_notifier.notify_all();
                guard.unlock();
            } else {
                assert(0 && "Caught executor/s death when context is not closed");
                std::abort();
            }
        }

        initializer_guard.lock();
        context.completions.erase(to_remove_after_death);
    }

#pragma endregion

    void taskTimer() {
        glob.time_control_enabled = true;
        _set_name_thread_dbg("task time controller");

        std::unique_lock guard(glob.task_timer_safety);
        std::list<std::shared_ptr<task>> cached_wake_ups;
        std::list<std::shared_ptr<task>> cached_cold;
        while (glob.time_control_enabled) {
            if (glob.timed_tasks.size()) {
                while (glob.timed_tasks.front().wait_timepoint <= std::chrono::high_resolution_clock::now()) {
                    timing& tmng = glob.timed_tasks.front();
                    if (tmng.check_id != tmng.awake_task->awake_check) {
                        glob.timed_tasks.pop_front();
                        if (glob.timed_tasks.empty())
                            break;
                        else
                            continue;
                    }
                    std::lock_guard task_guard(tmng.awake_task->no_race);
                    if (tmng.awake_task->awaked) {
                        glob.timed_tasks.pop_front();
                    } else {
                        tmng.awake_task->time_end_flag = true;
                        cached_wake_ups.push_back(std::move(tmng.awake_task));
                        glob.timed_tasks.pop_front();
                    }
                    if (glob.timed_tasks.empty())
                        break;
                }
            }
            if (glob.cold_timed_tasks.size()) {
                while (glob.cold_timed_tasks.front().wait_timepoint <= std::chrono::high_resolution_clock::now()) {
                    timing& tmng = glob.cold_timed_tasks.front();
                    if (tmng.check_id != tmng.awake_task->awake_check) {
                        glob.cold_timed_tasks.pop_front();
                        if (glob.cold_timed_tasks.empty())
                            break;
                        else
                            continue;
                    }
                    cached_cold.push_back(std::move(tmng.awake_task));
                    glob.cold_timed_tasks.pop_front();
                    if (glob.cold_timed_tasks.empty())
                        break;
                }
            }
            guard.unlock();
            if (!cached_wake_ups.empty() || !cached_cold.empty()) {
                std::lock_guard guard(glob.task_thread_safety);
                if (!cached_wake_ups.empty())
                    while (!cached_wake_ups.empty()) {
                        glob.tasks.push(std::move(cached_wake_ups.back()));
                        cached_wake_ups.pop_back();
                    }
                if (!cached_cold.empty())
                    while (!cached_cold.empty()) {
                        glob.cold_tasks.push(std::move(cached_cold.back()));
                        cached_cold.pop_back();
                    }
                glob.tasks_notifier.notify_all();
            }
            guard.lock();
            if (glob.timed_tasks.empty() && glob.cold_timed_tasks.empty())
                glob.time_notifier.wait(guard);
            else if (glob.timed_tasks.size() && glob.cold_timed_tasks.size()) {
                if (glob.timed_tasks.front().wait_timepoint < glob.cold_timed_tasks.front().wait_timepoint)
                    glob.time_notifier.wait_until(guard, glob.timed_tasks.front().wait_timepoint);
                else
                    glob.time_notifier.wait_until(guard, glob.cold_timed_tasks.front().wait_timepoint);
            } else if (glob.timed_tasks.size())
                glob.time_notifier.wait_until(guard, glob.timed_tasks.front().wait_timepoint);
            else
                glob.time_notifier.wait_until(guard, glob.cold_timed_tasks.front().wait_timepoint);
        }
    }

#if defined(__GNUC__) && !defined(__clang__)
    #pragma GCC pop_options
#endif
#pragma optimize("", on)

    void startTimeController() {
        std::lock_guard guard(glob.task_timer_safety);
        if (glob.time_control_enabled)
            return;
        std::thread(taskTimer).detach();
        glob.time_control_enabled = true;
    }

    void unsafe_put_task_to_timed_queue(std::deque<timing>& queue, std::chrono::high_resolution_clock::time_point t, std::shared_ptr<task>& task) {
        size_t i = 0;
        auto it = queue.begin();
        auto end = queue.end();
        while (it != end) {
            if (it->wait_timepoint >= t) {
                queue.emplace(it, timing(t, task, task->awake_check));
                i = -1;
                break;
            }
            ++it;
        }
        if (i != -1)
            queue.emplace_back(timing(t, task, task->awake_check));
    }

    void makeTimeWait(std::chrono::high_resolution_clock::time_point t) {
        if (!glob.time_control_enabled)
            startTimeController();
        loc.curr_task->awaked = false;
        loc.curr_task->time_end_flag = false;

        std::lock_guard guard(glob.task_timer_safety);
        unsafe_put_task_to_timed_queue(glob.timed_tasks, t, loc.curr_task);
        glob.time_notifier.notify_one();
    }
}
