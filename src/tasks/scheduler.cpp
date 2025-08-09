// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <tasks.hpp>
#include <tasks/_internal.hpp>
#include <tasks/util/interrupt.hpp>
#include <tasks/util/light_stack.hpp>
#include <threading.hpp>

namespace fast_task {

    size_t task::max_running_tasks = 0;
    //In debug builds there locks in std library, so it could deadlock
    //  you could remove the '!_DEBUG ' check and add hooks to winapi like EnterCriticalSection or WaitForSingleObject and use interrupt::interrupt_unsafe_region::lock() or ::unlock() to support this scheduler
#if tasks_enable_preemptive_scheduler_preview && PLATFORM_WINDOWS && !_DEBUG
    void timer_reinit() {
        std::chrono::nanoseconds interval = next_quantum(get_data(loc.curr_task).priority, get_data(loc.curr_task).current_available_quantum);
        interrupt::itimerval timer;
        timer.it_interval.tv_sec = 0;
        timer.it_interval.tv_usec = 0;
        timer.it_value.tv_sec = interval.count() / 1000000000;
        timer.it_value.tv_usec = (interval.count() % 1000000000) / 1000;
        interrupt::setitimer(&timer, nullptr);
    }

    void swapCtx();

    void interruptTask() {
        if (get_data(loc.curr_task).bind_to_worker_id != (uint16_t)-1) {
            fast_task::unique_lock guard(glob.binded_workers_safety);
            auto& bind_context = glob.binded_workers[get_data(loc.curr_task).bind_to_worker_id];
            guard.unlock();
            if (bind_context.tasks.empty()) {
                if (glob.cold_tasks.empty()) {
                    timer_reinit();
                    return;
                } else {
                    if (task::max_running_tasks && !can_be_scheduled_task_to_hot()) {
                        timer_reinit();
                        return;
                    }
                }
            }
        } else {
            if (glob.tasks.empty()) {
                if (glob.cold_tasks.empty()) {
                    timer_reinit();
                    return;
                } else {
                    if (task::max_running_tasks && !can_be_scheduled_task_to_hot()) {
                        timer_reinit();
                        return;
                    }
                }
            }
        }

        ++glob.interrupts;
        ++get_data(loc.curr_task).interrupt_count;
        auto old_relock_0 = get_data(loc.curr_task).relock_0;
        auto old_relock_1 = get_data(loc.curr_task).relock_1;
        auto old_relock_2 = get_data(loc.curr_task).relock_2;
        get_data(loc.curr_task).relock_0 = nullptr;
        get_data(loc.curr_task).relock_1 = nullptr;
        get_data(loc.curr_task).relock_2 = nullptr;
        auto tmp_tsk = loc.curr_task;
        transfer_task(tmp_tsk);
        swapCtx();
        get_data(loc.curr_task).relock_0 = old_relock_0;
        get_data(loc.curr_task).relock_1 = old_relock_1;
        get_data(loc.curr_task).relock_2 = old_relock_2;
    }

    #define set_interruptTask() interrupt::timer_callback(interruptTask);

    #define stop_timer() interrupt::stop_timer()
    #define preserve_interput_data get_data(loc.curr_task).interrupt_data = interrupt::interrupt_unsafe_region::lock_swap(0);
    #define restore_interput_data interrupt::interrupt_unsafe_region::lock_swap(get_data(loc.curr_task).interrupt_data);
    #define flush_interput_data interrupt::interrupt_unsafe_region::lock_swap(0);
#else
    #define timer_reinit()
    #define set_interruptTask()
    #define stop_timer()
    #define preserve_interput_data
    #define restore_interput_data
    #define flush_interput_data
#endif

#pragma optimize("", off)
#if defined(__GNUC__) && !defined(__clang__)
    #pragma GCC push_options
    #pragma GCC optimize("O0")
#endif
#pragma region TaskExecutor

    void swapCtx() {
        stop_timer();
        if (loc.is_task_thread) {
            loc.context_in_swap = true;
            ++glob.tasks_in_swap;
            ++get_data(loc.curr_task).context_switch_count;
            preserve_interput_data;
            //TODO add exception preservation
            try {
                *loc.stack_current_context = std::move(*loc.stack_current_context).resume();
            } catch (const boost::context::detail::forced_unwind&) {
                --glob.tasks_in_swap;
                throw;
            }
            preserve_interput_data;
            --glob.tasks_in_swap;
            loc.context_in_swap = true;
            auto relock_state_0 = get_data(loc.curr_task).relock_0;
            auto relock_state_1 = get_data(loc.curr_task).relock_1;
            auto relock_state_2 = get_data(loc.curr_task).relock_2;
            get_data(loc.curr_task).relock_0 = nullptr;
            get_data(loc.curr_task).relock_1 = nullptr;
            get_data(loc.curr_task).relock_2 = nullptr;
            relock_state_0.relock_end();
            relock_state_1.relock_end();
            relock_state_2.relock_end();
            get_data(loc.curr_task).awake_check++;
            loc.context_in_swap = false;
            if (get_data(loc.curr_task).invalid_switch_caught) {
                get_data(loc.curr_task).invalid_switch_caught = false;
                throw std::runtime_error("Caught task that switched context but not scheduled or finalized self");
            }
        } else
            throw std::runtime_error("swapCtx() not allowed to call in non-task thread or in dispatcher");
        timer_reinit();
    }

    void swapCtxRelock(const mutex_unify& mut0) {
        get_data(loc.curr_task).relock_0 = mut0;
        swapCtx();
    }

    void swapCtxRelock(const mutex_unify& mut0, const mutex_unify& mut1, const mutex_unify& mut2) {
        get_data(loc.curr_task).relock_0 = mut0;
        get_data(loc.curr_task).relock_1 = mut1;
        get_data(loc.curr_task).relock_2 = mut2;
        swapCtx();
    }

    void swapCtxRelock(const mutex_unify& mut0, const mutex_unify& mut1) {
        get_data(loc.curr_task).relock_0 = mut0;
        get_data(loc.curr_task).relock_1 = mut1;
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
            flush_interput_data;
            timer_reinit();
            if (get_data(loc.curr_task).callbacks.is_extended_mode) {
                if (get_data(loc.curr_task).callbacks.extended_mode.on_start)
                    get_data(loc.curr_task).callbacks.extended_mode.on_start(get_data(loc.curr_task).callbacks.extended_mode.data);
            } else
                get_data(loc.curr_task).callbacks.normal_mode.func();
        } catch (const task_cancellation& cancel) {
            forceCancelCancellation(cancel);
        } catch (const boost::context::detail::forced_unwind&) {
            --glob.in_run_tasks;
            throw;
        } catch (...) {
            loc.ex_ptr = std::current_exception();
        }
        stop_timer();
        flush_interput_data;
        fast_task::lock_guard l(get_data(loc.curr_task).no_race);
        --glob.in_run_tasks;
        if (get_data(loc.curr_task).callbacks.is_extended_mode) {
            if (get_data(loc.curr_task).callbacks.extended_mode.is_coroutine) {
                get_data(loc.curr_task).started = false;
                get_data(loc.curr_task).result_notify.notify_all();
                if (task::max_running_tasks)
                    glob.can_started_new_notifier.notify_one();
                return std::move(*loc.stack_current_context);
            }
        }
        get_data(loc.curr_task).end_of_life = true;
        get_data(loc.curr_task).result_notify.notify_all();
        if (task::max_running_tasks)
            glob.can_started_new_notifier.notify_one();
        return std::move(*loc.stack_current_context);
    }

    boost::context::continuation context_ex_handle(boost::context::continuation&& sink) {
        *loc.stack_current_context = std::move(sink);
        try {
            checkCancellation();
            flush_interput_data;
            timer_reinit();
            if (!get_data(loc.curr_task).callbacks.is_extended_mode)
                get_data(loc.curr_task).callbacks.normal_mode.ex_handle(loc.ex_ptr);
        } catch (task_cancellation& cancel) {
            forceCancelCancellation(cancel);
        } catch (const boost::context::detail::forced_unwind&) {
            --glob.in_run_tasks;
            throw;
        } catch (...) {
            loc.ex_ptr = std::current_exception();
        }
        stop_timer();
        flush_interput_data;
        mutex_unify uni(get_data(loc.curr_task).no_race);
        fast_task::unique_lock l(uni);
        get_data(loc.curr_task).end_of_life = true;
        get_data(loc.curr_task).result_notify.notify_all();
        --glob.in_run_tasks;
        if (task::max_running_tasks)
            glob.can_started_new_notifier.notify_one();
        return std::move(*loc.stack_current_context);
    }

    void transfer_task(std::shared_ptr<task>& task) {
        if (get_data(task).bind_to_worker_id == (uint16_t)-1) {
            fast_task::lock_guard guard(glob.task_thread_safety);
            glob.tasks.push(std::move(task));
            glob.tasks_notifier.notify_one();
        } else {
            fast_task::unique_lock initializer_guard(glob.binded_workers_safety);
            if (!glob.binded_workers.contains(get_data(task).bind_to_worker_id)) {
                initializer_guard.unlock();
                assert("Binded worker context not found");
                std::abort();
            }
            binded_context& extern_context = glob.binded_workers[get_data(task).bind_to_worker_id];
            initializer_guard.unlock();
            if (extern_context.in_close) {
                assert("Binded worker context is closed");
                std::abort();
            }
            fast_task::lock_guard guard(extern_context.no_race);
            extern_context.tasks.emplace_back(std::move(task));
            extern_context.new_task_notifier.notify_one();
        }
    }

    void awake_task(std::shared_ptr<task>& task) {
        if (get_data(task).bind_to_worker_id == (uint16_t)-1) {
            if (get_data(task).auto_bind_worker) {
                fast_task::unique_lock guard(glob.binded_workers_safety);
                for (auto& [id, context] : glob.binded_workers) {
                    if (context.allow_implicit_start) {
                        if (context.in_close)
                            continue;
                        guard.unlock();
                        fast_task::unique_lock context_guard(context.no_race);
                        get_data(task).bind_to_worker_id = id;
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

    bool loadTask() {
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
        loc.current_context = get_data(loc.curr_task).context;
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
        if (!loc.curr_task)
            return false;
        if (!get_data(loc.curr_task).callbacks.is_extended_mode) {
            if (!get_data(loc.curr_task).callbacks.normal_mode.func)
                return true;
        } else if (!get_data(loc.curr_task).callbacks.extended_mode.on_start) {
            get_data(loc.curr_task).end_of_life = true;
            get_data(loc.curr_task).result_notify.notify_all();
            goto end_task;
        }

        if (get_data(loc.curr_task).end_of_life)
            goto end_task;


        worker_mode_desk(old_name, "process task - " + std::to_string(this_task::get_id()));
        if (*loc.stack_current_context) {
            *loc.stack_current_context = std::move(*loc.stack_current_context).resume();
            get_data(loc.curr_task).relock_0.relock_start();
            get_data(loc.curr_task).relock_1.relock_start();
            get_data(loc.curr_task).relock_2.relock_start();
        } else {
            ++glob.in_run_tasks;
            *loc.stack_current_context = boost::context::callcc(std::allocator_arg, light_stack(1048576 /*1 mb*/), context_exec);
            get_data(loc.curr_task).relock_0.relock_start();
            get_data(loc.curr_task).relock_1.relock_start();
            get_data(loc.curr_task).relock_2.relock_start();
        }
        if (loc.ex_ptr) {
            ++glob.in_run_tasks;
            *loc.stack_current_context = boost::context::callcc(std::allocator_arg, light_stack(1048576 /*1 mb*/), context_exec);
            get_data(loc.curr_task).relock_0.relock_start();
            get_data(loc.curr_task).relock_1.relock_start();
            get_data(loc.curr_task).relock_2.relock_start();
            loc.ex_ptr = nullptr;
        }
    end_task:
        get_data(loc.curr_task).context = loc.current_context;
        loc.current_context = nullptr;
        loc.is_task_thread = false;
        if (!get_data(loc.curr_task).end_of_life && loc.curr_task.use_count() == 1) {
            get_data(loc.curr_task).invalid_switch_caught = true;
            glob.tasks.push(loc.curr_task);
        }

        loc.curr_task = nullptr;
        worker_mode_desk(old_name, "idle");
        return false;
    }

    bool taskExecutor_check_next(fast_task::unique_lock<fast_task::recursive_mutex>& guard, bool end_in_task_out) {
        loc.context_in_swap = false;
        loc.current_context = nullptr;
        loc.stack_current_context = nullptr;
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
            else
                glob.tasks_notifier.wait(guard);
        }
        loc.is_task_thread = true;
        return false;
    }

    void taskExecutor(bool end_in_task_out, bool prevent_naming) {
        set_interruptTask();
        std::string old_name = end_in_task_out && !prevent_naming ? _get_name_thread_dbg(_thread_id()) : "";
        if (!prevent_naming) {
            if (old_name.empty())
                _set_name_thread_dbg("Worker " + std::to_string(_thread_id()));
            else
                _set_name_thread_dbg(old_name + " | (Temporal worker) " + std::to_string(_thread_id()));
        }

        fast_task::unique_lock guard(glob.task_thread_safety);
        ++glob.executors;
        while (true) {
            if (taskExecutor_check_next(guard, end_in_task_out))
                break;
            if (loadTask())
                continue;

            guard.unlock();
            if (get_data(loc.curr_task).bind_to_worker_id != (uint16_t)-1) {
                transfer_task(loc.curr_task);
                guard.lock();
                continue;
            }
            if (execute_task(old_name))
                break;
            guard.lock();
        }
        --glob.executors;
        if (!glob.in_run_tasks && glob.tasks.empty() && glob.timed_tasks.empty())
            glob.no_tasks_execute_notifier.notify_all();
        glob.executor_shutdown_notifier.notify_all();
        if (!prevent_naming)
            _set_name_thread_dbg(old_name);
    }

    void bindedTaskExecutor(uint16_t id) {
        set_interruptTask();
        std::string old_name = "Binded";
        fast_task::unique_lock initializer_guard(glob.binded_workers_safety);
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
        auto& safety = context.no_race;
        auto& notifier = context.new_task_notifier;
        _set_name_thread_dbg("Binded worker " + std::to_string(_thread_id()) + ": " + std::to_string(id));

        fast_task::unique_lock guard(safety);
        context.executors++;
        while (true) {
            while (queue.empty()) {
                if (context.in_close) {
                    guard.unlock();
                    break;
                }
                notifier.wait(guard);
            }
            loc.curr_task = queue.back();
            queue.pop_back();
            guard.unlock();

            if (get_data(loc.curr_task).bind_to_worker_id != (uint16_t)id) {
                transfer_task(loc.curr_task);
                guard.lock();
                continue;
            }
            loc.is_task_thread = true;
            loc.current_context = get_data(loc.curr_task).context;
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

        fast_task::unique_lock guard(glob.task_timer_safety);
        std::list<std::shared_ptr<task>> cached_wake_ups;
        std::list<std::shared_ptr<task>> cached_cold;
        while (glob.time_control_enabled) {
            if (glob.timed_tasks.size()) {
                auto current_now = std::chrono::high_resolution_clock::now();
                while (glob.timed_tasks.front().wait_timepoint <= current_now) {
                    timing& tmng = glob.timed_tasks.front();
                    if (tmng.check_id != get_data(tmng.awake_task).awake_check) {
                        glob.timed_tasks.pop_front();
                        if (glob.timed_tasks.empty())
                            break;
                        else
                            continue;
                    }
                    fast_task::lock_guard task_guard(get_data(tmng.awake_task).no_race);
                    if (get_data(tmng.awake_task).awaked) {
                        glob.timed_tasks.pop_front();
                    } else {
                        get_data(tmng.awake_task).time_end_flag = true;
                        cached_wake_ups.push_back(std::move(tmng.awake_task));
                        glob.timed_tasks.pop_front();
                    }
                    if (glob.timed_tasks.empty())
                        break;
                }
            }
            if (glob.cold_timed_tasks.size()) {
                auto current_now = std::chrono::high_resolution_clock::now();
                while (glob.cold_timed_tasks.front().wait_timepoint <= current_now) {
                    timing& tmng = glob.cold_timed_tasks.front();
                    if (tmng.check_id != get_data(tmng.awake_task).awake_check) {
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
                fast_task::lock_guard guard(glob.task_thread_safety);
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
        fast_task::lock_guard guard(glob.task_timer_safety);
        if (glob.time_control_enabled)
            return;
        fast_task::thread(taskTimer).detach();
        glob.time_control_enabled = true;
    }

    void unsafe_put_task_to_timed_queue(std::deque<timing>& queue, std::chrono::high_resolution_clock::time_point t, std::shared_ptr<task>& task) {
        size_t i = 0;
        auto it = queue.begin();
        auto end = queue.end();
        while (it != end) {
            if (it->wait_timepoint >= t) {
                queue.emplace(it, timing(t, task, get_data(task).awake_check));
                i = -1;
                break;
            }
            ++it;
        }
        if (i != -1)
            queue.emplace_back(timing(t, task, get_data(task).awake_check));
    }

    void makeTimeWait(std::chrono::high_resolution_clock::time_point t) {
        if (!glob.time_control_enabled)
            startTimeController();
        get_data(loc.curr_task).awaked = false;
        get_data(loc.curr_task).time_end_flag = false;

        fast_task::lock_guard guard(glob.task_timer_safety);
        unsafe_put_task_to_timed_queue(glob.timed_tasks, t, loc.curr_task);
        glob.time_notifier.notify_one();
    }
}
