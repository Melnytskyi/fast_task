// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <task.hpp>
#include <tasks/_internal.hpp>
#include <tasks/util/interrupt.hpp>
#include <tasks/util/light_stack.hpp>
#include <threading.hpp>

namespace fast_task {

    size_t task::max_running_tasks = 0;
#ifdef FT_ENABLE_PREEMPTIVE_SCHEDULER
    void timer_reinit() {
        if (get_loc().policy == scheduler::executor_policy::cooperative_only)
            return;
        std::chrono::nanoseconds interval = next_quantum(get_execution_data(get_loc().curr_task).priority, get_execution_data(get_loc().curr_task).current_available_quantum);
        interrupt::itimerval timer;
        timer.it_interval.tv_sec = 0;
        timer.it_interval.tv_usec = 0;
        timer.it_value.tv_sec = interval.count() / 1000000000;
        timer.it_value.tv_usec = (interval.count() % 1000000000) / 1000;
        interrupt::setitimer(&timer, nullptr);
    }

    void swapCtx();

    void interruptTask() {
        if (get_loc().policy == scheduler::executor_policy::cooperative_only)
            return;
    #ifdef FT_EXCEPTION_POLICY_CHECK
        if (std::uncaught_exceptions())
            return;
    #endif
        if (get_data(get_loc().curr_task).bind_to_worker_id != (uint16_t)-1) {
            fast_task::unique_lock guard(glob.binded_workers_safety);
            auto& bind_context = glob.binded_workers[get_data(get_loc().curr_task).bind_to_worker_id];
            guard.unlock();
            if (bind_context.tasks.size_approx() == 0) {
                if (glob.cold_tasks.size_approx() == 0) {
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
            if (glob.tasks.size_approx() == 0) {
                if (glob.cold_tasks.size_approx() == 0) {
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
        auto curr_task = get_loc().curr_task;
        ++get_execution_data(curr_task).interrupt_count;
        auto old_relock_0 = get_data(curr_task).get_relock_0();
        auto old_relock_1 = get_data(curr_task).get_relock_1();
        get_data(curr_task).set_relock_0(nullptr);
        get_data(curr_task).set_relock_1(nullptr);
        get_loc().yield_request = true;
        swapCtx();
        get_data(curr_task).set_relock_0(old_relock_0);
        get_data(curr_task).set_relock_1(old_relock_1);
    }

    void set_interruptTask() {
        interrupt::timer_callback(interruptTask);
    }

    void stop_timer() {
        interrupt::stop_timer();
    }

    void preserve_interrupt_data() {
        get_execution_data(get_loc()).interrupt_data = interrupt_unsafe_region::lock_swap(0);
    }

    void restore_interrupt_data() {
        interrupt_unsafe_region::lock_swap(get_execution_data(get_loc()).interrupt_data);
    }

    void flush_interrupt_data() {
        interrupt_unsafe_region::lock_swap(0);
    }
#else
    #define timer_reinit()
    #define set_interruptTask()
    #define stop_timer()
    #define preserve_interrupt_data
    #define restore_interrupt_data
    #define flush_interrupt_data
#endif

#pragma region TaskExecutor

    void swapCtx() {
        auto& pre_switch_loc = get_loc();
        if (pre_switch_loc.is_task_thread) {
            stop_timer();
            if (get_data(pre_switch_loc.curr_task).get_is_on_scheduler())
                throw invalid_context();
            pre_switch_loc.context_in_swap = true;
            ++glob.tasks_in_swap;
            ++get_execution_data(pre_switch_loc.curr_task).context_switch_count;
            preserve_interrupt_data;

            task my_task = pre_switch_loc.curr_task;
#ifdef FT_EXCEPTION_POLICY_CHECK
            if (std::uncaught_exceptions()) {
                assert(false && "Unexpected exception during context switch");
                std::abort();
            }
#elif defined(FT_EXCEPTION_POLICY_PRESERVE)
            if (std::uncaught_exceptions())
                get_execution_data(my_task).switch_preserve = std::current_exception();
#endif
            try {
                *get_loc().stack_current_context = std::move(*get_loc().stack_current_context).resume();
            } catch (const boost::context::detail::forced_unwind&) {
                flush_interrupt_data;
                auto& post_switch_loc = get_loc();
                --glob.tasks_in_swap;

                auto old_curr_task = post_switch_loc.curr_task;
                bool old_context_in_swap = post_switch_loc.context_in_swap;
                post_switch_loc.curr_task = my_task;
                post_switch_loc.context_in_swap = true;

                auto relock_state_0 = get_data(my_task).get_relock_0();
                auto relock_state_1 = get_data(my_task).get_relock_1();
                get_data(my_task).set_relock_0(nullptr);
                get_data(my_task).set_relock_1(nullptr);
                auto old_time_end_flag = get_data(post_switch_loc.curr_task).get_time_end();
                auto old_awaked = get_data(post_switch_loc.curr_task).get_awaked();

                relock_state_0.relock_end();
                relock_state_1.relock_end();
                auto& post_relock_loc = get_loc();
                get_data(post_relock_loc.curr_task).set_time_end(old_time_end_flag);
                get_data(post_relock_loc.curr_task).set_awaked(old_awaked);

                post_relock_loc.curr_task = old_curr_task;
                post_relock_loc.context_in_swap = old_context_in_swap;
                throw;
            }
            auto& post_switch_loc = get_loc();
#if defined(FT_EXCEPTION_POLICY_PRESERVE)
            if (get_execution_data(post_switch_loc.curr_task).switch_preserve)
                std::rethrow_exception(std::move(get_execution_data(post_switch_loc.curr_task).switch_preserve));
#endif
            preserve_interrupt_data;
            --glob.tasks_in_swap;
            post_switch_loc.context_in_swap = true;
            auto relock_state_0 = get_data(my_task).get_relock_0();
            auto relock_state_1 = get_data(my_task).get_relock_1();
            get_data(my_task).set_relock_0(nullptr);
            get_data(my_task).set_relock_1(nullptr);
            auto old_time_end_flag = get_data(post_switch_loc.curr_task).get_time_end();
            auto old_awaked = get_data(post_switch_loc.curr_task).get_awaked();
            relock_state_0.relock_end();
            relock_state_1.relock_end();

            auto& post_relock_loc = get_loc();
            get_data(post_relock_loc.curr_task).awake_check++;
            get_data(post_relock_loc.curr_task).set_time_end(old_time_end_flag);
            get_data(post_relock_loc.curr_task).set_awaked(old_awaked);
            post_relock_loc.context_in_swap = false;
            if (get_data(post_relock_loc.curr_task).get_invalid_switch_caught()) {
                get_data(post_relock_loc.curr_task).set_invalid_switch_caught(false);
                throw invalid_switch();
            }
            if (get_execution_data(post_relock_loc.curr_task).timeout != std::chrono::high_resolution_clock::time_point::min().time_since_epoch().count())
                if (get_execution_data(post_relock_loc.curr_task).timeout <= std::chrono::high_resolution_clock::now().time_since_epoch().count())
                    throw task_cancellation();
            timer_reinit();
        } else
            throw invalid_context();
    }

    void swapCtxRelock(const mutex_unify& mut0) {
        get_data(get_loc().curr_task).set_relock_0(mut0);
        swapCtx();
    }

    void swapCtxRelock(const mutex_unify& mut0, const mutex_unify& mut1) {
        auto& curr_task = get_loc().curr_task;
        get_data(curr_task).set_relock_0(mut0);
        get_data(curr_task).set_relock_1(mut1);
        swapCtx();
    }

    boost::context::continuation context_exec(boost::context::continuation&& sink) {
        *get_loc().stack_current_context = std::move(sink);
        try {
            if (!checkCancellation()) {
                flush_interrupt_data;
                timer_reinit();
                auto& loc = get_loc();
                auto vtable = get_data(loc.curr_task).vtable;
                if (get_data(get_loc().curr_task).on_start_override)
                    get_data(get_loc().curr_task).on_start_override(&get_data(loc.curr_task));
                else if (vtable && vtable->on_start)
                    vtable->on_start(get_data(get_loc().curr_task).user_data());
            } else
                this_task::the_coroutine_ended(get_loc().curr_task);
        } catch (const task_cancellation& cancel) {
            forceCancelCancellation(cancel);
        } catch (const boost::context::detail::forced_unwind&) {
            --glob.in_run_tasks;
            throw;
        } catch (...) {
            get_loc().ex_ptr = std::current_exception();
        }
        stop_timer();
        flush_interrupt_data;
        auto& loc = get_loc();
        {
            fast_task::lock_guard l(get_data(loc.curr_task));
            --glob.in_run_tasks;
            if (get_data(loc.curr_task).get_is_restartable()) {
                return std::move(*loc.stack_current_context);
            }
        }
        if (!loc.ex_ptr)
            get_data(loc.curr_task).end_of_life_notify();

        return std::move(*loc.stack_current_context);
    }

    boost::context::continuation context_ex_handle(boost::context::continuation&& sink) {
        *get_loc().stack_current_context = std::move(sink);
        try {
            if (!checkCancellation()) {
                flush_interrupt_data;
                timer_reinit();
                auto& loc = get_loc();
                auto vtable = get_data(loc.curr_task).vtable;
                if (vtable && vtable->on_exception)
                    vtable->on_exception(get_data(loc.curr_task).user_data(), loc.ex_ptr);
            } else
                this_task::the_coroutine_ended(get_loc().curr_task);
        } catch (task_cancellation& cancel) {
            forceCancelCancellation(cancel);
        } catch (const boost::context::detail::forced_unwind&) {
            --glob.in_run_tasks;
            throw;
        } catch (...) {
            get_loc().ex_ptr = std::current_exception();
        }
        stop_timer();
        flush_interrupt_data;
        auto& loc = get_loc();
        get_data(loc.curr_task).end_of_life_notify();
        --glob.in_run_tasks;
        return std::move(*loc.stack_current_context);
    }

    void in_place_run() {
        auto& loc = get_loc();
        ++glob.in_run_tasks;
        auto* data = &get_data(loc.curr_task);
        data->awake_check++;
        try {
            if (!checkCancellation()) {
                if constexpr (FT_TASK_TRANSFERS_LIMIT > 0)
                    loc.transfer_state.transfers = 0;
                while (true) {
                    if (data->on_start_override)
                        data->on_start_override(data);
                    else if (data->vtable && data->vtable->on_start)
                        data->vtable->on_start(data->user_data());
                    data->get_relock_0().relock_start();
                    data->get_relock_1().relock_start();
                    if (loc.transfer_state.pending == nullptr)
                        break;
#if FT_TASK_TRANSFERS_LIMIT > 0
                    else if (loc.transfer_state.transfers > FT_TASK_TRANSFERS_LIMIT) {
                        transfer_task(std::move(loc.transfer_state.pending));
                        loc.transfer_state.pending.reset();
                        break;
                    }
#endif
                    else {
                        loc.curr_task = loc.transfer_state.pending;
                        loc.transfer_state.pending.reset();
                        data = &get_data(loc.curr_task);
                    }
                }
                if constexpr (FT_TASK_TRANSFERS_LIMIT > 0)
                    loc.transfer_state.transfers = 0;
            } else
                this_task::the_coroutine_ended(loc.curr_task);

            if (data->get_is_restartable()) {
            } else
                data->end_of_life_notify();
        } catch (const task_cancellation& cancel) {
            forceCancelCancellation(cancel);
            data->end_of_life_notify();
        } catch (...) {
            loc.ex_ptr = std::current_exception();
        }
        if (loc.ex_ptr) {
            if (data->vtable && data->vtable->on_exception) {
                try {
                    data->vtable->on_exception(data->user_data(), loc.ex_ptr);
                    loc.ex_ptr = nullptr;
                } catch (const task_cancellation& cancel) {
                    forceCancelCancellation(cancel);
                    loc.ex_ptr = nullptr;
                } catch (...) {
                    loc.ex_ptr = std::current_exception();
                }
            }
            data->end_of_life_notify();
        }
        --glob.in_run_tasks;
    }

    void transfer_task(task&& task, enter_state* stat) {
        if (!task) {
            glob.tasks.enqueue(std::move(task));
            glob.tasks_notifier.unsafe_notify_one();
            return;
        }

        if (get_data(task).get_is_on_scheduler() && get_data(task).get_relock_0() && stat) {
            auto mut = get_data(task).get_relock_0();

            get_data(task).set_relock_0(nullptr);
            get_data(task).set_relock_1(nullptr);

            if (!mut.enter_wait(task, *stat))
                return;
        }

        if (get_data(task).bind_to_worker_id == (uint16_t)-1) {
            if (get_data(task).get_auto_bind()) {
                fast_task::shared_lock global_guard(glob.binded_workers_safety);
                for (auto& [id, context] : glob.binded_workers) {
                    if (context.allow_implicit_start) {
                        if (context.in_close)
                            continue;
                        global_guard.unlock();
                        get_data(task).bind_to_worker_id = id;
                        fast_task::shared_lock guard(context.no_race);
                        context.tasks.enqueue(std::move(task));
                        context.new_task_notifier.notify_one();
                        return;
                    }
                }
            }
            auto& loc = get_loc();
            if (loc.binded_id == (uint16_t)-1 && loc.is_task_thread) {
                if (loc.local_tasks->emplace(std::move(task))) {
                    if (loc.local_tasks->size() > 1) //if there only one task the notification not passed to avoid redundant concurency
                        glob.tasks_notifier.unsafe_notify_one();
                    return;
                }
            }

            if (can_be_scheduled_task_to_hot())
                glob.tasks.enqueue(std::move(task));
            else
                glob.cold_tasks.enqueue(std::move(task));
            glob.tasks_notifier.unsafe_notify_one();
        } else {
            fast_task::shared_lock initializer_guard(glob.binded_workers_safety);
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
            auto& loc = get_loc();
            if (get_data(task).bind_to_worker_id == loc.binded_id) {
                if (loc.local_tasks->emplace(std::move(task))) {
                    if (loc.local_tasks->size() > 1) //if there only one task the notification not passed to avoid redundant concurency
                        extern_context.new_task_notifier.unsafe_notify_one();
                    return;
                }
            }
            fast_task::shared_lock guard(extern_context.no_race);
            extern_context.tasks.enqueue(std::move(task));
            extern_context.new_task_notifier.notify_one();
        }
    }

    bool loadTask() {
        auto& loc = get_loc();
        if (loc.local_tasks->pop(loc.curr_task)) {
            if (loc.curr_task && !get_data(loc.curr_task).get_is_on_scheduler())
                loc.stack_current_context = &get_execution_data(loc.curr_task).context;
            return false;
        }

        constexpr size_t BATCH_SIZE = 32;
        task temp_tasks[BATCH_SIZE];
        {
            size_t count = glob.tasks.try_dequeue_bulk(temp_tasks, BATCH_SIZE);

            if (count > 0) {
                for (size_t i = 1; i < count; ++i)
                    if (!loc.local_tasks->emplace(std::move(temp_tasks[i])))
                        glob.tasks.enqueue(temp_tasks[i]);
                loc.curr_task = std::move(temp_tasks[0]);
                if (loc.curr_task && !get_data(loc.curr_task).get_is_on_scheduler())
                    loc.stack_current_context = &get_execution_data(loc.curr_task).context;
                return false;
            }
        }

        if (can_be_scheduled_task_to_hot()) {
            size_t count = glob.cold_tasks.try_dequeue_bulk(temp_tasks, BATCH_SIZE);

            if (count > 0) {
                for (size_t i = 1; i < count; ++i)
                    if (!loc.local_tasks->emplace(std::move(temp_tasks[i])))
                        glob.cold_tasks.enqueue(temp_tasks[i]);
                loc.curr_task = std::move(temp_tasks[0]);
                if (loc.curr_task && !get_data(loc.curr_task).get_is_on_scheduler())
                    loc.stack_current_context = &get_execution_data(loc.curr_task).context;
                return false;
            }
        }

        {
            auto queues = glob.executors_queues.load(std::memory_order_relaxed);
            if (queues) {
                if (!queues->empty()) {
                    auto& engine = get_thread_local_random_engine();
                    size_t size = queues->size();
                    std::uniform_int_distribution<size_t> dist(0, size - 1);

                    size_t start_index = dist(engine);
                    for (size_t i = 0; i < size; ++i) {
                        size_t index = (start_index + i) % size;
                        auto& victim_deque = (*queues)[index];

                        if (victim_deque == loc.local_tasks)
                            continue;

                        if (victim_deque->steal(loc.curr_task)) {
                            if (loc.curr_task && !get_data(loc.curr_task).get_is_on_scheduler())
                                loc.stack_current_context = &get_execution_data(loc.curr_task).context;
                            return false;
                        }
                    }
                }
            }
        }

        loc.curr_task = nullptr;
        loc.stack_current_context = nullptr;
        return true;
    }

#define worker_mode_desk(old_name, mode, id) \
    if (task::enable_task_naming)            \
        worker_mode_desk_(old_name, mode, id);

    void worker_mode_desk_(const std::string& old_name, std::string_view mode, size_t id) {
        if (old_name.empty())
            _set_name_thread_dbg("Worker " + std::to_string(_thread_id()) + ": " + std::string(mode) + std::to_string(id));
        else
            _set_name_thread_dbg(old_name + " | (Temporal worker) " + std::to_string(_thread_id()) + ": " + std::string(mode) + std::to_string(id));
    }

    bool execute_task(const std::string& old_name) {
        auto& pre_exec_loc = get_loc();
        if (!pre_exec_loc.curr_task)
            return true;
        auto& vtable = get_data(pre_exec_loc.curr_task).vtable;
        if (vtable && vtable->on_start == nullptr && vtable->on_destruct == nullptr) {
            get_data(pre_exec_loc.curr_task).end_of_life_notify();
            pre_exec_loc.curr_task = nullptr;
            return true;
        } else if (!vtable->on_start) {
            get_data(pre_exec_loc.curr_task).end_of_life_notify();
            goto end_task;
        }
        {
            fast_task::lock_guard guard(get_data(pre_exec_loc.curr_task));
            if (get_data(pre_exec_loc.curr_task).is_ended())
                goto end_task;

            get_data(pre_exec_loc.curr_task).set_status(task_object::status_e::running);
        }

        pre_exec_loc.is_task_thread = true;

        worker_mode_desk(old_name, "process task - ", this_task::get_id());
        if (get_loc().stack_current_context && *get_loc().stack_current_context) {
            *get_loc().stack_current_context = std::move(*get_loc().stack_current_context).resume();
            get_data(get_loc().curr_task).get_relock_0().relock_start();
            get_data(get_loc().curr_task).get_relock_1().relock_start();
        } else if (get_data(get_loc().curr_task).get_is_on_scheduler()) {
            in_place_run();
        } else {
            light_stack stack_alloc(1048576 /*1 mb*/);
            auto ss = stack_alloc.allocate();
#if PLATFORM_LINUX
            get_execution_data(get_loc().curr_task).stack_ptr = ((char*)ss.sp) - ss.size;
            get_execution_data(get_loc().curr_task).stack_size = ss.size;
#endif
            ++glob.in_run_tasks;
            *get_loc().stack_current_context = boost::context::callcc(std::allocator_arg, boost::context::preallocated(ss.sp, ss.size, ss), stack_alloc, context_exec);
            get_data(get_loc().curr_task).get_relock_0().relock_start();
            get_data(get_loc().curr_task).get_relock_1().relock_start();
        }
        if (get_loc().ex_ptr) {
            light_stack stack_alloc(1048576 /*1 mb*/);
            auto ss = stack_alloc.allocate();
#if PLATFORM_LINUX
            get_execution_data(get_loc().curr_task).stack_ptr = ((char*)ss.sp) - ss.size;
            get_execution_data(get_loc().curr_task).stack_size = ss.size;
#endif
            ++glob.in_run_tasks;
            *get_loc().stack_current_context = boost::context::callcc(std::allocator_arg, boost::context::preallocated(ss.sp, ss.size, ss), stack_alloc, context_ex_handle);
            get_data(get_loc().curr_task).get_relock_0().relock_start();
            get_data(get_loc().curr_task).get_relock_1().relock_start();
            get_loc().ex_ptr = nullptr;
        }
    end_task:
        auto& loc = get_loc();
        loc.stack_current_context = nullptr;
        loc.is_task_thread = false;
        loc.context_in_swap = false;
        bool end_of_life = false;
        bool do_yield_transfer = loc.yield_request;
        bool do_invalid_transfer = false;
        {
            fast_task::lock_guard guard(get_data(loc.curr_task));
            end_of_life = get_data(loc.curr_task).is_ended();

            if (!end_of_life) {
                if (!do_yield_transfer && get_data(loc.curr_task).link_counter == 1) {
                    do_invalid_transfer = true;
                    get_data(loc.curr_task).set_invalid_switch_caught(true);
                }

                if (!do_yield_transfer && !do_invalid_transfer)
                    get_data(pre_exec_loc.curr_task).set_status(task_object::status_e::suspended);
                else
                    get_data(pre_exec_loc.curr_task).set_status(task_object::status_e::running);
            }
        }
        if (do_invalid_transfer || do_yield_transfer) {
            transfer_task(std::move(loc.curr_task));
            loc.yield_request = false;
        } else if (end_of_life) {
            bool should_decrement = false;
            {
                fast_task::lock_guard guard(get_data(loc.curr_task));
                if (!get_data(loc.curr_task).get_completed()) {
                    get_data(loc.curr_task).set_completed(true);
                    should_decrement = true;
                }
            }

            if (should_decrement) {
                --glob.executing_tasks;
                fast_task::shared_lock guard(glob.task_thread_safety);
                glob.no_tasks_execute_notifier.notify_all_guarded();
            }
        }


        loc.curr_task = nullptr;
        worker_mode_desk(old_name, "idle ", 0);
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
        auto& loc = get_loc();
        {
            fast_task::unique_lock lock(glob.task_thread_safety);
            auto old_queues_ptr = glob.executors_queues.load();
            auto new_queues = old_queues_ptr ? std::make_shared<std::vector<std::shared_ptr<work_stealing_deque<task>>>>(*old_queues_ptr)
                                             : std::make_shared<std::vector<std::shared_ptr<work_stealing_deque<task>>>>();
            new_queues->push_back(loc.local_tasks);
            glob.executors_queues.store(new_queues);
        }
        constexpr size_t max_retrys = 13;
        size_t retrys = 0;
        ++glob.executors;
        while (true) {
            check_stw();
            if (loadTask()) {
                if (end_in_task_out)
                    goto exit_path;
                else if (retrys < max_retrys) {
                    ++retrys;
                } else if (!loc.local_tasks->empty())
                    retrys = 0;
                else {
                    fast_task::unique_lock guard(glob.task_thread_safety);
                    if (glob.tasks.size_approx() == 0 && glob.cold_tasks.size_approx() == 0) {
                        if (glob.executor_shutting_down.load(std::memory_order_acquire))
                            goto exit_path;
                        glob.tasks_notifier.wait(guard);
                        if (glob.executor_shutting_down.load(std::memory_order_acquire))
                            goto exit_path;
                    }
                }
                continue;
            }
            retrys = 0;
            if (loc.curr_task && get_data(loc.curr_task).bind_to_worker_id != (uint16_t)-1) {
                transfer_task(std::move(loc.curr_task));
                continue;
            }
            if (execute_task(old_name))
                break;
        }
    exit_path:
        if (!prevent_naming)
            _set_name_thread_dbg(old_name);


        fast_task::unique_lock lock(glob.task_thread_safety);

        auto old_queues_ptr = glob.executors_queues.load();
        auto new_queues = std::make_shared<std::vector<std::shared_ptr<work_stealing_deque<task>>>>();
        new_queues->reserve(old_queues_ptr->size());

        for (const auto& q_ptr : *old_queues_ptr) {
            if (q_ptr.get() != loc.local_tasks.get())
                new_queues->push_back(q_ptr);
        }

        glob.executors_queues.store(new_queues);
        lock.unlock();
        while (!loc.local_tasks->empty())
            while (loc.local_tasks->pop(loc.curr_task))
                glob.tasks.enqueue(std::move(loc.curr_task));

        lock.lock();
        --glob.executors;
        loc.reset();
        --glob.thread_count;
        glob.tasks_notifier.unsafe_notify_all();
        glob.executor_shutdown_notifier.notify_all();
    }

    bool loadTaskBinded(binded_context& context) {
        auto& loc = get_loc();
        while (true) {
            check_stw();
            if (loc.local_tasks->pop(loc.curr_task)) {
                if (loc.curr_task && !get_data(loc.curr_task).get_is_on_scheduler())
                    loc.stack_current_context = &get_execution_data(loc.curr_task).context;
                return true;
            }

            constexpr size_t BATCH_SIZE = 8;
            task temp_tasks[BATCH_SIZE];
            size_t count = context.tasks.try_dequeue_bulk(temp_tasks, BATCH_SIZE);

            if (count > 0) {
                for (size_t i = 1; i < count; ++i)
                    if (!loc.local_tasks->emplace(std::move(temp_tasks[i])))
                        glob.tasks.enqueue(temp_tasks[i]);
                loc.curr_task = std::move(temp_tasks[0]);
                if (loc.curr_task && !get_data(loc.curr_task).get_is_on_scheduler())
                    loc.stack_current_context = &get_execution_data(loc.curr_task).context;
                return true;
            }

            {
                auto queue = context.executors_queues.load();
                if (queue) {
                    if (!queue->empty()) {
                        auto& engine = get_thread_local_random_engine();
                        std::uniform_int_distribution<size_t> dist(0, queue->size() - 1);

                        size_t start_index = dist(engine);
                        for (size_t i = 0; i < queue->size(); ++i) {
                            size_t index = (start_index + i) % queue->size();
                            auto& victim_deque = (*queue)[index];

                            if (victim_deque == loc.local_tasks)
                                continue;

                            if (victim_deque->pop(loc.curr_task)) {
                                if (loc.curr_task && !get_data(loc.curr_task).get_is_on_scheduler())
                                    loc.stack_current_context = &get_execution_data(loc.curr_task).context;
                                return true;
                            }
                        }
                    }
                }
            }


            if (!context.tasks.try_dequeue(loc.curr_task)) {
                {
                    fast_task::unique_lock guard(glob.task_thread_safety);
                    glob.no_tasks_execute_notifier.notify_all_guarded();
                }
                fast_task::unique_lock guard(context.no_race);
                if (context.in_close)
                    break;
                if (!context.tasks.try_dequeue(loc.curr_task)) {
                    context.new_task_notifier.wait(guard);
                } else if (loc.curr_task && !get_data(loc.curr_task).get_is_on_scheduler()) {
                    loc.stack_current_context = &get_execution_data(loc.curr_task).context;
                    return true;
                }
            } else if (loc.curr_task && !get_data(loc.curr_task).get_is_on_scheduler()) {
                loc.stack_current_context = &get_execution_data(loc.curr_task).context;
                return true;
            }
        }
        return false;
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
        auto& loc = get_loc();
        loc.policy = context.policy;
        loc.binded_id = id;

        context.completions.emplace_back(0);
        auto& completions = context.completions.back();
        auto completions_remove = --context.completions.end();
        context.executors++;
        initializer_guard.unlock();
        {
            fast_task::unique_lock lock(context.no_race);
            auto old_queues_ptr = context.executors_queues.load();
            auto new_queues = old_queues_ptr ? std::make_shared<std::vector<std::shared_ptr<work_stealing_deque<task>>>>(*old_queues_ptr)
                                             : std::make_shared<std::vector<std::shared_ptr<work_stealing_deque<task>>>>();
            new_queues->push_back(loc.local_tasks);
            context.executors_queues.store(new_queues);
        }
        _set_name_thread_dbg("Binded worker " + std::to_string(_thread_id()) + ": " + std::to_string(id));

        while (true) {
            if (!loadTaskBinded(context))
                break;

            if (loc.curr_task && get_data(loc.curr_task).bind_to_worker_id != (uint16_t)id) {
                transfer_task(std::move(loc.curr_task));
                continue;
            }
            if (execute_task(old_name))
                break;
            completions += 1;
        }

        while (!loc.local_tasks->empty())
            while (loc.local_tasks->pop(loc.curr_task))
                context.tasks.enqueue(std::move(loc.curr_task));

        {
            fast_task::unique_lock guard(context.no_race);
            context.completions.erase(completions_remove);
            auto old_queues_ptr = context.executors_queues.load();
            auto new_queues = std::make_shared<std::vector<std::shared_ptr<work_stealing_deque<task>>>>();
            new_queues->reserve(old_queues_ptr->size());

            for (const auto& q_ptr : *old_queues_ptr) {
                if (q_ptr.get() != loc.local_tasks.get())
                    new_queues->push_back(q_ptr);
            }

            context.executors_queues.store(new_queues);

            --context.executors;
            if (context.executors == 0) {
                if (context.in_close) {
                    while (context.tasks.size_approx())
                        while (context.tasks.try_dequeue(loc.curr_task)) {
                            if (!loc.curr_task)
                                continue;
                            if (context.abort_tasks_on_close) {
                                bool should_decrement = false;
                                {
                                    fast_task::lock_guard guard(get_data(loc.curr_task));
                                    if (!get_data(loc.curr_task).get_completed()) {
                                        get_data(loc.curr_task).set_completed(true);
                                        should_decrement = true;
                                    }
                                }
                                get_data(loc.curr_task).end_of_life_notify();
                                if (should_decrement) {
                                    --glob.executing_tasks;
                                    fast_task::shared_lock notify_guard(glob.task_thread_safety);
                                    glob.no_tasks_execute_notifier.notify_all_guarded();
                                }
                            } else {
                                get_data(loc.curr_task).bind_to_worker_id = (uint16_t)-1;
                                glob.tasks.enqueue(std::move(loc.curr_task));
                            }
                        }
                    glob.tasks_notifier.unsafe_notify_all();
                    context.on_closed_notifier.notify_all();
                    guard.unlock();
                } else {
                    assert(0 && "Caught executor/s death when context is not closed");
                    std::abort();
                }
            }
        }
        fast_task::lock_guard lock(glob.task_thread_safety);
        loc.reset();
        --glob.thread_count;
        glob.executor_shutdown_notifier.notify_all();
    }

#pragma endregion

#if defined(FT_TIMER_PRECISION) && FT_TIMER_PRECISION == 1 && !defined(FT_HAS_HIRES_TIMER)
    static void hires_spin_sleep(std::chrono::high_resolution_clock::time_point deadline) {
        while (std::chrono::high_resolution_clock::now() < deadline) {
    #if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
            __builtin_ia32_pause();
    #elif defined(__aarch64__) || defined(_M_ARM64)
            __yield();
    #else
            std::atomic_signal_fence(std::memory_order_seq_cst);
    #endif
        }
    }
#endif
    static void smart_wait_until(fast_task::unique_lock<fast_task::mutex>& guard, std::chrono::high_resolution_clock::time_point deadline) {
        auto now = std::chrono::high_resolution_clock::now();
        if (deadline <= now)
            return;
#if defined(FT_TIMER_PRECISION) && FT_TIMER_PRECISION == 1 && !defined(FT_HAS_HIRES_TIMER)
        auto remaining = deadline - now;
        if (remaining <= std::chrono::microseconds(100)) {
            guard.unlock();
            hires_spin_sleep(deadline);
            guard.lock();
            return;
        }
#endif
        glob.time_notifier.wait_until(guard, deadline);
    }

    void taskTimer() {
        _set_name_thread_dbg("task time controller");

        fast_task::unique_lock guard(glob.task_timer_safety);
        constexpr size_t BATCH = 64;
        task wake_ups[BATCH];
        task cold_wakes[BATCH];
        size_t wake_count = 0;
        size_t cold_count = 0;

        auto flush_wake_ups = [&] {
            for (size_t i = 0; i < wake_count; ++i)
                transfer_task(std::move(wake_ups[i]));
            wake_count = 0;
        };
        auto flush_cold = [&] {
            if (cold_count) {
                {
                    fast_task::shared_lock sg(glob.task_thread_safety);
                    for (size_t i = 0; i < cold_count; ++i)
                        glob.cold_tasks.enqueue(std::move(cold_wakes[i]));
                }
                glob.tasks_notifier.unsafe_notify_all();
                cold_count = 0;
            }
        };

        auto enqueue_wake = [&](task&& t) {
            wake_ups[wake_count++] = std::move(t);
            if (wake_count == BATCH)
                flush_wake_ups();
        };
        auto enqueue_cold = [&](task&& t) {
            cold_wakes[cold_count++] = std::move(t);
            if (cold_count == BATCH)
                flush_cold();
        };

        while (glob.time_control_enabled) {
            auto current_now = std::chrono::high_resolution_clock::now();

            if (glob.shutdown_requested.load(std::memory_order_acquire)) {
                glob.timed_wheel.clear([&](timing& tmng) {
                    if (tmng.check_id == get_data(tmng.awake_task).awake_check) {
                        fast_task::lock_guard tg(get_data(tmng.awake_task));
                        if (!get_data(tmng.awake_task).get_awaked()) {
                            get_data(tmng.awake_task).set_time_end(true);
                            enqueue_wake(std::move(tmng.awake_task));
                        }
                    }
                });
                glob.cold_timed_wheel.clear([&](timing& tmng) {
                    if (tmng.check_id == get_data(tmng.awake_task).awake_check) {
                        fast_task::lock_guard tg(get_data(tmng.awake_task));
                        if (!get_data(tmng.awake_task).get_awaked()) {
                            get_data(tmng.awake_task).set_time_end(true);
                            enqueue_cold(std::move(tmng.awake_task));
                        }
                    }
                });
            } else {
                glob.timed_wheel.collect_expired(current_now, [&](timing& tmng) {
                    if (tmng.check_id != get_data(tmng.awake_task).awake_check)
                        return;

                    fast_task::lock_guard tg(get_data(tmng.awake_task));
                    if (get_data(tmng.awake_task).get_awaked())
                        return;

                    get_data(tmng.awake_task).set_time_end(true);
                    enqueue_wake(std::move(tmng.awake_task));
                });

                glob.cold_timed_wheel.collect_expired(current_now, [&](timing& tmng) {
                    if (tmng.check_id != get_data(tmng.awake_task).awake_check)
                        return;
                    enqueue_cold(std::move(tmng.awake_task));
                });
            }

            guard.unlock();
            flush_wake_ups();
            flush_cold();

            {
                fast_task::shared_lock sg(glob.task_thread_safety);
                glob.no_tasks_execute_notifier.notify_all_guarded();
            }

            check_stw();
            guard.lock();
            if (!glob.time_control_enabled)
                break;

            auto next_hot = glob.timed_wheel.next_deadline();
            auto next_cold = glob.cold_timed_wheel.next_deadline();

            if (next_hot == std::chrono::high_resolution_clock::time_point::max() && next_cold == std::chrono::high_resolution_clock::time_point::max())
                glob.time_notifier.wait(guard);
            else {
                auto deadline = (next_hot == std::chrono::high_resolution_clock::time_point::max())
                                    ? next_cold
                                : (next_cold == std::chrono::high_resolution_clock::time_point::max())
                                    ? next_hot
                                    : std::min(next_hot, next_cold);
                smart_wait_until(guard, deadline);
            }
        }

        guard.unlock();
        flush_wake_ups();
        flush_cold();

        fast_task::shared_lock _guard(glob.task_thread_safety);
        get_loc().reset();
        --glob.thread_count;
        glob.executor_shutdown_notifier.notify_all();
    }

    void startTimeController() {
        fast_task::lock_guard guard(glob.task_timer_safety);
        if (glob.time_control_enabled)
            return;
        ++glob.thread_count;
        glob.time_control_enabled = true;
        fast_task::thread(taskTimer).detach();
    }

    void startTimeController_unsafe() {
        if (glob.time_control_enabled)
            return;
        ++glob.thread_count;
        glob.time_control_enabled = true;
        fast_task::thread(taskTimer).detach();
    }

    void unsafe_put_task_to_timed_queue(hashed_timing_wheel& wheel, std::chrono::high_resolution_clock::time_point t, task& task) {
        wheel.insert(timing(t, task, get_data(task).awake_check));
    }

    void makeTimeWait_extern(task _task, std::chrono::high_resolution_clock::time_point time_point) {
        if (!glob.time_control_enabled)
            startTimeController();
        auto& loc = get_loc();
        get_data(loc.curr_task).set_awaked(false);
        get_data(loc.curr_task).set_time_end(false);
        fast_task::lock_guard guard(glob.task_timer_safety);
        if (can_be_scheduled_task_to_hot())
            unsafe_put_task_to_timed_queue(glob.timed_wheel, time_point, _task);
        else
            unsafe_put_task_to_timed_queue(glob.cold_timed_wheel, time_point, _task);
        glob.tasks_notifier.notify_one();
    }

    void makeTimeWait(std::chrono::high_resolution_clock::time_point t) {
        if (!glob.time_control_enabled)
            startTimeController();
        auto& loc = get_loc();
        get_data(loc.curr_task).set_awaked(false);
        get_data(loc.curr_task).set_time_end(false);

        fast_task::lock_guard guard(glob.task_timer_safety);
        unsafe_put_task_to_timed_queue(glob.timed_wheel, t, loc.curr_task);
        glob.time_notifier.notify_one();
    }

    void makeTimeWait_unsafe(std::chrono::high_resolution_clock::time_point t) {
        if (!glob.time_control_enabled)
            startTimeController_unsafe();
        auto& loc = get_loc();
        get_data(loc.curr_task).set_awaked(false);
        get_data(loc.curr_task).set_time_end(false);

        unsafe_put_task_to_timed_queue(glob.timed_wheel, t, loc.curr_task);
        glob.time_notifier.notify_one();
    }

    void resetTimeWait() {
        auto& loc = get_loc();
        get_data(loc.curr_task).set_awaked(false);
        get_data(loc.curr_task).set_time_end(false);
    }
}
