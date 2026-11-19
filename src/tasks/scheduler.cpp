// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <fast_task/native.hpp>
#include <fast_task/task.hpp>
#include <tasks/_internal.hpp>
#include <tasks/util/interrupt.hpp>
#include <tasks/util/light_stack.hpp>

namespace fast_task {

#define worker_mode_desk(old_name, mode, id) \
    if (task::enable_task_naming)            \
        worker_mode_desk_(old_name, mode, id);

    void worker_mode_desk_(const std::string& old_name, std::string_view mode, size_t id) {
        if (old_name.empty())
            _set_name_thread_dbg("Worker " + std::to_string(_thread_id()) + ": " + std::string(mode) + std::to_string(id));
        else
            _set_name_thread_dbg(old_name + " | (Temporal worker) " + std::to_string(_thread_id()) + ": " + std::string(mode) + std::to_string(id));
    }

    size_t task::max_running_tasks = 0;
#ifdef FT_ENABLE_PREEMPTIVE_SCHEDULER
    void timer_reinit() {
        auto* loc = get_loc();
        assert(loc && "timer_reinit requires a worker context");
        if (loc->policy == scheduler::preemption_policy::cooperative_only)
            return;
        std::chrono::nanoseconds interval = next_quantum(get_execution_data(loc->curr_task).priority, get_execution_data(loc->curr_task).current_available_quantum);
        interrupt::itimerval timer;
        timer.it_interval.tv_sec = 0;
        timer.it_interval.tv_usec = 0;
        timer.it_value.tv_sec = interval.count() / 1000000000;
        timer.it_value.tv_usec = (interval.count() % 1000000000) / 1000;
        interrupt::setitimer(&timer, nullptr);
    }

    void swapCtx();

    void interruptTask() {
        auto* loc = get_loc();
        assert(loc && "interruptTask requires a worker context");
        if (loc->policy == scheduler::preemption_policy::cooperative_only)
            return;
    #ifdef FT_EXCEPTION_POLICY_CHECK
        if (std::uncaught_exceptions())
            return;
    #endif
        // Preemption is only worth an interrupt when there is other work
        // waiting for the pool (§2.10's local notification rule).
        {
            auto& task_data = get_data(loc->curr_task);
            worker_pool_storage* pool = task_data.get_pool_assigned()
                                            ? pool_for_index(task_data.pool_index)
                                            : nullptr;
            if (!pool)
                pool = &global_storage();
            // The cheap witness, taken without any lock: a policy whose queue
            // is a plain lock-free structure answers from its own state.
            if (!has_queued_work(loc, pool)) {
                timer_reinit();
                return;
            }
            // Queued but throttled: letting this worker go would put it back
            // into the same queue behind the same limit.
            if (pool->is_global && task::max_running_tasks && !can_be_scheduled_task_to_hot()) {
                timer_reinit();
                return;
            }
        }

        ++glob.interrupts;
        auto curr_task = loc->curr_task;
        ++get_execution_data(curr_task).interrupt_count;
        auto old_relock = get_data(curr_task).get_relock();
        get_data(curr_task).set_relock(nullptr);
        loc->yield_request = true;
        swapCtx();
        get_data(curr_task).set_relock(old_relock);
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
        auto pre_switch_loc = get_loc();
        if (pre_switch_loc) {
            stop_timer();
            auto& task_data = get_data(pre_switch_loc->curr_task);
            if (task_data.get_is_on_scheduler())
                throw invalid_context();
            pre_switch_loc->context_in_swap = true;
            preserve_interrupt_data;

            auto& stack_current_context = get_execution_data(&task_data).context;
#ifndef NDEBUG
            glob.tasks_in_swap.fetch_add(1, std::memory_order_release);
#endif
            ++get_execution_data(&task_data).context_switch_count;

#ifdef FT_EXCEPTION_POLICY_CHECK
            if (std::uncaught_exceptions()) {
                assert(false && "Unexpected exception during context switch");
                std::abort();
            }
#elif defined(FT_EXCEPTION_POLICY_PRESERVE)
            if (std::uncaught_exceptions())
                get_execution_data(&task_data).switch_preserve = std::current_exception();
#endif
            try {
                stack_current_context = std::move(stack_current_context).resume();
            } catch (const boost::context::detail::forced_unwind&) {
                flush_interrupt_data;
                auto post_switch_loc = get_loc();
#ifndef NDEBUG
                glob.tasks_in_swap.fetch_sub(1, std::memory_order_release);
#endif

                bool old_context_in_swap = post_switch_loc->context_in_swap;
                post_switch_loc->context_in_swap = true;

                auto relock_state = task_data.get_relock();
                task_data.set_relock(nullptr);
                auto old_time_end_flag = task_data.get_time_end();
                auto old_awaked = task_data.get_awaked();

                relock_state.relock_end();
                task_data.set_time_end(old_time_end_flag);
                task_data.set_awaked(old_awaked);

                get_loc()->context_in_swap = old_context_in_swap;
                throw;
            }
#if defined(FT_EXCEPTION_POLICY_PRESERVE)
            if (get_execution_data(&task_data).switch_preserve)
                std::rethrow_exception(std::move(get_execution_data(&task_data).switch_preserve));
#endif
            preserve_interrupt_data;
#ifndef NDEBUG
            glob.tasks_in_swap.fetch_sub(1, std::memory_order_release);
#endif
            get_loc()->context_in_swap = true;
            auto relock_state = task_data.get_relock();
            task_data.set_relock(nullptr);
            auto old_time_end_flag = task_data.get_time_end();
            auto old_awaked = task_data.get_awaked();
            relock_state.relock_end();

            task_data.awake_check++;
            task_data.set_time_end(old_time_end_flag);
            task_data.set_awaked(old_awaked);
            get_loc()->context_in_swap = false;
            if (task_data.get_invalid_switch_caught()) {
                task_data.set_invalid_switch_caught(false);
                throw invalid_switch();
            }
            constexpr auto timeout_disabled = fast_task::time_point::min().time_since_epoch().count();
            if (get_execution_data(&task_data).timeout != timeout_disabled)
                if (get_execution_data(&task_data).timeout <= fast_task::clock::now().time_since_epoch().count())
                    throw task_cancellation();
            timer_reinit();
        } else
            throw invalid_context();
    }

    void swapCtxRelock(const mutex_unify& mut0) {
        get_data(get_loc()->curr_task).set_relock(mut0);
        swapCtx();
    }

    void swapCtxUnlock(const mutex_unify& mut0) {
        get_data(get_loc()->curr_task).set_unlock(mut0);
        swapCtx();
    }

    boost::context::continuation context_exec(boost::context::continuation&& sink) {
        auto& task_obj = get_data(get_loc()->curr_task);
        auto& stack_current_context = get_execution_data(&task_obj).context;
        stack_current_context = std::move(sink);
        try {
            if (!checkCancellation()) {
                flush_interrupt_data;
                timer_reinit();
                auto vtable = task_obj.vtable;
                if (task_obj.on_start_override)
                    task_obj.on_start_override->callback(&task_obj);
                else if (vtable && vtable->on_start)
                    vtable->on_start(task_obj.user_data());
            } else { //this_task::the_coroutine_ended(get_loc().curr_task); inline
                {
                    fast_task::lock_guard guard(task_obj);
                    task_obj.set_is_restartable(false);
                }
                task_obj.end_of_life_notify();
            }
        } catch (const task_cancellation& cancel) {
            forceCancelCancellation(cancel);
        } catch (const boost::context::detail::forced_unwind&) {
            task_run_exit();
            throw;
        } catch (...) {
            get_loc()->ex_ptr = std::current_exception();
        }
        stop_timer();
        flush_interrupt_data;
        {
            fast_task::lock_guard l(task_obj);
            task_run_exit();
            if (task_obj.get_is_restartable()) {
                return std::move(stack_current_context);
            }
        }
        if (!get_loc()->ex_ptr)
            task_obj.end_of_life_notify();

        return std::move(stack_current_context);
    }

    boost::context::continuation context_ex_handle(boost::context::continuation&& sink) {
        auto& task_obj = get_data(get_loc()->curr_task);
        auto& stack_current_context = get_execution_data(&task_obj).context;
        stack_current_context = std::move(sink);
        try {
            if (!checkCancellation()) {
                flush_interrupt_data;
                timer_reinit();
                auto vtable = task_obj.vtable;
                if (vtable && vtable->on_exception)
                    vtable->on_exception(task_obj.user_data(), get_loc()->ex_ptr);
            } else { //this_task::the_coroutine_ended(get_loc().curr_task); inline
                {
                    fast_task::lock_guard guard(task_obj);
                    task_obj.set_is_restartable(false);
                }
                task_obj.end_of_life_notify();
            }
        } catch (task_cancellation& cancel) {
            forceCancelCancellation(cancel);
        } catch (const boost::context::detail::forced_unwind&) {
            task_obj.set_is_restartable(false);
            task_obj.end_of_life_notify();
            task_run_exit();
            return std::move(stack_current_context);
        } catch (...) {
            get_loc()->ex_ptr = std::current_exception();
        }
        stop_timer();
        flush_interrupt_data;
        task_obj.set_is_restartable(false);
        task_obj.end_of_life_notify();
        task_run_exit();
        return std::move(stack_current_context);
    }

    void in_place_run(executors_local& loc, task_object* data) {
        task_run_enter();
        data->awake_check++;
        try {
            if (!checkCancellation()) {
                if (data->on_start_override)
                    data->on_start_override->callback(data);
                else if (data->vtable && data->vtable->on_start)
                    data->vtable->on_start(data->user_data());
            }
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
        task_run_exit();
    }

    void in_coroutine_run(executors_local& loc, task_object* data) {
        task_run_enter();
        data->awake_check++;
        try {
            if (!checkCancellation()) {
                if (data->on_start_override)
                    data->on_start_override->callback(data);
                else if (data->vtable && data->vtable->on_start)
                    data->vtable->on_start(data->user_data());
                data->get_relock().relock_start();
                data->set_status(task_object::status_e::suspended);
            } else
                data->set_is_restartable(false);
            if (!data->get_is_restartable())
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
        task_run_exit();
    }

    void in_stackfull_run(executors_local& loc, task_object* data) {
        auto& stack_current_context = get_execution_data(data).context;
        if (stack_current_context) {
            stack_current_context = std::move(stack_current_context).resume();
            data->get_relock().relock_start();
        } else {
            light_stack stack_alloc(1048576 /*1 mb*/);
            auto ss = stack_alloc.allocate();
#if PLATFORM_LINUX
            get_execution_data(data).stack_ptr = ((char*)ss.sp) - ss.size;
            get_execution_data(data).stack_size = ss.size;
#endif
            task_run_enter();
            stack_current_context = boost::context::callcc(std::allocator_arg, boost::context::preallocated(ss.sp, ss.size, ss), stack_alloc, context_exec);
            data->get_relock().relock_start();
        }
        if (loc.ex_ptr) {
            light_stack stack_alloc(1048576 /*1 mb*/);
            auto ss = stack_alloc.allocate();
#if PLATFORM_LINUX
            get_execution_data(data).stack_ptr = ((char*)ss.sp) - ss.size;
            get_execution_data(data).stack_size = ss.size;
#endif
            task_run_enter();
            stack_current_context = boost::context::callcc(std::allocator_arg, boost::context::preallocated(ss.sp, ss.size, ss), stack_alloc, context_ex_handle);
            data->get_relock().relock_start();
            loc.ex_ptr = nullptr;
        }
    }

    bool execute_task(const std::string& old_name) {
        auto* loc_ptr = get_loc();
        assert(loc_ptr && "execute_task requires a worker context");
        auto& loc = *loc_ptr;
        if (!loc.curr_task)
            return true;
        task_object* data = &get_data(loc.curr_task);
        auto& vtable = data->vtable;
        if (vtable && vtable->on_start == nullptr && vtable->on_destruct == nullptr) {
            data->end_of_life_notify();
            loc.curr_task = nullptr;
            return true;
        } else if (!vtable->on_start) {
            data->end_of_life_notify();
            goto end_task;
        }

        if constexpr (FT_TASK_TRANSFERS_LIMIT > 0)
            loc.transfer_state.transfers = 0;

        loc.is_task_thread = true;
        while (true) {
            {
                fast_task::lock_guard guard(*data);
                if (data->is_ended())
                    goto end_task;

                data->set_status(task_object::status_e::running);
            }

            worker_mode_desk(old_name, "process task - ", this_task::get_id());
            switch (data->get_execution_mode()) {
            case task_object::execution_mode::stackfull:
            case task_object::execution_mode::_stackfull_reserved:
                in_stackfull_run(loc, data);
                break;
            case task_object::execution_mode::stackless_callback:
                in_place_run(loc, data);
                break;
            case task_object::execution_mode::as_coroutine:
                in_coroutine_run(loc, data);
                break;
            default:
                break;
            }
            if (loc.pending_timer != fast_task::time_point::min()) {
                makeTimeWait(loc.pending_timer);
                loc.pending_timer = fast_task::time_point::min();
            }
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
                data->awake_check++;
            }
        }
    end_task:
        if constexpr (FT_TASK_TRANSFERS_LIMIT > 0)
            loc.transfer_state.transfers = 0;
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
                    data->set_status(task_object::status_e::suspended);
                else
                    data->set_status(task_object::status_e::running);
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

            if (should_decrement)
                task_mark_completed(get_data(loc.curr_task));
        }


        loc.curr_task = nullptr;
        worker_mode_desk(old_name, "idle ", 0);
        return false;
    }

    bool try_steal_from_registry(worker_registry_view& registry, task_object*& raw_curr_task) {
        auto* loc = get_loc();
        if (!loc)
            return false;
        // The view owns the cached-slot fast path and the thief-vs-release
        // handshake (plans/pool-architecture.md §2.6).
        return registry.try_steal(&loc->local_tasks, loc->rand, &loc->steal_cache.last_slot, raw_curr_task);
    }

    void taskExecutor(bool end_in_task_out, bool prevent_naming) {
        set_interruptTask();

        // Everything below — registry claim, thread naming, the fetch/steal/
        // execute loop, idle parking and the drain on exit — is owned by
        // worker_context. This wrapper only picks the run mode:
        //   end_in_task_out -> drain what is runnable, then hand control back
        //   otherwise       -> serve until the scheduler shuts down
        {
            scheduler::worker_options opts;
            opts.prevent_thread_naming = prevent_naming;
            scheduler::worker_context ctx(opts);
            if (end_in_task_out)
                ctx.poll_drained();
            else
                ctx.poll_all();
        }

        // Every caller of taskExecutor() does ++glob.thread_count before
        // spawning the thread, so the matching decrement has to happen here.
        // shut_down() waits on thread_count reaching zero; without this it
        // blocks forever.
        fast_task::lock_guard lock(glob.task_thread_safety);
        --glob.thread_count;
        glob.executor_shutdown_notifier.notify_all();
    }

    void bindedTaskExecutor(uint16_t id) {
        set_interruptTask();

        // All worker bookkeeping (registry claim/release, thread naming, the
        // drain of local_tasks back into the pool) is owned by worker_context.
        // The close-time abort/drain of a pool moved to close_bind_only_executor,
        // which waits for active_workers to reach zero before touching the
        // storage (plans/pool-architecture.md §2.17).
        worker_pool_storage* pool = pool_for_index(bind_pool_index(id));
        if (!pool) {
            assert(0 && "Binded worker context not found");
            std::abort();
        }

        {
            scheduler::worker_options opts;
            opts.bind_id = id;
            opts.policy = pool->config.policy;
            scheduler::worker_context ctx(opts);
            ctx.poll_all();
        }

        fast_task::lock_guard lock(glob.task_thread_safety);
        --glob.thread_count;
        glob.executor_shutdown_notifier.notify_all();
    }

#pragma endregion
}
