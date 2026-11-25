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
#if defined(_MSC_VER) && defined(_M_ARM64)
    #pragma optimize("", off)
#endif
    void swapCtx() {
        auto pre_switch_loc = get_loc();
        if (pre_switch_loc) {
            stop_timer();
            auto& task_data = get_data(pre_switch_loc->curr_task);
            if (task_data.get_is_on_scheduler())
                throw invalid_context();
            pre_switch_loc->context_in_swap = true;
            preserve_interrupt_data();

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
                flush_interrupt_data();
                auto post_switch_loc = get_loc();
#ifndef NDEBUG
                glob.tasks_in_swap.fetch_sub(1, std::memory_order_release);
#endif

                bool old_context_in_swap = false;
                if (post_switch_loc) {
                    old_context_in_swap = post_switch_loc->context_in_swap;
                    post_switch_loc->context_in_swap = true;
                }

                auto relock_state = task_data.get_relock();
                task_data.set_relock(nullptr);
                auto old_time_end_flag = task_data.get_time_end();
                auto old_awaked = task_data.get_awaked();

                relock_state.relock_end();
                task_data.set_time_end(old_time_end_flag);
                task_data.set_awaked(old_awaked);

                if (auto* loc_after = get_loc())
                    loc_after->context_in_swap = old_context_in_swap;
                throw;
            }
#if defined(FT_EXCEPTION_POLICY_PRESERVE)
            if (get_execution_data(&task_data).switch_preserve)
                std::rethrow_exception(std::move(get_execution_data(&task_data).switch_preserve));
#endif
            restore_interrupt_data();
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
                flush_interrupt_data();
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
            auto* post_loc = get_loc();
            if (post_loc) {
                task_run_exit(post_loc);
            } else {
                worker_pool_storage* pool = task_obj.get_pool_assigned() ? pool_for_index(task_obj.pool_index) : nullptr;
                if (!pool)
                    pool = &global_storage();
                pool->runtime.in_run_tasks.fetch_sub(1, std::memory_order_release);
            }
            throw;
        } catch (...) {
            get_loc()->ex_ptr = std::current_exception();
        }
        stop_timer();
        flush_interrupt_data();
        {
            fast_task::lock_guard l(task_obj);
            task_run_exit(get_loc());
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
                flush_interrupt_data();
                timer_reinit();
                auto vtable = task_obj.vtable;
                if (vtable && vtable->on_exception) {
                    std::exception_ptr ex = get_loc()->ex_ptr;
                    vtable->on_exception(task_obj.user_data(), ex);
                }
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
            auto* post_loc = get_loc();
            if (post_loc) {
                task_run_exit(post_loc);
            } else {
                worker_pool_storage* pool = task_obj.get_pool_assigned() ? pool_for_index(task_obj.pool_index) : nullptr;
                if (!pool)
                    pool = &global_storage();
                pool->runtime.in_run_tasks.fetch_sub(1, std::memory_order_release);
            }
            throw;
        } catch (...) {
            get_loc()->ex_ptr = std::current_exception();
        }
        stop_timer();
        flush_interrupt_data();
        task_obj.set_is_restartable(false);
        task_obj.end_of_life_notify();
        task_run_exit(get_loc());
        return std::move(stack_current_context);
    }
#if defined(_MSC_VER) && defined(_M_ARM64)
    #pragma optimize("", on)
#endif
}
