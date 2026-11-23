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
    namespace {
        void worker_mode_desk(std::string_view mode, size_t id) {
            if (!task::enable_task_naming)
                return;
            _set_name_thread_dbg("Worker " + std::to_string(_thread_id()) + ": " + std::string(mode) + std::to_string(id));
        }
    }

    void in_place_run(executors_local& loc, task_object* data) {
        task_run_enter(&loc);
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
        task_run_exit(&loc);
    }

    void in_coroutine_run(executors_local& loc, task_object* data) {
        task_run_enter(&loc);
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
        task_run_exit(&loc);
    }

    namespace {
        inline void arm_pending_timer(executors_local& loc) {
            if (loc.pending_timer == fast_task::time_point::min())
                return;
            makeTimeWait(loc.pending_timer);
            loc.pending_timer = fast_task::time_point::min();
        }
    }

    void in_stackfull_run(executors_local& loc, task_object* data) {
        auto& stack_current_context = get_execution_data(data).context;
        if (stack_current_context) {
            stack_current_context = std::move(stack_current_context).resume();
            arm_pending_timer(loc);
            data->get_relock().relock_start();
        } else {
            light_stack stack_alloc(1048576 /*1 mb*/);
            auto ss = stack_alloc.allocate();
#if PLATFORM_LINUX
            get_execution_data(data).stack_ptr = ((char*)ss.sp) - ss.size;
            get_execution_data(data).stack_size = ss.size;
#endif
            task_run_enter(&loc);
            stack_current_context = boost::context::callcc(std::allocator_arg, boost::context::preallocated(ss.sp, ss.size, ss), stack_alloc, context_exec);
            arm_pending_timer(loc);
            data->get_relock().relock_start();
        }
        if (loc.ex_ptr) {
            light_stack stack_alloc(1048576 /*1 mb*/);
            auto ss = stack_alloc.allocate();
#if PLATFORM_LINUX
            get_execution_data(data).stack_ptr = ((char*)ss.sp) - ss.size;
            get_execution_data(data).stack_size = ss.size;
#endif
            task_run_enter(&loc);
            stack_current_context = boost::context::callcc(std::allocator_arg, boost::context::preallocated(ss.sp, ss.size, ss), stack_alloc, context_ex_handle);
            arm_pending_timer(loc);
            data->get_relock().relock_start();
            loc.ex_ptr = nullptr;
        }
    }

    bool execute_task() {
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

            worker_mode_desk("process task - ", this_task::get_id());
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
                fast_task::lock_guard guard(*data);
                arm_pending_timer(loc);
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
                if (data->is_ended()) {
                    bool should_decrement = false;
                    {
                        fast_task::lock_guard guard(*data);
                        if (!data->get_completed()) {
                            data->set_completed(true);
                            should_decrement = true;
                        }
                    }
                    if (should_decrement)
                        task_mark_completed(*data, &loc);
                }
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
        bool should_decrement = false;
        bool do_yield_transfer = loc.yield_request;
        bool do_invalid_transfer = false;
        {
            task_object& finished = get_data(loc.curr_task);
            fast_task::lock_guard guard(finished);
            end_of_life = finished.is_ended();

            if (!end_of_life) {
                if (!do_yield_transfer && finished.link_counter == 1) {
                    do_invalid_transfer = true;
                    finished.set_invalid_switch_caught(true);
                }

                if (!do_yield_transfer && !do_invalid_transfer)
                    finished.set_status(task_object::status_e::suspended);
                else
                    finished.set_status(task_object::status_e::running);
            } else if (!finished.get_completed()) {
                finished.set_completed(true);
                should_decrement = true;
            }
        }
        if (do_invalid_transfer || do_yield_transfer) {
            transfer_task(std::move(loc.curr_task));
            loc.yield_request = false;
        } else if (should_decrement) {
            task_mark_completed(get_data(loc.curr_task), &loc);
        }

        loc.curr_task = nullptr;
        worker_mode_desk("idle ", 0);
        return false;
    }
}
