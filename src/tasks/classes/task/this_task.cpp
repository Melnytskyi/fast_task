// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <exceptions.hpp>
#include <task.hpp>
#include <tasks/_internal.hpp>

namespace fast_task::this_task {
    size_t get_id() noexcept {
        if (!get_loc().is_task_thread)
            return (size_t)_thread_id() | native_thread_flag;
        else
            return get_loc().curr_task.get_id();
    }

    bool is_task() noexcept {
        return get_loc().is_task_thread;
    }

    void check_cancellation() {
        if (checkCancellation())
            throw task_cancellation();
    }

    bool is_cancellation_requested() noexcept {
        return checkCancellation();
    }

    void self_cancel() {
        if (get_loc().is_task_thread) {
            if (get_loc().curr_task)
                get_loc().curr_task.notify_cancel();
            throw task_cancellation();
        } else
            throw invalid_context();
    }

    void the_coroutine_ended(const task& task) noexcept {
        if (task) {
            {
                fast_task::lock_guard guard(get_data(task));
                get_data(task).set_is_restartable(false);
            }
            get_data(task).end_of_life_notify();
        }
    }

    bool transfer_to(const task& target) {
        if (get_loc().is_task_thread) {
            if (!target || !get_loc().curr_task)
                return false;
            if (get_loc().ex_ptr)
                return false;
            if (get_loc().transfer_state.pending)
                return false;
            if (!(
                    get_data(get_loc().curr_task).get_is_on_scheduler() == true &&
                    get_data(target).get_is_on_scheduler() == true &&
                    (get_data(target).is_started() == false || (get_data(target).is_suspended() == true && get_data(target).get_is_restartable() == true))
                ))
                return false;

            if (get_data(get_loc().curr_task).bind_to_worker_id != get_data(target).bind_to_worker_id)
                return false;


#if FT_TASK_TRANSFERS_LIMIT > 0
            if (get_loc().transfer_state.transfers >= FT_TASK_TRANSFERS_LIMIT)
                return false;
            ++get_loc().transfer_state.transfers;
#endif
            if (!get_data(target).is_started())
                ++glob.executing_tasks;
            get_data(target).set_status(task_object::status_e::running);

            get_loc().transfer_state.pending = target;
            return true;
        } else
            return false;
    }

    void sleep_until(std::chrono::high_resolution_clock::time_point time_point) {
        if (get_loc().is_task_thread) {
            fast_task::lock_guard guard(glob.task_timer_safety);
            makeTimeWait_unsafe(time_point);
            swapCtxRelock(glob.task_timer_safety);
            resetTimeWait();
        } else
            this_thread::sleep_until(time_point);
    }

    bool FT_API enter_sleep_until(enter_state&, std::chrono::high_resolution_clock::time_point time_point) {
        if (get_loc().is_task_thread) {
            if (std::chrono::high_resolution_clock::now() >= time_point)
                return true;
            fast_task::lock_guard guard(glob.task_timer_safety);
            makeTimeWait_unsafe(time_point);
            return false;
        } else
            throw invalid_context();
    }

    bool FT_API enter_yield(enter_state&) {
        transfer_task(task{get_loc().curr_task});
        return false;
    }

    void yield() {
        if (get_loc().is_task_thread) {
            get_loc().yield_request = true;
            swapCtx();
        } else
            this_thread::yield();
    }
}