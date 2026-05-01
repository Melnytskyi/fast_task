// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <task.hpp>
#include <tasks/_internal.hpp>

namespace fast_task::this_task {
    size_t get_id() noexcept {
        if (!loc.is_task_thread)
            return 0;
        else
            return std::hash<size_t>()(reinterpret_cast<size_t>(&*loc.curr_task));
    }

    bool is_task() noexcept {
        return loc.is_task_thread;
    }

    void check_cancellation() {
        if (checkCancellation())
            throw task_cancellation();
    }

    bool is_cancellation_requested() noexcept {
        return checkCancellation();
    }

    void self_cancel() {
        if (loc.is_task_thread) {
            if (loc.curr_task)
                loc.curr_task->notify_cancel();
            throw task_cancellation();
        } else
            throw invalid_context();
    }

    void the_coroutine_ended(const std::shared_ptr<task>& task) noexcept {
        if (task) {
            {
                fast_task::lock_guard guard(get_data(task).no_race);
                get_data(task).callbacks.is_restartable = false;
                get_data(task).end_of_life = true;
                get_data(task).started = true;
            }
            get_data(task).result_notify.notify_all();
        }
    }

#pragma optimize("", off)
#if defined(__GNUC__) && !defined(__clang__)
    #pragma GCC push_options
    #pragma GCC optimize("O0")
#endif

    void sleep_until(std::chrono::high_resolution_clock::time_point time_point) {
        if (loc.is_task_thread) {
            fast_task::lock_guard guard(glob.task_timer_safety);
            makeTimeWait_unsafe(time_point);
            swapCtxRelock(glob.task_timer_safety);
            resetTimeWait();
        } else
            this_thread::sleep_until(time_point);
    }

    bool FT_API enter_sleep_until(std::chrono::high_resolution_clock::time_point time_point) {
        if (loc.is_task_thread) {
            if (std::chrono::high_resolution_clock::now() >= time_point)
                return true;
            fast_task::lock_guard guard(glob.task_timer_safety);
            makeTimeWait_unsafe(time_point);
            return false;
        } else
            throw invalid_context();
    }

    bool FT_API enter_yield() {
        transfer_task(auto{loc.curr_task});
        return false;
    }

    void yield() {
        if (loc.is_task_thread) {
            loc.yield_request = true;
            swapCtx();
        } else
            this_thread::yield();
    }

#if defined(__GNUC__) && !defined(__clang__)
    #pragma GCC pop_options
#endif
#pragma optimize("", on)
}