// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <tasks.hpp>
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
            throw std::runtime_error("Thread attempted cancel self, like task");
    }

    void the_coroutine_ended() noexcept {
        if (loc.is_task_thread)
            if (loc.curr_task)
                if (get_data(loc.curr_task).callbacks.is_extended_mode)
                    get_data(loc.curr_task).callbacks.extended_mode.is_coroutine = false;
    }

#pragma optimize("", off)
#if defined(__GNUC__) && !defined(__clang__)
    #pragma GCC push_options
    #pragma GCC optimize("O0")
#endif

    void sleep_until(std::chrono::high_resolution_clock::time_point time_point) {
        if (loc.is_task_thread) {
            fast_task::lock_guard guard(get_data(loc.curr_task).no_race);
            makeTimeWait(time_point);
            swapCtxRelock(get_data(loc.curr_task).no_race);
        } else
            this_thread::sleep_until(time_point);
    }

    void yield() {
        if (loc.is_task_thread) {
            fast_task::lock_guard guard(glob.task_thread_safety);
            glob.tasks.push(loc.curr_task);
            swapCtxRelock(glob.task_thread_safety);
        } else
            this_thread::yield();
    }

#if defined(__GNUC__) && !defined(__clang__)
    #pragma GCC pop_options
#endif
#pragma optimize("", on)
}