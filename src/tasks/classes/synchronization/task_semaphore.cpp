// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <tasks.hpp>
#include <tasks/_internal.hpp>

namespace fast_task {
    struct task_semaphore::resume_task {
        std::shared_ptr<task> task;
        uint16_t awake_check;
    };

    task_semaphore::task_semaphore() {}

    task_semaphore::~task_semaphore() {}


    void task_semaphore::setMaxThreshold(size_t val) {
        fast_task::lock_guard guard(no_race);
        release_all();
        max_threshold = val;
        allow_threshold = max_threshold;
    }

    void task_semaphore::lock() {
        get_data(loc.curr_task).awaked = false;
        get_data(loc.curr_task).time_end_flag = false;
        fast_task::unique_lock keeper(no_race);
        while (!allow_threshold) {
            if (loc.is_task_thread) {
                fast_task::lock_guard guard(glob.task_thread_safety);
                resume_task.emplace_back(loc.curr_task, get_data(loc.curr_task).awake_check);
                keeper.unlock();
                swapCtxRelock(glob.task_thread_safety);
            } else
                native_notify.wait(keeper);
        }
        --allow_threshold;
    }

    bool task_semaphore::try_lock() {
        if (!no_race.try_lock())
            return false;
        if (!allow_threshold) {
            no_race.unlock();
            return false;
        } else
            --allow_threshold;
        no_race.unlock();
        return true;
    }

    bool task_semaphore::try_lock_for(size_t milliseconds) {
        return try_lock_until(std::chrono::high_resolution_clock::now() + std::chrono::milliseconds(milliseconds));
    }

    bool task_semaphore::try_lock_until(std::chrono::high_resolution_clock::time_point time_point) {
        if (!no_race.try_lock_until(time_point))
            return false;
        fast_task::unique_lock keeper(no_race);

        while (!allow_threshold) {
            if (loc.is_task_thread) {
                fast_task::lock_guard guard(glob.task_thread_safety);
                makeTimeWait(time_point);
                resume_task.emplace_back(loc.curr_task, get_data(loc.curr_task).awake_check);
                keeper.unlock();
                swapCtxRelock(glob.task_thread_safety);
                if (!get_data(loc.curr_task).awaked)
                    return false;
            } else if (native_notify.wait_until(keeper, time_point) == fast_task::cv_status::timeout)
                return false;
        }
        --allow_threshold;
        no_race.unlock();
        return true;
    }

    void task_semaphore::release() {
        fast_task::lock_guard lg0(no_race);
        if (allow_threshold == max_threshold)
            return;
        allow_threshold++;
        native_notify.notify_one();
        while (resume_task.size()) {
            auto& it = resume_task.front();
            fast_task::lock_guard lg2(get_data(it.task).no_race);
            if (!get_data(it.task).time_end_flag) {
                if (get_data(it.task).awake_check != it.awake_check)
                    continue;
                get_data(it.task).awaked = true;
                auto task = resume_task.front().task;
                resume_task.pop_front();
                transfer_task(task);
                return;
            } else
                resume_task.pop_front();
        }
    }

    void task_semaphore::release_all() {
        fast_task::lock_guard lg0(no_race);
        if (allow_threshold == max_threshold)
            return;
        fast_task::lock_guard lg1(glob.task_thread_safety);
        allow_threshold = max_threshold;
        native_notify.notify_all();
        while (resume_task.size()) {
            auto& it = resume_task.back();
            fast_task::lock_guard lg2(get_data(it.task).no_race);
            if (!get_data(it.task).time_end_flag) {
                if (get_data(it.task).awake_check != it.awake_check)
                    continue;
                get_data(it.task).awaked = true;
                auto task = resume_task.front().task;
                resume_task.pop_front();
                transfer_task(task);
            } else
                resume_task.pop_front();
        }
    }

    bool task_semaphore::is_locked() {
        if (try_lock()) {
            release();
            return true;
        }
        return false;
    }
}