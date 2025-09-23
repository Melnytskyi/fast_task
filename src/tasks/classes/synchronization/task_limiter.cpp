// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <task.hpp>
#include <tasks/_internal.hpp>

namespace fast_task {
    struct task_limiter::resume_task {
        std::shared_ptr<task> task;
        uint16_t awake_check;
    };

    task_limiter::task_limiter() {}

    task_limiter::~task_limiter() {
        if (values.locked) {
            assert(false && "Tried to destroy locked limiter");
            std::terminate();
        }
    }

    void task_limiter::set_max_threshold(size_t val) {
        fast_task::lock_guard guard(values.no_race);
        if (val < 1)
            val = 1;
        if (values.max_threshold == val)
            return;
        if (values.max_threshold > val) {
            if (values.allow_threshold > values.max_threshold - val)
                values.allow_threshold -= values.max_threshold - val;
            else {
                values.locked = true;
                values.allow_threshold = 0;
            }
            values.max_threshold = val;
            return;
        } else {
            if (!values.allow_threshold) {
                size_t unlocks = values.max_threshold;
                values.max_threshold = val;
                while (unlocks-- >= 1)
                    unchecked_unlock();
            } else
                values.allow_threshold += val - values.max_threshold;
        }
    }

    void task_limiter::lock() {
        fast_task::unique_lock guard(values.no_race);
        while (values.locked) {
            if (loc.is_task_thread) {
                get_data(loc.curr_task).awaked = false;
                get_data(loc.curr_task).time_end_flag = false;
                values.resume_task.emplace_back(loc.curr_task, get_data(loc.curr_task).awake_check);
                swapCtxRelock(*guard.mutex());
            } else
                values.native_notify.wait(guard);
        }
        if (--values.allow_threshold == 0)
            values.locked = true;

        if (std::find(values.lock_check.begin(), values.lock_check.end(), &*loc.curr_task) != values.lock_check.end()) {
            if (++values.allow_threshold != 0)
                values.locked = false;
            values.no_race.unlock();
            throw std::logic_error("Dead lock. task try lock already locked task limiter");
        } else
            values.lock_check.push_back(&*loc.curr_task);
        values.no_race.unlock();
        return;
    }

    bool task_limiter::try_lock() {
        if (!values.no_race.try_lock())
            return false;
        if (values.locked) {
            values.no_race.unlock();
            return false;
        } else if (--values.allow_threshold <= 0)
            values.locked = true;

        if (std::find(values.lock_check.begin(), values.lock_check.end(), &*loc.curr_task) != values.lock_check.end()) {
            if (++values.allow_threshold != 0)
                values.locked = false;
            values.no_race.unlock();
            throw std::logic_error("Dead lock. task try lock already locked task limiter");
        } else
            values.lock_check.push_back(&*loc.curr_task);
        values.no_race.unlock();
        return true;
    }

    bool task_limiter::try_lock_for(size_t milliseconds) {
        return try_lock_until(std::chrono::high_resolution_clock::now() + std::chrono::milliseconds(milliseconds));
    }

    bool task_limiter::try_lock_until(std::chrono::high_resolution_clock::time_point time_point) {
        fast_task::unique_lock guard(values.no_race);
        while (values.locked) {
            if (loc.is_task_thread) {
                get_data(loc.curr_task).awaked = false;
                get_data(loc.curr_task).time_end_flag = false;
                makeTimeWait(time_point);
                values.resume_task.emplace_back(loc.curr_task, get_data(loc.curr_task).awake_check);
                swapCtxRelock(values.no_race);
                if (!get_data(loc.curr_task).awaked)
                    return false;
            } else if (values.native_notify.wait_until(guard, time_point) == fast_task::cv_status::timeout)
                return false;
        }
        if (--values.allow_threshold <= 0)
            values.locked = true;

        if (std::find(values.lock_check.begin(), values.lock_check.end(), &*loc.curr_task) != values.lock_check.end()) {
            if (++values.allow_threshold != 0)
                values.locked = false;
            values.no_race.unlock();
            throw std::logic_error("Dead lock. task try lock already locked task limiter");
        } else
            values.lock_check.push_back(&*loc.curr_task);
        values.no_race.unlock();
        return true;
    }

    void task_limiter::unlock() {
        fast_task::lock_guard lg0(values.no_race);
        auto item = std::find(values.lock_check.begin(), values.lock_check.end(), &*loc.curr_task);
        if (item == values.lock_check.end())
            throw std::logic_error("Invalid unlock. task try unlock already unlocked task limiter");
        else
            values.lock_check.erase(item);
        unchecked_unlock();
    }

    void task_limiter::unchecked_unlock() {
        if (values.allow_threshold >= values.max_threshold)
            return;
        values.allow_threshold++;
        values.native_notify.notify_one();
        while (values.resume_task.size()) {
            auto& it = values.resume_task.back();
            fast_task::lock_guard lg2(get_data(it.task).no_race);
            if (!get_data(it.task).time_end_flag) {
                if (get_data(it.task).awake_check != it.awake_check)
                    continue;
                get_data(it.task).awaked = true;
                auto task = values.resume_task.front().task;
                values.resume_task.pop_front();
                transfer_task(task);
                return;
            } else
                values.resume_task.pop_front();
        }
    }

    bool task_limiter::is_locked() {
        return values.locked;
    }
}