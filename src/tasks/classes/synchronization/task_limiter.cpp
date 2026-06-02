// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <task.hpp>
#include <tasks/_internal.hpp>

namespace fast_task {
    void task_limiter::push_back(private_values& values, resume_task* node) {
        node->next = nullptr;
        node->prev = values.end;
        if (values.end) {
            values.end->next = node;
        } else
            values.begin = node;

        values.end = node;
    }

    void task_limiter::erase(private_values& values, resume_task* node) {
        if (node->prev) {
            node->prev->next = node->next;
        } else
            values.begin = node->next;

        if (node->next) {
            node->next->prev = node->prev;
        } else
            values.end = node->prev;

        node->next = nullptr;
        node->prev = nullptr;
    }

    task_limiter::task_limiter() {
        FT_DEBUG_ONLY(register_object(this));
    }

    task_limiter::~task_limiter() {
        FT_DEBUG_ONLY(unregister_object(this));
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
            } else {
                values.allow_threshold += val - values.max_threshold;
                values.max_threshold = val;
            }
        }
    }

    void task_limiter::lock() {
        resume_task node;
        if (get_loc().is_task_thread)
            node.task = get_loc().curr_task;
        fast_task::unique_lock guard(values.no_race);
        while (values.locked) {
            if (get_loc().is_task_thread) {
                get_data(get_loc().curr_task).set_awaked(false);
                get_data(get_loc().curr_task).set_time_end(false);
                node.awake_check = get_data(get_loc().curr_task).awake_check;
                push_back(values, &node);
                swapCtxRelock(*guard.mutex());
            } else
                values.native_notify.wait(guard);
        }
        if (--values.allow_threshold == 0)
            values.locked = true;
        size_t lock_id = this_task::get_id();
        if (std::find(values.lock_check.begin(), values.lock_check.end(), lock_id) != values.lock_check.end()) {
            if (++values.allow_threshold != 0)
                values.locked = false;
            values.no_race.unlock();
            throw std::logic_error("Dead lock. task try lock already locked task limiter");
        } else
            values.lock_check.push_back(lock_id);
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

        size_t lock_id = this_task::get_id();
        if (std::find(values.lock_check.begin(), values.lock_check.end(), lock_id) != values.lock_check.end()) {
            if (++values.allow_threshold != 0)
                values.locked = false;
            values.no_race.unlock();
            throw std::logic_error("Dead lock. task try lock already locked task limiter");
        } else
            values.lock_check.push_back(lock_id);
        values.no_race.unlock();
        return true;
    }

    bool task_limiter::try_lock_until(std::chrono::high_resolution_clock::time_point time_point) {
        resume_task node;
        if (get_loc().is_task_thread)
            node.task = get_loc().curr_task;
        fast_task::unique_lock guard(values.no_race);
        while (values.locked) {
            if (get_loc().is_task_thread) {
                get_data(get_loc().curr_task).set_awaked(false);
                get_data(get_loc().curr_task).set_time_end(false);
                makeTimeWait(time_point);
                node.awake_check = get_data(get_loc().curr_task).awake_check;
                push_back(values, &node);
                swapCtxRelock(values.no_race);
                auto awaked = get_data(get_loc().curr_task).get_awaked();
                resetTimeWait();
                if (!awaked)
                    return false;
            } else if (values.native_notify.wait_until(guard, time_point) == fast_task::cv_status::timeout)
                return false;
        }
        if (--values.allow_threshold <= 0)
            values.locked = true;
        size_t lock_id = this_task::get_id();

        if (std::find(values.lock_check.begin(), values.lock_check.end(), lock_id) != values.lock_check.end()) {
            if (++values.allow_threshold != 0)
                values.locked = false;
            values.no_race.unlock();
            throw std::logic_error("Dead lock. task try lock already locked task limiter");
        } else
            values.lock_check.push_back(lock_id);
        values.no_race.unlock();
        return true;
    }

    void task_limiter::unlock() {
        size_t lock_id = this_task::get_id();
        fast_task::lock_guard lg0(values.no_race);
        auto item = std::find(values.lock_check.begin(), values.lock_check.end(), lock_id);
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
        values.locked = false;
        values.native_notify.notify_one();
        while (values.begin) {
            auto& it = *values.begin;
            fast_task::lock_guard lg2(get_data(it.task));
            if (!get_data(it.task).get_time_end()) {
                if (get_data(it.task).awake_check != it.awake_check) {
                    values.begin = it.next;
                    continue;
                }
                get_data(it.task).set_awaked(true);
                auto task = values.begin->task;
                erase(values, values.begin);
                if (get_data(task).get_is_on_scheduler())
                    if (--values.allow_threshold <= 0)
                        values.locked = true;
                transfer_task(std::move(task));
                return;
            } else
                erase(values, values.begin);
        }
    }

    bool task_limiter::is_locked() {
        return values.locked;
    }

    bool task_limiter::enter_wait(const task& task, enter_state& state) {
        auto node = state.template use<resume_task>();
        node->task = task;
        node->awake_check = get_data(task).awake_check;
        fast_task::lock_guard guard(values.no_race);

        if (!values.locked) {
            if (--values.allow_threshold == 0)
                values.locked = true;

            if (std::find(values.lock_check.begin(), values.lock_check.end(), task.get_id()) != values.lock_check.end()) {
                if (++values.allow_threshold != 0)
                    values.locked = false;

                throw std::logic_error("Dead lock. task try lock already locked task limiter");
            } else
                values.lock_check.push_back(task.get_id());
            return true;
        } else {
            push_back(values, node);
            return false;
        }
    }

    bool task_limiter::enter_wait_until(const task& task, enter_state& state, std::chrono::high_resolution_clock::time_point time_point) {
        auto node = state.template use<resume_task>();
        node->task = task;
        node->awake_check = get_data(task).awake_check;
        fast_task::lock_guard guard(values.no_race);

        if (!values.locked) {
            if (--values.allow_threshold == 0)
                values.locked = true;

            if (std::find(values.lock_check.begin(), values.lock_check.end(), task.get_id()) != values.lock_check.end()) {
                if (++values.allow_threshold != 0)
                    values.locked = false;

                throw std::logic_error("Dead lock. task try lock already locked task limiter");
            } else
                values.lock_check.push_back(task.get_id());
            return true;
        } else {
            push_back(values, node);
            fast_task::makeTimeWait_extern(task, time_point);
            return false;
        }
    }
}
