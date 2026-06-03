// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <task.hpp>
#include <tasks/_internal.hpp>

namespace fast_task {
    void task_semaphore::push_back(private_values& values, resume_task* node) {
        node->next = nullptr;
        node->prev = values.end;
        if (values.end) {
            values.end->next = node;
        } else
            values.begin = node;

        values.end = node;
    }

    void task_semaphore::erase(private_values& values, resume_task* node) {
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

    task_semaphore::task_semaphore() {
        FT_DEBUG_ONLY(register_object(this));
    }

    task_semaphore::~task_semaphore() {
        FT_DEBUG_ONLY(unregister_object(this));
        if (values.allow_threshold != values.max_threshold) {
            assert(false && "Semaphore destroyed while locked");
            std::terminate();
        }
    }

    void task_semaphore::set_max_threshold(size_t val) {
        fast_task::lock_guard guard(values.no_race);
        if (values.allow_threshold != values.max_threshold) {
            values.allow_threshold = values.max_threshold;
            values.native_notify.notify_all();
            while (values.begin) {
                auto& it = *values.begin;
                fast_task::lock_guard lg2(get_data(it.task));
                if (!get_data(it.task).get_time_end()) {
                    if (get_data(it.task).awake_check != it.awake_check) {
                        erase(values, values.begin);
                        continue;
                    }
                    get_data(it.task).set_awaked(true);
                    auto task = it.task;
                    erase(values, values.begin);
                    transfer_task(std::move(task));
                } else
                    erase(values, values.begin);
            }
        }
        values.max_threshold = val;
        values.allow_threshold = values.max_threshold;
    }

    void task_semaphore::lock() {
        resume_task node;
        if (get_loc().is_task_thread) {
            node.task = get_loc().curr_task;
            get_data(get_loc().curr_task).set_awaked(false);
            get_data(get_loc().curr_task).set_time_end(false);
        }
        fast_task::unique_lock keeper(values.no_race);
        while (!values.allow_threshold) {
            if (get_loc().is_task_thread) {
                node.awake_check = get_data(node.task).awake_check;
                push_back(values, &node);
                swapCtxRelock(values.no_race);
            } else
                values.native_notify.wait(keeper);
        }
        --values.allow_threshold;
    }

    bool task_semaphore::try_lock() {
        if (!values.no_race.try_lock())
            return false;
        if (!values.allow_threshold) {
            values.no_race.unlock();
            return false;
        } else
            --values.allow_threshold;
        values.no_race.unlock();
        return true;
    }

    bool task_semaphore::try_lock_until(std::chrono::high_resolution_clock::time_point time_point) {
        resume_task node;
        if (get_loc().is_task_thread) {
            node.task = get_loc().curr_task;
        }
        fast_task::unique_lock keeper(values.no_race);

        while (!values.allow_threshold) {
            if (get_loc().is_task_thread) {
                fast_task::lock_guard guard(glob.task_timer_safety);
                node.awake_check = get_data(node.task).awake_check;
                push_back(values, &node);
                makeTimeWait_unsafe(time_point);
                swapCtxRelock(glob.task_timer_safety, values.no_race);
                auto awaked = get_data(get_loc().curr_task).get_awaked();
                resetTimeWait();
                if (!awaked) {
                    erase(values, &node);
                    return false;
                }
            } else if (values.native_notify.wait_until(keeper, time_point) == fast_task::cv_status::timeout)
                return false;
        }
        --values.allow_threshold;
        values.no_race.unlock();
        return true;
    }

    void task_semaphore::release() {
        fast_task::lock_guard lg0(values.no_race);
        if (values.allow_threshold == values.max_threshold)
            return;
        values.allow_threshold++;
        values.native_notify.notify_one();
        while (values.begin) {
            auto& it = *values.begin;
            fast_task::lock_guard lg2(get_data(it.task));
            if (!get_data(it.task).get_time_end()) {
                if (get_data(it.task).awake_check != it.awake_check) {
                    erase(values, values.begin);
                    continue;
                }
                get_data(it.task).set_awaked(true);
                auto task = values.begin->task;
                erase(values, values.begin);
                if (get_data(task).get_is_on_scheduler())
                    --values.allow_threshold;
                transfer_task(std::move(task));
                return;
            } else
                erase(values, values.begin);
        }
    }

    void task_semaphore::release_all() {
        fast_task::lock_guard lg0(values.no_race);
        if (values.allow_threshold == values.max_threshold)
            return;
        resume_task* head = values.begin;
        values.begin = nullptr;
        values.end = nullptr;
        values.allow_threshold = values.max_threshold;
        values.native_notify.notify_all();

        if (!head)
            return;

        fast_task::shared_lock guard(glob.task_thread_safety);
        resume_task* curr = head;
        while (curr) {
            resume_task* next = curr->next;
            fast_task::lock_guard guard_loc(get_data(curr->task));
            if (get_data(curr->task).awake_check == curr->awake_check) {
                if (!get_data(curr->task).get_time_end()) {
                    get_data(curr->task).set_awaked(true);
                    fast_task::relock_guard guard_relock(guard);
                    transfer_task(std::move(curr->task));
                }
            }
            curr = next;
        }
    }

    bool task_semaphore::is_locked() {
        if (try_lock()) {
            release();
            return false;
        }
        return true;
    }

    bool task_semaphore::enter_wait(const task& task, enter_state& state) {
        auto node = state.template use<resume_task>();
        node->task = task;
        node->awake_check = get_data(task).awake_check;
        fast_task::lock_guard guard(values.no_race);
        if (!values.allow_threshold) {
            push_back(values, node);
            return true;
        } else {
            --values.allow_threshold;
            return false;
        }
    }

    bool task_semaphore::enter_wait_until(const task& task, enter_state& state, std::chrono::high_resolution_clock::time_point time_point) {
        auto node = state.template use<resume_task>();
        node->task = task;
        node->awake_check = get_data(task).awake_check;
        fast_task::lock_guard guard(values.no_race);
        if (!values.allow_threshold) {
            push_back(values, node);
            fast_task::makeTimeWait_extern(task, time_point);
            return true;
        } else {
            --values.allow_threshold;
            return false;
        }
    }
}
