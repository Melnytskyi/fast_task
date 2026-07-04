// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <task.hpp>
#include <tasks/_internal.hpp>

namespace fast_task {
    void task_condition_variable::push_back(private_values& values, resume_task* node) {
        node->next = nullptr;
        node->prev = values.end;
        if (values.end) {
            values.end->next = node;
        } else
            values.begin = node;

        values.end = node;
    }

    void task_condition_variable::erase(private_values& values, resume_task* node) {
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

    task_condition_variable::task_condition_variable() {
        FT_DEBUG_ONLY(register_object(this));
    }

    task_condition_variable::~task_condition_variable() {
        FT_DEBUG_ONLY(unregister_object(this));
        if (values.begin) {
            assert(false && "Condition_variable destroyed while waited");
            std::terminate();
        }
    }

    void task_condition_variable::wait(fast_task::unique_lock<mutex_unify>& mut) {
        resume_task node;
        if (get_loc().is_task_thread) {
            node.task = get_loc().curr_task;
            node.awake_check = get_data(get_loc().curr_task).awake_check;

            fast_task::unique_lock guard(values.no_race);
            relock_guard relock(mut);
            push_back(values, &node);
            swapCtxRelock(values.no_race);
            guard.unlock();
        } else {
            fast_task::condition_variable_any cd;
            bool has_res = false;
            node.task = nullptr;
            node.awake_check = 0;
            node.native_cv = &cd;
            node.native_check = &has_res;

            fast_task::unique_lock no_race_guard(values.no_race);
            push_back(values, &node);

            relock_guard relock(mut);
            while (!has_res) //-V654
                cd.wait(no_race_guard);
            no_race_guard.unlock();
        }
    }

    bool task_condition_variable::wait_until(fast_task::unique_lock<mutex_unify>& mut, std::chrono::high_resolution_clock::time_point time_point) {
        resume_task node;
        if (get_loc().is_task_thread) {
            node.task = get_loc().curr_task;
            node.awake_check = get_data(get_loc().curr_task).awake_check;

            get_loc().pending_timer = time_point;
            fast_task::unique_lock guard(values.no_race);
            relock_guard relock(mut);
            push_back(values, &node);
            swapCtxRelock(values.no_race);
            auto timed = get_data(get_loc().curr_task).get_time_end();
            guard.unlock();

            resetTimeWait();
            if (timed) {
                fast_task::lock_guard _guard(values.no_race);
                erase(values, &node);
                return false;
            }
        } else {
            fast_task::condition_variable_any cd;
            bool has_res = false;
            node.task = nullptr;
            node.awake_check = 0;
            node.native_cv = &cd;
            node.native_check = &has_res;

            fast_task::unique_lock no_race_guard(values.no_race);
            push_back(values, &node);

            relock_guard relock(mut);
            while (!has_res) { //-V654
                if (cd.wait_until(no_race_guard, time_point) == cv_status::timeout) {
                    erase(values, &node);
                    no_race_guard.unlock();
                    return false;
                }
            }
            no_race_guard.unlock();
        }
        return true;
    }

    void task_condition_variable::wait(std::unique_lock<mutex_unify>& mut) {
        resume_task node;
        if (get_loc().is_task_thread) {
            node.task = get_loc().curr_task;
            node.awake_check = get_data(get_loc().curr_task).awake_check;
            fast_task::unique_lock guard(values.no_race);
            relock_guard relock(mut);
            push_back(values, &node);
            swapCtxRelock(values.no_race);
        } else {
            fast_task::condition_variable_any cd;
            bool has_res = false;
            node.task = nullptr;
            node.awake_check = 0;
            node.native_cv = &cd;
            node.native_check = &has_res;

            fast_task::unique_lock no_race_guard(values.no_race);
            push_back(values, &node);

            relock_guard relock(mut);
            while (!has_res) //-V654
                cd.wait(no_race_guard);
            no_race_guard.unlock();
        }
    }

    bool task_condition_variable::wait_until(std::unique_lock<mutex_unify>& mut, std::chrono::high_resolution_clock::time_point time_point) {
        resume_task node;
        if (get_loc().is_task_thread) {
            node.task = get_loc().curr_task;
            node.awake_check = get_data(get_loc().curr_task).awake_check;

            get_loc().pending_timer = time_point;
            fast_task::unique_lock guard(values.no_race);
            relock_guard relock(mut);
            push_back(values, &node);
            swapCtxRelock(values.no_race);
            auto timed = get_data(get_loc().curr_task).get_time_end();
            guard.unlock();

            resetTimeWait();
            if (timed) {
                fast_task::lock_guard _guard(values.no_race);
                erase(values, &node);
                return false;
            }
        } else {
            fast_task::condition_variable_any cd;
            bool has_res = false;
            node.task = nullptr;
            node.awake_check = 0;
            node.native_cv = &cd;
            node.native_check = &has_res;

            fast_task::unique_lock no_race_guard(values.no_race);
            push_back(values, &node);

            relock_guard relock(mut);
            while (!has_res) { //-V654
                if (cd.wait_until(no_race_guard, time_point) == cv_status::timeout) {
                    erase(values, &node);
                    no_race_guard.unlock();
                    return false;
                }
            }
            no_race_guard.unlock();
        }
        return true;
    }

    void task_condition_variable::notify_all() {
        fast_task::unique_lock no_race_guard(values.no_race);
        resume_task* head = values.begin;
        values.begin = nullptr;
        values.end = nullptr;
        if (!head)
            return;
        bool to_yield = false;

        resume_task* curr = head;
        while (curr) {
            resume_task* next = curr->next;
            if (curr->task == nullptr) {
                if (curr->native_cv != nullptr) {
                    *curr->native_check = true;
                    curr->native_cv->notify_all();
                }
            } else {
                fast_task::lock_guard guard_loc(get_data(curr->task));
                if (get_data(curr->task).awake_check == curr->awake_check) {
                    if (!get_data(curr->task).get_time_end()) {
                        get_data(curr->task).set_awaked(true);
                        transfer_task(std::move(curr->task));
                    }
                }
            }
            if (curr->heap_allocated)
                delete curr;
            curr = next;
        }
        if (task::max_running_tasks && get_loc().is_task_thread)
            if (can_be_scheduled_task_to_hot() && get_loc().curr_task && !get_data(get_loc().curr_task).is_ended())
                to_yield = true;

        if (to_yield)
            this_task::yield();
    }

    void task_condition_variable::notify_one() {
        task tsk;
        resume_task* popped_node = nullptr;
        {
            fast_task::lock_guard guard(values.no_race);
            while (values.end) {
                resume_task* cur_node = values.end;
                if (cur_node->task == nullptr) {
                    if (cur_node->native_cv != nullptr) {
                        *cur_node->native_check = true;
                        cur_node->native_cv->notify_all();

                        erase(values, cur_node);
                        if (cur_node->heap_allocated)
                            delete cur_node;

                        return;
                    }
                    erase(values, cur_node);
                    if (cur_node->heap_allocated)
                        delete cur_node;
                    continue;
                }

                tsk = cur_node->task;
                erase(values, cur_node);
                popped_node = cur_node;
                break;
            }
            if (!tsk)
                return;
        }
        bool to_yield = false;
        fast_task::lock_guard guard_loc(get_data(tsk));
        {
            get_data(tsk).set_awaked(true);
            fast_task::shared_lock guard(glob.task_thread_safety);
            if (task::max_running_tasks && get_loc().is_task_thread)
                if (can_be_scheduled_task_to_hot() && get_loc().curr_task && !get_data(get_loc().curr_task).is_ended())
                    to_yield = true;
            guard.unlock();
            transfer_task(std::move(tsk), reinterpret_cast<enter_state*>(popped_node));
            if (popped_node && popped_node->heap_allocated)
                delete popped_node;
        }
        if (to_yield)
            this_task::yield();
    }

    bool task_condition_variable::has_waiters() {
        fast_task::lock_guard guard(values.no_race);
        return values.begin != nullptr;
    }

    void task_condition_variable::callback(fast_task::unique_lock<mutex_unify>& mut, const task& task) {
        {
            fast_task::lock_guard guard(get_data(task));
            if (get_data(task).is_running() || get_data(task).is_ended())
                throw std::runtime_error("Task is running or completed and cannot be registered");
            if (get_data(task).is_scheduled() && (!get_data(task).is_suspended() && get_data(task).get_is_on_scheduler()))
                throw std::runtime_error("Task is already in the scheduler queue");
            if (!get_data(task).vtable || !get_data(task).vtable->on_start)
                throw std::logic_error("task_condition_variable::callback requires the on_start callback to be set");
        }
        auto* node = new resume_task();
        node->task = task;
        node->awake_check = get_data(task).awake_check;
        node->heap_allocated = true;

        if (*mut.mutex() == values.no_race) {
            push_back(values, node);
        } else {
            fast_task::lock_guard guard(values.no_race);
            push_back(values, node);
        }
        if (get_data(task).is_created())
            ++glob.executing_tasks;

        get_data(task).set_status(task_object::status_e::scheduled);
    }

    void task_condition_variable::callback(std::unique_lock<mutex_unify>& mut, const task& task) {
        {
            fast_task::lock_guard guard(get_data(task));
            if (get_data(task).is_running() || get_data(task).is_ended())
                throw std::runtime_error("Task is running or completed and cannot be registered");
            if (get_data(task).is_scheduled() && (!get_data(task).is_suspended() && get_data(task).get_is_on_scheduler()))
                throw std::runtime_error("Task is already in the scheduler queue");
            if (!get_data(task).vtable || !get_data(task).vtable->on_start)
                throw std::logic_error("task_condition_variable::callback requires the on_start callback to be set");
        }
        auto* node = new resume_task();
        node->task = task;
        node->awake_check = get_data(task).awake_check;
        node->heap_allocated = true;

        if (*mut.mutex() == values.no_race) {
            push_back(values, node);
        } else {
            fast_task::lock_guard guard(values.no_race);
            push_back(values, node);
        }
        if (get_data(task).is_created())
            ++glob.executing_tasks;

        get_data(task).set_status(task_object::status_e::scheduled);
    }

    bool task_condition_variable::enter_wait(mutex_unify& mut, const task& task, enter_state& st) {
        fast_task::lock_guard l(values.no_race);
        get_data(task).set_relock(mut);
        auto node = st.template use<resume_task>();
        node->task = task;
        node->awake_check = get_data(task).awake_check;
        push_back(values, node);
        return false;
    }

    bool task_condition_variable::enter_wait_until(mutex_unify& mut, const task& task, enter_state& st, std::chrono::high_resolution_clock::time_point time_point) {
        if (std::chrono::high_resolution_clock::now() >= time_point)
            return true;
        fast_task::lock_guard l(values.no_race);
        get_data(task).set_relock(mut);
        auto node = st.template use<resume_task>();
        node->task = task;
        node->awake_check = get_data(task).awake_check;
        push_back(values, node);
        fast_task::makeTimeWait_extern(task, time_point);
        return false;
    }
}
