// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <task.hpp>
#include <tasks/_internal.hpp>

namespace fast_task {
    void task_mutex::push_back(private_values& values, resume_task* node) {
        node->next = nullptr;
        node->prev = values.end;
        if (values.end) {
            values.end->next = node;
        } else
            values.begin = node;

        values.end = node;
    }

    void task_mutex::erase(private_values& values, resume_task* node) {
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

    task_mutex::task_mutex() {
        FT_DEBUG_ONLY(register_object(this));
    }

    task_mutex::~task_mutex() {
        FT_DEBUG_ONLY(unregister_object(this));
        if (values.current_task) {
            assert(false && "Tried to destroy locked mutex");
            std::terminate();
        }
    }

    void task_mutex::lock() {
        resume_task node;
        if (get_loc().is_task_thread) {
            get_data(get_loc().curr_task).set_awaked(false);
            get_data(get_loc().curr_task).set_time_end(false);
            node.task = get_loc().curr_task;

            fast_task::lock_guard lg(values.no_race);
            if (values.current_task == get_loc().curr_task.get_id())
                throw std::logic_error("Tried lock mutex twice");
            while (values.current_task) {
                node.awake_check = get_data(get_loc().curr_task).awake_check;
                push_back(values, &node);
                swapCtxRelock(values.no_race);
            }
            values.current_task = get_loc().curr_task.get_id();
        } else {
            fast_task::condition_variable_any cd;
            bool has_res = false;
            node.task = nullptr;
            node.awake_check = 0;
            node.native_cv = &cd;
            node.native_check = &has_res;
            fast_task::unique_lock ul(values.no_race);

            if (values.current_task == ((size_t)_thread_id() | native_thread_flag))
                throw std::logic_error("Tried lock mutex twice");
            while (values.current_task) {
                bool has_res = false;
                push_back(values, &node);
                while (!has_res) //-V654
                    cd.wait(ul);
            }
            values.current_task = (size_t)_thread_id() | native_thread_flag;
        }
    }

    bool task_mutex::try_lock() {
        if (!values.no_race.try_lock())
            return false;
        fast_task::unique_lock ul(values.no_race, fast_task::adopt_lock);

        if (values.current_task)
            return false;
        else if (get_loc().is_task_thread || get_loc().context_in_swap) {
            if (values.current_task == get_loc().curr_task.get_id())
                return false;
            values.current_task = get_loc().curr_task.get_id();
        } else {
            if (values.current_task == ((size_t)_thread_id() | native_thread_flag))
                return false;
            values.current_task = (size_t)_thread_id() | native_thread_flag;
        }
        return true;
    }

    bool task_mutex::try_lock_until(std::chrono::high_resolution_clock::time_point time_point) {
        resume_task node;
        fast_task::unique_lock ul(values.no_race);

        if (get_loc().is_task_thread && !get_loc().context_in_swap) {
            if (values.current_task == get_loc().curr_task.get_id())
                return false;
            node.task = get_loc().curr_task;
            while (values.current_task) {
                fast_task::lock_guard guard(glob.task_timer_safety);
                makeTimeWait_unsafe(time_point);
                node.awake_check = get_data(get_loc().curr_task).awake_check;
                push_back(values, &node);
                swapCtxRelock(glob.task_timer_safety, values.no_race);
                auto awaked = get_data(get_loc().curr_task).get_awaked();
                resetTimeWait();
                if (!awaked) {
                    erase(values, &node);
                    return false;
                }
            }
            values.current_task = get_loc().curr_task.get_id();
            return true;
        } else {
            if (values.current_task == ((size_t)_thread_id() | native_thread_flag))
                return false;
            fast_task::condition_variable_any cd;
            bool has_res = false;
            node.task = nullptr;
            node.awake_check = 0;
            node.native_cv = &cd;
            node.native_check = &has_res;
            while (values.current_task) {
                has_res = false;
                while (!has_res) { //-V654
                    if (cd.wait_until(ul, time_point) == cv_status::timeout) {
                        node.native_cv = nullptr;
                        return false;
                    }
                }
            }
            if (!get_loc().context_in_swap)
                values.current_task = (size_t)_thread_id() | native_thread_flag;
            else
                values.current_task = get_loc().curr_task.get_id();
            return true;
        }
    }

    void task_mutex::unlock() {
        bool to_yield = false;
        fast_task::unique_lock no_race_guard(values.no_race);
        if (get_loc().is_task_thread) {
            if (values.current_task != get_loc().curr_task.get_id())
                throw std::logic_error("Tried unlock non owned mutex");
        } else if (values.current_task != ((size_t)_thread_id() | native_thread_flag))
            throw std::logic_error("Tried unlock non owned mutex");

        resume_task* head = values.begin;
        resume_task* end = values.end;
        values.begin = nullptr;
        values.end = nullptr;
        values.current_task = 0;
        if (!head)
            return;
        {
            fast_task::shared_lock guard(glob.task_thread_safety);
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
                            bool on_scheduler = get_data(curr->task).get_is_on_scheduler();
                            if (on_scheduler) {
                                values.current_task = curr->task.get_id();
                                if (next) {
                                    next->prev = nullptr;
                                    values.begin = next;
                                    values.end = next->next ? end : next;
                                }
                            }
                            get_data(curr->task).set_awaked(true);
                            task rescheduled = curr->task;
                            {
                                fast_task::relock_guard guard_relock(guard);
                                transfer_task(std::move(rescheduled));
                            }
                            if (on_scheduler)
                                break;
                        }
                    }
                }
                curr = next;
            }
            glob.tasks_notifier.notify_one();
            if (task::max_running_tasks && get_loc().is_task_thread)
                if (can_be_scheduled_task_to_hot() && get_loc().curr_task && !get_data(get_loc().curr_task).is_ended())
                    to_yield = true;
        }
        no_race_guard.unlock();
        if (to_yield)
            this_task::yield();
    }

    bool task_mutex::is_locked() {
        if (try_lock()) {
            unlock();
            return false;
        }
        return true;
    }

    bool task_mutex::is_own() {
        fast_task::lock_guard lg0(values.no_race);
        if (get_loc().is_task_thread) {
            if (values.current_task != get_loc().curr_task.get_id())
                return false;
        } else if (values.current_task != ((size_t)_thread_id() | native_thread_flag))
            return false;
        return true;
    }

    void task_mutex::lifecycle_lock(task&& lock_task) {
        {
            fast_task::lock_guard guard(get_data(lock_task));
            if (get_data(lock_task).is_running() || get_data(lock_task).is_ended())
                throw std::runtime_error("Task is running or completed and cannot be registered");
            if (get_data(lock_task).is_started() && (!get_data(lock_task).is_suspended() && get_data(lock_task).get_is_on_scheduler()))
                throw std::runtime_error("Task is already in the scheduler queue");
            if (!get_data(lock_task).vtable || !get_data(lock_task).vtable->on_start)
                throw std::logic_error("task_mutex::lifecycle_lock requires the on_start callback to be set");
        }
        task::run([lock_task, this]() {
            fast_task::lock_guard guard(*this);
            task::await_task(lock_task, true);
        });
    }

    bool task_mutex::enter_wait(const task& task, enter_state& state) {
        auto node = state.template use<resume_task>();
        node->task = task;
        node->awake_check = get_data(task).awake_check;
        fast_task::lock_guard l(values.no_race);
        if (values.current_task == 0) {
            values.current_task = task.get_id();
            return true;
        } else {
            push_back(values, node);
            return false;
        }
    }

    bool task_mutex::enter_wait_until(const task& task, enter_state& state, std::chrono::high_resolution_clock::time_point time_point) {
        auto node = state.template use<resume_task>();
        node->task = task;
        node->awake_check = get_data(task).awake_check;
        fast_task::lock_guard l(values.no_race);
        if (values.current_task == 0) {
            values.current_task = task.get_id();
            return true;
        } else {
            push_back(values, node);
            fast_task::makeTimeWait_extern(task, time_point);
            return false;
        }
    }
}
