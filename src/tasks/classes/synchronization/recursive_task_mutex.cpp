// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <task.hpp>
#include <tasks/_internal.hpp>

namespace fast_task {
    task_recursive_mutex::task_recursive_mutex() {
        FT_DEBUG_ONLY(register_object(this));
    }

    task_recursive_mutex::~task_recursive_mutex() {
        FT_DEBUG_ONLY(unregister_object(this));
        if (recursive_count != 0) {
            assert(false && "Mutex destroyed while locked");
            std::terminate();
        }
    }

    void task_recursive_mutex::lock() {
        if (get_loc().is_task_thread) {
            if (mutex.values.current_task == get_loc().curr_task.get_id()) {
                recursive_count++;
                if (recursive_count == 0) {
                    recursive_count--;
                    throw std::logic_error("Recursive mutex overflow");
                }
            } else {
                mutex.lock();
                recursive_count = 1;
            }
        } else {
            if (mutex.values.current_task == ((size_t)_thread_id() | native_thread_flag)) {
                recursive_count++;
                if (recursive_count == 0) {
                    recursive_count--;
                    throw std::logic_error("Recursive mutex overflow");
                }
            } else {
                mutex.lock();
                recursive_count = 1;
            }
        }
    }

    bool task_recursive_mutex::try_lock() {
        if (get_loc().is_task_thread) {
            if (mutex.values.current_task == get_loc().curr_task.get_id()) {
                recursive_count++;
                if (recursive_count == 0) {
                    recursive_count--;
                    return false;
                }
                return true;
            } else if (mutex.try_lock()) {
                recursive_count = 1;
                return true;
            } else
                return false;
        } else {
            if (mutex.values.current_task == ((size_t)_thread_id() | native_thread_flag)) {
                recursive_count++;
                if (recursive_count == 0) {
                    recursive_count--;
                    return false;
                }
                return true;
            } else if (mutex.try_lock()) {
                recursive_count = 1;
                return true;
            } else
                return false;
        }
    }

    bool task_recursive_mutex::try_lock_until(std::chrono::high_resolution_clock::time_point time_point) {
        if (get_loc().is_task_thread) {
            if (mutex.values.current_task == get_loc().curr_task.get_id()) {
                recursive_count++;
                if (recursive_count == 0) {
                    recursive_count--;
                    return false;
                }
                return true;
            } else if (mutex.try_lock_until(time_point)) {
                recursive_count = 1;
                return true;
            } else
                return false;
        } else {
            if (mutex.values.current_task == ((size_t)_thread_id() | native_thread_flag)) {
                recursive_count++;
                if (recursive_count == 0) {
                    recursive_count--;
                    return false;
                }
                return true;
            } else if (mutex.try_lock_until(time_point)) {
                recursive_count = 1;
                return true;
            } else
                return false;
        }
    }

    void task_recursive_mutex::unlock() {
        if (recursive_count) {
            recursive_count--;
            if (!recursive_count) {
                task_mutex::resume_task* head = nullptr;
                {
                    fast_task::unique_lock no_race_guard(mutex.values.no_race);
                    if (get_loc().is_task_thread) {
                        if (mutex.values.current_task != get_loc().curr_task.get_id())
                            throw std::logic_error("Tried unlock non owned mutex");
                    } else if (mutex.values.current_task != ((size_t)_thread_id() | native_thread_flag))
                        throw std::logic_error("Tried unlock non owned mutex");
                    head = mutex.values.begin;
                    mutex.values.begin = nullptr;
                    mutex.values.end = nullptr;
                }
                if (!head)
                    return;
                bool to_yield = false;
                {
                    fast_task::shared_lock guard(glob.task_thread_safety);
                    task_mutex::resume_task* curr = head;
                    while (curr) {
                        task_mutex::resume_task* next = curr->next;
                        if (curr->task == nullptr) {
                            if (curr->native_cv != nullptr) {
                                *curr->native_check = true;
                                curr->native_cv->notify_all();
                            }
                        } else {
                            fast_task::lock_guard guard_loc(get_data(curr->task));
                            if (get_data(curr->task).awake_check == curr->awake_check) {
                                if (!get_data(curr->task).get_time_end()) {
                                    if (get_data(curr->task).get_is_on_scheduler()) {
                                        mutex.values.current_task = curr->task.get_id();
                                        ++recursive_count;
                                    }
                                    get_data(curr->task).set_awaked(true);
                                    fast_task::relock_guard guard_relock(guard);
                                    transfer_task(std::move(curr->task));
                                }
                            }
                        }
                        curr = next;
                    }
                    glob.tasks_notifier.notify_one();
                    if (task::max_running_tasks && get_loc().is_task_thread) {
                        if (can_be_scheduled_task_to_hot() && get_loc().curr_task && !get_data(get_loc().curr_task).is_ended())
                            to_yield = true;
                    }
                }
                if (to_yield)
                    this_task::yield();
            }
        } else
            throw std::logic_error("Mutex not locked");
    }

    bool task_recursive_mutex::is_locked() {
        if (recursive_count)
            return true;
        else
            return false;
    }

    void task_recursive_mutex::lifecycle_lock(task&& task) {
        mutex.lifecycle_lock(std::move(task));
    }

    bool task_recursive_mutex::is_own() {
        if (get_loc().is_task_thread) {
            if (mutex.values.current_task == get_loc().curr_task.get_id())
                return true;
        } else if (mutex.values.current_task == ((size_t)_thread_id() | native_thread_flag))
            return true;
        return false;
    }

    bool task_recursive_mutex::enter_wait(const task& task, enter_state& state) {
        auto* node = state.template use<task_mutex::resume_task>();
        node->task = task;
        node->awake_check = get_data(task).awake_check;
        fast_task::lock_guard l(mutex.values.no_race);
        if (mutex.values.current_task == task.get_id()) {
            recursive_count++;
            if (recursive_count == 0) {
                recursive_count--;
                throw std::logic_error("Recursive mutex overflow");
            }
            return true;
        } else if (mutex.values.current_task == 0) {
            mutex.values.current_task = task.get_id();
            recursive_count = 1;
            return true;
        } else {
            mutex.push_back(mutex.values, node);
            return false;
        }
    }

    bool task_recursive_mutex::enter_wait_until(const task& task, enter_state& state, std::chrono::high_resolution_clock::time_point time_point) {
        auto* node = state.template use<task_mutex::resume_task>();
        node->task = task;
        node->awake_check = get_data(task).awake_check;
        fast_task::lock_guard l(mutex.values.no_race);
        if (mutex.values.current_task == task.get_id()) {
            recursive_count++;
            if (recursive_count == 0) {
                recursive_count--;
                throw std::logic_error("Recursive mutex overflow");
            }
            return true;
        } else if (mutex.values.current_task == 0) {
            mutex.values.current_task = task.get_id();
            recursive_count = 1;
            return true;
        } else {
            mutex.push_back(mutex.values, node);
            fast_task::makeTimeWait_extern(task, time_point);
            return false;
        }
    }
}
