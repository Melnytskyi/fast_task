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
        if (loc.is_task_thread) {
            if (mutex.values.current_task == &*loc.curr_task) {
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
            if (mutex.values.current_task == reinterpret_cast<task*>((size_t)_thread_id() | native_thread_flag)) {
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
        if (loc.is_task_thread) {
            if (mutex.values.current_task == &*loc.curr_task) {
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
            if (mutex.values.current_task == reinterpret_cast<task*>((size_t)_thread_id() | native_thread_flag)) {
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
        if (loc.is_task_thread) {
            if (mutex.values.current_task == &*loc.curr_task) {
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
            if (mutex.values.current_task == reinterpret_cast<task*>((size_t)_thread_id() | native_thread_flag)) {
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
                fast_task::lock_guard lg0(mutex.values.no_race);
                if (loc.is_task_thread) {
                    if (mutex.values.current_task != &*loc.curr_task)
                        throw std::logic_error("Tried unlock non owned mutex");
                } else if (mutex.values.current_task != reinterpret_cast<task*>((size_t)_thread_id() | native_thread_flag))
                    throw std::logic_error("Tried unlock non owned mutex");

                mutex.values.current_task = nullptr;
                while (mutex.values.resume_task.size()) {
                    auto [it, awake_check, native_cv, native_flag] = mutex.values.resume_task.front();
                    mutex.values.resume_task.pop_front();
                    if (it == nullptr) {
                        if (native_cv != nullptr) {
                            *native_flag = true;
                            native_cv->notify_all();
                            return;
                        }
                        continue;
                    }
                    fast_task::lock_guard lg1(get_data(it).no_race);
                    if (get_data(it).awake_check != awake_check)
                        continue;
                    if (!get_data(it).time_end_flag) {
                        get_data(it).awaked = true;
                        if (get_data(it).is_on_scheduler) {
                            mutex.values.current_task = it.get();
                            ++recursive_count;
                        }
                        transfer_task(std::move(it));
                        return;
                    }
                }
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

    void task_recursive_mutex::lifecycle_lock(std::shared_ptr<task>&& task) {
        mutex.lifecycle_lock(std::move(task));
    }

    bool task_recursive_mutex::is_own() {
        if (loc.is_task_thread) {
            if (mutex.values.current_task == &*loc.curr_task)
                return true;
        } else if (mutex.values.current_task == reinterpret_cast<task*>((size_t)_thread_id() | native_thread_flag))
            return true;
        return false;
    }

    bool task_recursive_mutex::enter_wait(const std::shared_ptr<task>& task) {
        fast_task::lock_guard l(mutex.values.no_race);
        if (mutex.values.current_task == task.get()) {
            recursive_count++;
            if (recursive_count == 0) {
                recursive_count--;
                throw std::logic_error("Recursive mutex overflow");
            }
            return true;
        } else if (mutex.values.current_task == nullptr) {
            mutex.values.current_task = task.get();
            recursive_count = 1;
            return true;
        } else {
            mutex.values.resume_task.push_back({task, get_data(task).awake_check, nullptr, nullptr});
            return false;
        }
    }

    bool task_recursive_mutex::enter_wait_until(const std::shared_ptr<task>& task, std::chrono::high_resolution_clock::time_point time_point) {
        fast_task::lock_guard l(mutex.values.no_race);
        if (mutex.values.current_task == task.get()) {
            recursive_count++;
            if (recursive_count == 0) {
                recursive_count--;
                throw std::logic_error("Recursive mutex overflow");
            }
            return true;
        } else if (mutex.values.current_task == nullptr) {
            mutex.values.current_task = task.get();
            recursive_count = 1;
            return true;
        } else {
            mutex.values.resume_task.push_back({task, get_data(task).awake_check, nullptr, nullptr});
            fast_task::makeTimeWait_extern(task, time_point);
            return false;
        }
    }
}
