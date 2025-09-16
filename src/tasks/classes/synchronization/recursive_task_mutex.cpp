// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <task.hpp>
#include <tasks/_internal.hpp>

namespace fast_task {
    task_recursive_mutex::task_recursive_mutex() {}

    task_recursive_mutex::~task_recursive_mutex() {
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

    bool task_recursive_mutex::try_lock_for(size_t milliseconds) {
        if (loc.is_task_thread) {
            if (mutex.values.current_task == &*loc.curr_task) {
                recursive_count++;
                if (recursive_count == 0) {
                    recursive_count--;
                    return false;
                }
                return true;
            } else if (mutex.try_lock_for(milliseconds)) {
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
            } else if (mutex.try_lock_for(milliseconds)) {
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
            if (!recursive_count)
                mutex.unlock();
        } else
            throw std::logic_error("Mutex not locked");
    }

    bool task_recursive_mutex::is_locked() {
        if (recursive_count)
            return true;
        else
            return false;
    }

    void task_recursive_mutex::lifecycle_lock(std::shared_ptr<task>& task) {
        mutex.lifecycle_lock(task);
    }

    bool task_recursive_mutex::is_own() {
        if (loc.is_task_thread) {
            if (mutex.values.current_task == &*loc.curr_task)
                return true;
        } else if (mutex.values.current_task == reinterpret_cast<task*>((size_t)_thread_id() | native_thread_flag))
            return true;
        return false;
    }
}
