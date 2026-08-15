// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <task.hpp>
#include <tasks/_internal.hpp>

namespace fast_task {
    recursive_mutex::recursive_mutex() {
        FT_DEBUG_ONLY(register_object(this));
    }

    recursive_mutex::~recursive_mutex() {
        FT_DEBUG_ONLY(unregister_object(this));
        if (mut.is_locked()) {
            assert(false && "Mutex destroyed while locked");
            std::terminate();
        }
    }

    void recursive_mutex::lock() {
        if (!mut.is_own()) {
            mut.lock();
            return;
        }
        ++recursive_count;
        if (recursive_count == 0) {
            recursive_count--;
            throw std::logic_error("Recursive mutex overflow");
        }
    }

    bool recursive_mutex::try_lock() {
        if (!mut.is_own())
            return mut.try_lock();
        ++recursive_count;
        if (recursive_count == 0) {
            recursive_count--;
            return false;
        }
        return true;
    }

    bool recursive_mutex::try_lock_until(std::chrono::high_resolution_clock::time_point time_point) {
        if (!mut.is_own())
            return mut.try_lock_until(time_point);
        ++recursive_count;
        if (recursive_count == 0) {
            recursive_count--;
            return false;
        }
        return true;
    }

    void recursive_mutex::unlock() {
        if (mut.is_own()) {
            if (recursive_count-- == 0) {
                mut.unlock();
                recursive_count = 0;
            }
        } else
            throw std::logic_error("Mutex not owned");
    }

    bool recursive_mutex::is_locked() {
        if (recursive_count)
            return true;
        else
            return false;
    }

    void recursive_mutex::lifecycle_lock(task&& task) {
        mut.lifecycle_lock(std::move(task));
    }

    bool recursive_mutex::is_own() {
        return mut.is_own();
    }

    bool recursive_mutex::enter_wait(const task& task, enter_state& state) {
        if (mut.is_own()) {
            recursive_count++;
            if (recursive_count == 0) {
                recursive_count--;
                throw std::logic_error("Recursive mutex overflow");
            }
            return true;
        } else if (mut.try_lock()) {
            return true;
        } else
            return mut.enter_wait(task, state);
    }

    bool recursive_mutex::enter_wait_until(const task& task, enter_state& state, std::chrono::high_resolution_clock::time_point time_point) {
        if (mut.is_own()) {
            recursive_count++;
            if (recursive_count == 0) {
                recursive_count--;
                throw std::logic_error("Recursive mutex overflow");
            }
            return true;
        } else if (mut.try_lock()) {
            return true;
        } else
            return mut.enter_wait_until(task, state, time_point);
    }
}
