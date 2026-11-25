// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <fast_task/task.hpp>
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
            recursive_count.store(0, std::memory_order_relaxed);
            return;
        }
        uint32_t count = recursive_count.load(std::memory_order_relaxed);
        if (count == UINT32_MAX)
            throw std::logic_error("Recursive mutex overflow");
        recursive_count.store(count + 1, std::memory_order_relaxed);
    }

    bool recursive_mutex::try_lock() {
        if (!mut.is_own())
            return mut.try_lock();
        uint32_t count = recursive_count.load(std::memory_order_relaxed);
        if (count == UINT32_MAX)
            return false;
        recursive_count.store(count + 1, std::memory_order_relaxed);
        return true;
    }

    bool recursive_mutex::try_lock_until(fast_task::time_point time_point) {
        if (!mut.is_own())
            return mut.try_lock_until(time_point);
        uint32_t count = recursive_count.load(std::memory_order_relaxed);
        if (count == UINT32_MAX)
            return false;
        recursive_count.store(count + 1, std::memory_order_relaxed);
        return true;
    }

    void recursive_mutex::unlock() {
        if (!mut.is_own())
            throw std::logic_error("Mutex not owned");
        uint32_t count = recursive_count.load(std::memory_order_relaxed);
        if (count != 0) {
            recursive_count.store(count - 1, std::memory_order_relaxed);
            return;
        }
        mut.unlock();
    }

    bool recursive_mutex::is_locked() {
        return mut.is_locked();
    }

    void recursive_mutex::lifecycle_lock(task&& task) {
        mut.lifecycle_lock(std::move(task));
    }

    bool recursive_mutex::is_own() {
        return mut.is_own();
    }

    bool recursive_mutex::enter_wait(const task& task, enter_state& state) {
        size_t self_id = task.get_id();
        if ((mut.state.load(std::memory_order_relaxed) & ~native_thread_data) == self_id) {
            uint32_t count = recursive_count.load(std::memory_order_relaxed);
            if (count == UINT32_MAX)
                throw std::logic_error("Recursive mutex overflow");
            recursive_count.store(count + 1, std::memory_order_relaxed);
            return true;
        }
        if (mut.enter_wait(task, state)) {
            recursive_count.store(0, std::memory_order_relaxed);
            return true;
        }
        return false;
    }

    bool recursive_mutex::enter_wait_until(const task& task, enter_state& state, fast_task::time_point time_point) {
        size_t self_id = task.get_id();
        if ((mut.state.load(std::memory_order_relaxed) & ~native_thread_data) == self_id) {
            uint32_t count = recursive_count.load(std::memory_order_relaxed);
            if (count == UINT32_MAX)
                throw std::logic_error("Recursive mutex overflow");
            recursive_count.store(count + 1, std::memory_order_relaxed);
            return true;
        }
        if (mut.enter_wait_until(task, state, time_point)) {
            if ((mut.state.load(std::memory_order_relaxed) & ~native_thread_data) == self_id)
                recursive_count.store(0, std::memory_order_relaxed);
            return true;
        }
        return false;
    }
}
