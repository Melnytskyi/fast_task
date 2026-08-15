// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <experimental/futex.hpp>
#include <task.hpp>
#include <tasks/_internal.hpp>

namespace fast_task {
    constexpr size_t UNLOCKED = 0;
    constexpr size_t OWNER_MASK = ~native_thread_data;
    constexpr size_t HAS_WAITER = native_thread_data;

    void mutex::transfer_ownership(size_t to_owner) {
        if (!is_own())
            return;
        size_t expected = state.load(std::memory_order_relaxed);
        while (true) {
            if (state.compare_exchange_strong(expected, to_owner | (expected & HAS_WAITER), std::memory_order_acquire, std::memory_order_relaxed))
                return;
        }
    }

    void mutex::mark_has_wait() {
        size_t expected = state.load(std::memory_order_relaxed);
        while (true) {
            if (state.compare_exchange_strong(expected, expected | HAS_WAITER, std::memory_order_acquire, std::memory_order_relaxed))
                return;
        }
    }

    mutex::mutex() : state(UNLOCKED) {
        FT_DEBUG_ONLY(register_object(this));
    }

    mutex::~mutex() {
        FT_DEBUG_ONLY(unregister_object(this));
        if (is_locked()) {
            assert(false && "Tried to destroy locked mutex");
            std::terminate();
        }
    }

    void mutex::lock() {
        interrupt_unsafe_region region;
        size_t expected = UNLOCKED;
        size_t self_id = this_task::get_id();
        if ((state.load(std::memory_order_relaxed) & OWNER_MASK) == self_id)
            throw std::logic_error("Tried lock mutex twice");
        if (state.compare_exchange_strong(expected, self_id, std::memory_order_acquire, std::memory_order_relaxed))
            return;
        if ((expected & OWNER_MASK) == self_id)
            return;
        while (true) {
            if ((expected & HAS_WAITER) == 0) {
                if (!state.compare_exchange_weak(expected, expected | HAS_WAITER, std::memory_order_relaxed, std::memory_order_relaxed)) {
                    if (expected == 0) {
                        if (state.compare_exchange_strong(expected, self_id, std::memory_order_acquire, std::memory_order_relaxed))
                            return;
                    }
                    continue;
                }
                expected |= HAS_WAITER;
            }
            futex::wait_on_address(&state, [](void* addr) {
                return *reinterpret_cast<size_t*>(addr) == UNLOCKED;
            });
            expected = state.load(std::memory_order_acquire);
            if (expected == 0)
                if (state.compare_exchange_strong(expected, self_id, std::memory_order_acquire, std::memory_order_relaxed))
                    return;
        }
    }

    bool mutex::try_lock() {
        interrupt_unsafe_region region;
        size_t expected = UNLOCKED;
        size_t self_id = this_task::get_id();
        if (is_own())
            return false;
        if (state.compare_exchange_strong(expected, self_id, std::memory_order_acquire, std::memory_order_relaxed))
            return true;
        else
            return (expected & OWNER_MASK) == self_id;
    }

    bool mutex::try_lock_until(std::chrono::high_resolution_clock::time_point time_point) {
        interrupt_unsafe_region region;
        size_t expected = UNLOCKED;
        size_t self_id = this_task::get_id();
        if ((state.load(std::memory_order_relaxed) & OWNER_MASK) == self_id)
            return false;
        if (state.compare_exchange_strong(expected, self_id, std::memory_order_acquire, std::memory_order_relaxed))
            return true;
        if ((expected & OWNER_MASK) == self_id)
            return true;
        while (true) {
            if ((expected & HAS_WAITER) == 0) {
                if (!state.compare_exchange_weak(expected, expected | HAS_WAITER, std::memory_order_relaxed, std::memory_order_relaxed)) {
                    if (expected == 0) {
                        if (state.compare_exchange_strong(expected, self_id, std::memory_order_acquire, std::memory_order_relaxed))
                            return true;
                    }
                    continue;
                }
                expected |= HAS_WAITER;
            }
            if (!futex::wait_on_address_until(&state, [](void* addr) { return *reinterpret_cast<size_t*>(addr) == UNLOCKED; }, time_point))
                return false;
            expected = state.load(std::memory_order_acquire);
            if (expected == 0)
                if (state.compare_exchange_strong(expected, self_id, std::memory_order_acquire, std::memory_order_relaxed))
                    return true;
        }
    }

    void mutex::unlock() {
        size_t self_id = this_task::get_id();
        size_t cached_state = state.load(std::memory_order_relaxed);

        if ((cached_state & OWNER_MASK) != self_id)
            throw std::logic_error("Tried unlock non owned mutex");
        else if (cached_state == self_id)
            if (state.compare_exchange_strong(self_id, 0, std::memory_order_release, std::memory_order_relaxed))
                return;

        futex::wake_on_address(&state, [](void* addr, size_t) { *reinterpret_cast<size_t*>(addr) = UNLOCKED; });
    }

    bool mutex::is_locked() {
        return state.load(std::memory_order_relaxed) != UNLOCKED;
    }

    bool mutex::is_own() {
        return (state.load(std::memory_order_relaxed) & OWNER_MASK) == this_task::get_id();
    }

    void mutex::lifecycle_lock(task&& lock_task) {
        {
            fast_task::lock_guard guard(get_data(lock_task));
            if (get_data(lock_task).is_running() || get_data(lock_task).is_ended())
                throw std::runtime_error("Task is running or completed and cannot be registered");
            if (get_data(lock_task).is_scheduled() && (!get_data(lock_task).is_suspended() && get_data(lock_task).get_is_on_scheduler()))
                throw std::runtime_error("Task is already in the scheduler queue");
            if (!get_data(lock_task).vtable || !get_data(lock_task).vtable->on_start)
                throw std::logic_error("mutex::lifecycle_lock requires the on_start callback to be set");
        }
        task::run([lock_task, this]() {
            fast_task::lock_guard guard(*this);
            task::await_task(lock_task, true);
        });
    }

    bool mutex::enter_wait(const task& task, enter_state& es) {
        interrupt_unsafe_region region;
        size_t expected = UNLOCKED;
        size_t self_id = task.get_id();
        if ((state.load(std::memory_order_relaxed) & OWNER_MASK) == self_id)
            throw std::logic_error("Tried lock mutex twice");
        if (state.compare_exchange_strong(expected, self_id, std::memory_order_acquire, std::memory_order_relaxed))
            return true;
        if ((expected & OWNER_MASK) == self_id)
            return true;
        return futex::enter_wait_on_address_lock(
            task,
            &state,
            [](void* addr) { return *reinterpret_cast<size_t*>(addr) == UNLOCKED; },
            [](void* addr, auto& task) { *reinterpret_cast<size_t*>(addr) = task.get_id() | HAS_WAITER; },
            es
        );
    }

    bool mutex::enter_wait_until(const task& task, enter_state& es, std::chrono::high_resolution_clock::time_point time_point) {
        interrupt_unsafe_region region;
        size_t expected = UNLOCKED;
        size_t self_id = task.get_id();
        if ((state.load(std::memory_order_relaxed) & OWNER_MASK) == self_id)
            throw std::logic_error("Tried lock mutex twice");
        if (state.compare_exchange_strong(expected, self_id, std::memory_order_acquire, std::memory_order_relaxed))
            return true;
        if ((expected & OWNER_MASK) == self_id)
            return true;
        return futex::enter_wait_on_address_lock_until(
            task,
            &state,
            [](void* addr) { return *reinterpret_cast<size_t*>(addr) == UNLOCKED; },
            [](void* addr, auto& task) { *reinterpret_cast<size_t*>(addr) = task.get_id() | HAS_WAITER; },
            es,
            time_point
        );
    }
}
