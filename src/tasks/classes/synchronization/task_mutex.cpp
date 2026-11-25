// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <fast_task/internal/futex.hpp>
#include <fast_task/task.hpp>
#include <tasks/_internal.hpp>
#include <thread>

namespace fast_task {
    constexpr size_t UNLOCKED = 0;
    constexpr size_t OWNER_MASK = ~native_thread_data;
    constexpr size_t HAS_WAITER = native_thread_data;

    namespace {
        struct mutex_enter_lock_ctx {
            bool active = false;
            bool called = false;
            bool acquired = false;
        };

        thread_local mutex_enter_lock_ctx g_mutex_enter_lock_ctx;

        struct mutex_enter_lock_scope {
            mutex_enter_lock_ctx& ctx;

            mutex_enter_lock_scope(mutex_enter_lock_ctx& c) noexcept : ctx(c) {
                ctx = {true, false, false};
            }

            ~mutex_enter_lock_scope() noexcept {
                ctx.active = false;
            }
        };

        bool mutex_enter_check_callback(void* addr) {
            auto& state = *reinterpret_cast<std::atomic_size_t*>(addr);
            size_t cur = state.load(std::memory_order_relaxed);
            while (true) {
                if ((cur & OWNER_MASK) == UNLOCKED)
                    return true;
                if (state.compare_exchange_weak(cur, cur | HAS_WAITER, std::memory_order_release, std::memory_order_relaxed))
                    return false;
            }
        }

        void mutex_enter_lock_callback(void* addr, const task& t, futex::node_data) {
            auto& state = *reinterpret_cast<std::atomic_size_t*>(addr);
            size_t self_id = t.get_id();
            size_t expected = state.load(std::memory_order_relaxed);
            bool try_only = g_mutex_enter_lock_ctx.active;
            if (try_only)
                g_mutex_enter_lock_ctx.called = true;
            while (true) {
                if ((expected & OWNER_MASK) == UNLOCKED) {
                    if (state.compare_exchange_weak(expected, self_id | (expected & HAS_WAITER), std::memory_order_acquire, std::memory_order_relaxed)) {
                        if (try_only)
                            g_mutex_enter_lock_ctx.acquired = true;
                        return;
                    }
                    continue;
                }
                if (try_only) {
                    g_mutex_enter_lock_ctx.acquired = false;
                    return;
                }
                std::this_thread::yield();
                expected = state.load(std::memory_order_relaxed);
            }
        }
    }

    void mutex::transfer_ownership(size_t to_owner) {
        if (!is_own())
            return;
        size_t expected = state.load(std::memory_order_relaxed);
        while (true) {
            if (state.compare_exchange_strong(expected, to_owner | (expected & HAS_WAITER), std::memory_order_acq_rel, std::memory_order_relaxed))
                return;
        }
    }

    void mutex::mark_has_wait() {
        size_t expected = state.load(std::memory_order_relaxed);
        while (true) {
            if (state.compare_exchange_strong(expected, expected | HAS_WAITER, std::memory_order_acq_rel, std::memory_order_relaxed))
                return;
        }
    }

    void mutex::set_unlocked(bool has_remaining) {
        state.store(has_remaining ? HAS_WAITER : UNLOCKED, std::memory_order_release);
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
            futex::wait_on_address(&state, [](void* addr) {
                auto& state = *reinterpret_cast<std::atomic_size_t*>(addr);
                size_t cur = state.load(std::memory_order_relaxed);
                while (true) {
                    if ((cur & OWNER_MASK) == UNLOCKED)
                        return true;
                    if (state.compare_exchange_weak(cur, cur | HAS_WAITER, std::memory_order_release, std::memory_order_relaxed))
                        return false;
                }
            });
            expected = state.load(std::memory_order_relaxed);
            while ((expected & OWNER_MASK) == UNLOCKED)
                if (state.compare_exchange_weak(expected, self_id | (expected & HAS_WAITER), std::memory_order_acquire, std::memory_order_relaxed))
                    return;
        }
    }

    bool mutex::try_lock() {
        interrupt_unsafe_region region;
        size_t self_id = this_task::get_id();
        size_t expected = state.load(std::memory_order_relaxed);

        if ((expected & OWNER_MASK) == self_id)
            return false;

        while ((expected & OWNER_MASK) == UNLOCKED)
            if (state.compare_exchange_weak(expected, self_id | (expected & HAS_WAITER), std::memory_order_acquire, std::memory_order_relaxed))
                return true;

        return false;
    }

    bool mutex::try_lock_until(fast_task::time_point time_point) {
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
            if (!futex::wait_on_address_until(
                    &state,
                    [](void* addr) {
                        auto& state = *reinterpret_cast<std::atomic_size_t*>(addr);
                        size_t cur = state.load(std::memory_order_relaxed);
                        while (true) {
                            if ((cur & OWNER_MASK) == UNLOCKED)
                                return true;
                            if (state.compare_exchange_weak(cur, cur | HAS_WAITER, std::memory_order_release, std::memory_order_relaxed))
                                return false;
                        }
                    },
                    time_point
                ))
                return false;
            expected = state.load(std::memory_order_acquire);
            if ((expected & OWNER_MASK) == UNLOCKED)
                if (state.compare_exchange_strong(expected, self_id | (expected & HAS_WAITER), std::memory_order_acquire, std::memory_order_relaxed))
                    return true;
        }
    }

    void mutex::unlock() {
        size_t self_id = this_task::get_id();
        size_t cached_state = state.load(std::memory_order_relaxed);

        if ((cached_state & OWNER_MASK) != self_id)
            throw std::logic_error("Tried unlock non owned mutex");

        if (cached_state == self_id)
            if (state.compare_exchange_strong(self_id, UNLOCKED, std::memory_order_release, std::memory_order_relaxed))
                return;

        futex::wake_on_address(&state, [](void* addr, size_t, bool has_remaining) {
            reinterpret_cast<std::atomic_size_t*>(addr)->store(has_remaining ? HAS_WAITER : UNLOCKED, std::memory_order_release);
        });
    }

    bool mutex::is_locked() {
        return (state.load(std::memory_order_relaxed) & OWNER_MASK) != UNLOCKED;
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
        size_t self_id = task.get_id();
        if ((state.load(std::memory_order_relaxed) & OWNER_MASK) == self_id)
            throw std::logic_error("Tried lock mutex twice");

        while (true) {
            size_t expected = state.load(std::memory_order_relaxed);
            while ((expected & OWNER_MASK) == UNLOCKED)
                if (state.compare_exchange_weak(expected, self_id | (expected & HAS_WAITER), std::memory_order_acquire, std::memory_order_relaxed))
                    return true;

            bool immediate = false;
            bool called = false;
            bool acquired = false;
            {
                mutex_enter_lock_scope scope(g_mutex_enter_lock_ctx);
                immediate = futex::enter_wait_on_address_lock(
                    task,
                    &state,
                    &mutex_enter_check_callback,
                    &mutex_enter_lock_callback,
                    es
                );
                called = g_mutex_enter_lock_ctx.called;
                acquired = g_mutex_enter_lock_ctx.acquired;
            }
            if (!immediate)
                return false;
            if (!called || acquired)
                return true;
        }
    }

    bool mutex::enter_wait_until(const task& task, enter_state& es, fast_task::time_point time_point) {
        interrupt_unsafe_region region;
        size_t self_id = task.get_id();
        get_data(task).set_time_end(false);

        if ((state.load(std::memory_order_relaxed) & OWNER_MASK) == self_id)
            throw std::logic_error("Tried lock mutex twice");

        while (true) {
            size_t expected = state.load(std::memory_order_relaxed);
            while ((expected & OWNER_MASK) == UNLOCKED)
                if (state.compare_exchange_weak(expected, self_id | (expected & HAS_WAITER), std::memory_order_acquire, std::memory_order_relaxed))
                    return true;

            bool immediate = false;
            bool called = false;
            bool acquired = false;
            {
                mutex_enter_lock_scope scope(g_mutex_enter_lock_ctx);
                immediate = futex::enter_wait_on_address_lock_until(
                    task,
                    &state,
                    &mutex_enter_check_callback,
                    &mutex_enter_lock_callback,
                    es,
                    time_point
                );
                called = g_mutex_enter_lock_ctx.called;
                acquired = g_mutex_enter_lock_ctx.acquired;
            }
            if (!immediate)
                return false;
            if (!called || acquired)
                return true;
        }
    }
}
