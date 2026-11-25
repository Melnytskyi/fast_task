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
    constexpr size_t SEM_COUNT_MASK = ~native_thread_data;
    constexpr size_t SEM_HAS_WAITER = native_thread_data;

    namespace {
        struct sem_enter_lock_ctx {
            bool active = false;
            bool called = false;
            bool acquired = false;
        };

        thread_local sem_enter_lock_ctx g_sem_enter_lock_ctx;

        struct sem_enter_lock_scope {
            sem_enter_lock_ctx& ctx;

            sem_enter_lock_scope(sem_enter_lock_ctx& c) noexcept : ctx(c) {
                ctx = {true, false, false};
            }

            ~sem_enter_lock_scope() noexcept {
                ctx.active = false;
            }
        };

        void semaphore_release_waiter_bit(void* address, size_t, bool has_remaining) {
            auto& state = *reinterpret_cast<std::atomic_size_t*>(address);
            if (has_remaining)
                state.fetch_or(SEM_HAS_WAITER, std::memory_order_release);
            else
                state.fetch_and(SEM_COUNT_MASK, std::memory_order_release);
        }

        size_t semaphore_wake_some(std::atomic_size_t& state, size_t count) {
            if (count == 0)
                return 0;
            return futex::wake_on_address(&state, semaphore_release_waiter_bit, count);
        }

        bool sem_enter_check_callback(void* addr) {
            auto& state = *reinterpret_cast<std::atomic_size_t*>(addr);
            size_t cur = state.load(std::memory_order_relaxed);
            while (true) {
                if ((cur & SEM_COUNT_MASK) > 0)
                    return true;
                if (state.compare_exchange_weak(cur, cur | SEM_HAS_WAITER, std::memory_order_release, std::memory_order_relaxed))
                    return false;
            }
        }

        void sem_enter_lock_callback(void* addr, const task&, futex::node_data) {
            auto& state = *reinterpret_cast<std::atomic_size_t*>(addr);
            size_t cur = state.load(std::memory_order_relaxed);
            bool try_only = g_sem_enter_lock_ctx.active;
            if (try_only)
                g_sem_enter_lock_ctx.called = true;
            while (true) {
                if ((cur & SEM_COUNT_MASK) > 0) {
                    if (state.compare_exchange_weak(cur, cur - 1, std::memory_order_acquire, std::memory_order_relaxed)) {
                        if (try_only)
                            g_sem_enter_lock_ctx.acquired = true;
                        return;
                    }
                    continue;
                }
                if (try_only) {
                    g_sem_enter_lock_ctx.acquired = false;
                    return;
                }
                std::this_thread::yield();
                cur = state.load(std::memory_order_relaxed);
            }
        }
    }

    semaphore::semaphore() : values{.state = 0, .max_threshold = 0} {
        FT_DEBUG_ONLY(register_object(this));
    }

    semaphore::~semaphore() {
        FT_DEBUG_ONLY(unregister_object(this));
        if (futex::has_waiters(&values.state)) {
            assert(false && "Semaphore destroyed while waited");
            std::terminate();
        }
    }

    void semaphore::set_max_threshold(size_t val) {
        values.max_threshold.store(val, std::memory_order_release);

        size_t expected = values.state.load(std::memory_order_relaxed);
        while (!values.state.compare_exchange_weak(
            expected,
            (expected & SEM_HAS_WAITER) | val,
            std::memory_order_release,
            std::memory_order_relaxed
        )) {
        }

        if ((expected & SEM_HAS_WAITER) == 0)
            return;

        size_t waiters = futex::wait_items_on(&values.state);
        semaphore_wake_some(values.state, std::min(val, waiters));
    }

    void semaphore::lock() {
        interrupt_unsafe_region region;
        size_t expected = values.state.load(std::memory_order_relaxed);
        while (true) {
            while ((expected & SEM_COUNT_MASK) > 0) {
                if (values.state.compare_exchange_weak(expected, expected - 1, std::memory_order_acquire, std::memory_order_relaxed))
                    return;
            }
            futex::wait_on_address(&values.state, [](void* addr) {
                auto& state = *reinterpret_cast<std::atomic_size_t*>(addr);
                size_t cur = state.load(std::memory_order_relaxed);
                while (true) {
                    if ((cur & SEM_COUNT_MASK) > 0)
                        return true;
                    if (state.compare_exchange_weak(cur, cur | SEM_HAS_WAITER, std::memory_order_release, std::memory_order_relaxed))
                        return false;
                }
            });
            expected = values.state.load(std::memory_order_relaxed);
        }
    }

    bool semaphore::try_lock() {
        size_t expected = values.state.load(std::memory_order_relaxed);
        while ((expected & SEM_COUNT_MASK) > 0) {
            if (values.state.compare_exchange_weak(expected, expected - 1, std::memory_order_acquire, std::memory_order_relaxed))
                return true;
        }
        return false;
    }

    bool semaphore::try_lock_until(fast_task::time_point time_point) {
        interrupt_unsafe_region region;
        size_t expected = values.state.load(std::memory_order_relaxed);
        while (true) {
            while ((expected & SEM_COUNT_MASK) > 0) {
                if (values.state.compare_exchange_weak(expected, expected - 1, std::memory_order_acquire, std::memory_order_relaxed))
                    return true;
            }
            if (!futex::wait_on_address_until(&values.state, [](void* addr) {
                    auto& state = *reinterpret_cast<std::atomic_size_t*>(addr);
                    size_t cur = state.load(std::memory_order_relaxed);
                    while (true) {
                        if ((cur & SEM_COUNT_MASK) > 0)
                            return true;
                        if (state.compare_exchange_weak(cur, cur | SEM_HAS_WAITER, std::memory_order_release, std::memory_order_relaxed))
                            return false;
                    } }, time_point))
                return false;
            expected = values.state.load(std::memory_order_relaxed);
        }
    }

    void semaphore::release() {
        size_t cached = values.state.load(std::memory_order_relaxed);
        size_t max = values.max_threshold.load(std::memory_order_relaxed);
        while (true) {
            if ((cached & SEM_COUNT_MASK) >= max)
                return;
            if (values.state.compare_exchange_weak(cached, cached + 1, std::memory_order_release, std::memory_order_relaxed))
                break;
        }

        if ((cached & SEM_HAS_WAITER) == 0)
            return;

        semaphore_wake_some(values.state, 1);
    }

    void semaphore::release_all() {
        size_t max = values.max_threshold.load(std::memory_order_relaxed);

        size_t expected = values.state.load(std::memory_order_relaxed);
        while (!values.state.compare_exchange_weak(
            expected,
            (expected & SEM_HAS_WAITER) | max,
            std::memory_order_release,
            std::memory_order_relaxed
        )) {
        }

        if ((expected & SEM_HAS_WAITER) == 0)
            return;

        size_t waiters = futex::wait_items_on(&values.state);
        semaphore_wake_some(values.state, std::min(max, waiters));
    }

    bool semaphore::is_locked() {
        return (values.state.load(std::memory_order_relaxed) & SEM_COUNT_MASK) == 0;
    }

    bool semaphore::enter_wait(const task& task, enter_state& state) {
        interrupt_unsafe_region region;
        while (true) {
            size_t expected = values.state.load(std::memory_order_relaxed);
            while ((expected & SEM_COUNT_MASK) > 0) {
                if (values.state.compare_exchange_weak(expected, expected - 1, std::memory_order_acquire, std::memory_order_relaxed))
                    return true;
            }
            bool immediate = false;
            bool called = false;
            bool acquired = false;
            {
                sem_enter_lock_scope scope(g_sem_enter_lock_ctx);
                immediate = futex::enter_wait_on_address_lock(
                    task,
                    &values.state,
                    &sem_enter_check_callback,
                    &sem_enter_lock_callback,
                    state
                );
                called = g_sem_enter_lock_ctx.called;
                acquired = g_sem_enter_lock_ctx.acquired;
            }
            if (!immediate)
                return false;
            if (!called || acquired)
                return true;
        }
    }

    bool semaphore::enter_wait_until(const task& task, enter_state& state, fast_task::time_point time_point) {
        interrupt_unsafe_region region;
        get_data(task).set_time_end(false);
        while (true) {
            size_t expected = values.state.load(std::memory_order_relaxed);
            while ((expected & SEM_COUNT_MASK) > 0) {
                if (values.state.compare_exchange_weak(expected, expected - 1, std::memory_order_acquire, std::memory_order_relaxed))
                    return true;
            }
            bool immediate = false;
            bool called = false;
            bool acquired = false;
            {
                sem_enter_lock_scope scope(g_sem_enter_lock_ctx);
                immediate = futex::enter_wait_on_address_lock_until(
                    task,
                    &values.state,
                    &sem_enter_check_callback,
                    &sem_enter_lock_callback,
                    state,
                    time_point
                );
                called = g_sem_enter_lock_ctx.called;
                acquired = g_sem_enter_lock_ctx.acquired;
            }
            if (!immediate)
                return false;
            if (!called || acquired)
                return true;
        }
    }
}
