// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <fast_task/internal/futex.hpp>
#include <fast_task/task.hpp>
#include <tasks/_internal.hpp>

namespace fast_task {
    constexpr size_t SEM_COUNT_MASK = ~native_thread_data;
    constexpr size_t SEM_HAS_WAITER = native_thread_data;

    semaphore::semaphore() : values{.state = 0, .max_threshold = 0} {
        FT_DEBUG_ONLY(register_object(this));
    }

    semaphore::~semaphore() {
        FT_DEBUG_ONLY(unregister_object(this));
        if ((values.state.load(std::memory_order_relaxed) & SEM_COUNT_MASK) == 0) {
            assert(false && "Semaphore destroyed while locked");
            std::terminate();
        }
    }

    void semaphore::set_max_threshold(size_t val) {
        values.max_threshold.store(val, std::memory_order_release);
        values.state.store(val, std::memory_order_release);
        size_t waiters = futex::wait_items_on(&values.state);
        size_t to_wake = std::min(val, waiters);
        futex::wake_on_address(&values.state, [](void* addr, size_t, bool has_remaining) {
            auto& state = *reinterpret_cast<std::atomic_size_t*>(addr);
            size_t cur = state.load(std::memory_order_relaxed);
            state.store(has_remaining ? (cur | SEM_HAS_WAITER) : (cur & SEM_COUNT_MASK), std::memory_order_release); }, to_wake);
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

    bool semaphore::try_lock_until(std::chrono::high_resolution_clock::time_point time_point) {
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
            if ((cached & SEM_COUNT_MASK) == max)
                return;
            if (values.state.compare_exchange_weak(cached, cached + 1, std::memory_order_release, std::memory_order_relaxed))
                break;
        }
        futex::wake_on_address(&values.state, [](void* addr, size_t, bool has_remaining) {
            auto& state = *reinterpret_cast<std::atomic_size_t*>(addr);
            size_t cur = state.load(std::memory_order_relaxed);
            state.store(has_remaining ? (cur | SEM_HAS_WAITER) : (cur & SEM_COUNT_MASK), std::memory_order_release);
        });
    }

    void semaphore::release_all() {
        size_t max = values.max_threshold.load(std::memory_order_relaxed);
        values.state.store(max, std::memory_order_release);

        size_t waiters = futex::wait_items_on(&values.state);
        size_t to_wake = std::min(max, waiters);
        futex::wake_on_address(&values.state, [](void* addr, size_t, bool has_remaining) {
            auto& state = *reinterpret_cast<std::atomic_size_t*>(addr);
            size_t cur = state.load(std::memory_order_relaxed);
            state.store(has_remaining ? (cur | SEM_HAS_WAITER) : (cur & SEM_COUNT_MASK), std::memory_order_release); }, to_wake);
    }

    bool semaphore::is_locked() {
        return (values.state.load(std::memory_order_relaxed) & SEM_COUNT_MASK) == 0;
    }

    bool semaphore::enter_wait(const task& task, enter_state& state) {
        interrupt_unsafe_region region;
        size_t expected = values.state.load(std::memory_order_relaxed);
        while ((expected & SEM_COUNT_MASK) > 0) {
            if (values.state.compare_exchange_weak(expected, expected - 1, std::memory_order_acquire, std::memory_order_relaxed))
                return true;
        }
        return futex::enter_wait_on_address_lock(
            task,
            &values.state,
            [](void* addr) {
                auto& state = *reinterpret_cast<std::atomic_size_t*>(addr);
                size_t cur = state.load(std::memory_order_relaxed);
                while (true) {
                    if ((cur & SEM_COUNT_MASK) > 0)
                        return true;
                    if (state.compare_exchange_weak(cur, cur | SEM_HAS_WAITER, std::memory_order_release, std::memory_order_relaxed))
                        return false;
                }
            },
            [](void* addr, auto&, auto) {
                auto& state = *reinterpret_cast<std::atomic_size_t*>(addr);
                state.fetch_sub(1, std::memory_order_acquire);
            },
            state
        );
    }

    bool semaphore::enter_wait_until(const task& task, enter_state& state, std::chrono::high_resolution_clock::time_point time_point) {
        interrupt_unsafe_region region;
        size_t expected = values.state.load(std::memory_order_relaxed);
        while ((expected & SEM_COUNT_MASK) > 0) {
            if (values.state.compare_exchange_weak(expected, expected - 1, std::memory_order_acquire, std::memory_order_relaxed))
                return true;
        }
        return futex::enter_wait_on_address_lock_until(
            task,
            &values.state,
            [](void* addr) {
                auto& state = *reinterpret_cast<std::atomic_size_t*>(addr);
                size_t cur = state.load(std::memory_order_relaxed);
                while (true) {
                    if ((cur & SEM_COUNT_MASK) > 0)
                        return true;
                    if (state.compare_exchange_weak(cur, cur | SEM_HAS_WAITER, std::memory_order_release, std::memory_order_relaxed))
                        return false;
                }
            },
            [](void* addr, auto&, auto) {
                auto& state = *reinterpret_cast<std::atomic_size_t*>(addr);
                state.fetch_sub(1, std::memory_order_acquire);
            },
            state,
            time_point
        );
    }
}
