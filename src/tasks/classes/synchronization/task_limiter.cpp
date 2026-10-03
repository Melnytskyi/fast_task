// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <experimental/futex.hpp>
#include <task.hpp>
#include <tasks/_internal.hpp>

namespace fast_task {
    constexpr size_t LIM_COUNT_MASK = ~native_thread_data;
    constexpr size_t LIM_HAS_WAITER = native_thread_data;

    limiter::limiter() : values{.lock_check = {}, .lock_check_lock = {}, .state = 1, .max_threshold = 1} {
        FT_DEBUG_ONLY(register_object(this));
    }

    limiter::~limiter() {
        FT_DEBUG_ONLY(unregister_object(this));
        if ((values.state.load(std::memory_order_relaxed) & LIM_COUNT_MASK) == 0) {
            assert(false && "Tried to destroy locked limiter");
            std::terminate();
        }
    }

    void limiter::check_deadlock(size_t lock_id) {
        fast_task::lock_guard guard(values.lock_check_lock);
        if (std::find(values.lock_check.begin(), values.lock_check.end(), lock_id) != values.lock_check.end()) {
            values.state.fetch_add(1, std::memory_order_release);
            throw std::logic_error("Dead lock. task try lock already locked task limiter");
        }
        values.lock_check.push_back(lock_id);
    }

    void limiter::set_max_threshold(size_t val) {
        if (val < 1)
            val = 1;
        size_t old_max = values.max_threshold.load(std::memory_order_relaxed);
        if (old_max == val)
            return;
        values.max_threshold.store(val, std::memory_order_release);

        if (val > old_max) {
            size_t added = val - old_max;
            size_t expected = values.state.load(std::memory_order_relaxed);
            while (true) {
                size_t cur_count = expected & LIM_COUNT_MASK;
                size_t new_count = cur_count + added;
                if (new_count > val)
                    new_count = val;
                if (values.state.compare_exchange_weak(expected, (expected & LIM_HAS_WAITER) | new_count, std::memory_order_release, std::memory_order_relaxed))
                    break;
            }
            size_t waiters = futex::wait_items_on(&values.state);
            size_t to_wake = std::min(added, waiters);
            futex::wake_on_address(&values.state, [](void* addr, size_t, bool has_remaining) {
                auto& state = *reinterpret_cast<std::atomic_size_t*>(addr);
                size_t cur = state.load(std::memory_order_relaxed);
                state.store(has_remaining ? (cur | LIM_HAS_WAITER) : (cur & LIM_COUNT_MASK), std::memory_order_release); }, to_wake);
        } else {
            size_t remove = old_max - val;
            size_t expected = values.state.load(std::memory_order_relaxed);
            while (true) {
                size_t cur_count = expected & LIM_COUNT_MASK;
                size_t new_count = cur_count > remove ? cur_count - remove : 0;
                if (values.state.compare_exchange_weak(expected, (expected & LIM_HAS_WAITER) | new_count, std::memory_order_release, std::memory_order_relaxed))
                    break;
            }
        }
    }

    void limiter::lock() {
        interrupt_unsafe_region region;
        size_t expected = values.state.load(std::memory_order_relaxed);
        while (true) {
            while ((expected & LIM_COUNT_MASK) > 0) {
                if (values.state.compare_exchange_weak(expected, expected - 1, std::memory_order_acquire, std::memory_order_relaxed)) {
                    check_deadlock(this_task::get_id());
                    return;
                }
            }
            futex::wait_on_address(&values.state, [](void* addr) {
                auto& state = *reinterpret_cast<std::atomic_size_t*>(addr);
                size_t cur = state.load(std::memory_order_relaxed);
                while (true) {
                    if ((cur & LIM_COUNT_MASK) > 0)
                        return true;
                    if (state.compare_exchange_weak(cur, cur | LIM_HAS_WAITER, std::memory_order_release, std::memory_order_relaxed))
                        return false;
                }
            });
            expected = values.state.load(std::memory_order_relaxed);
        }
    }

    bool limiter::try_lock() {
        size_t expected = values.state.load(std::memory_order_relaxed);
        while ((expected & LIM_COUNT_MASK) > 0) {
            if (values.state.compare_exchange_weak(expected, expected - 1, std::memory_order_acquire, std::memory_order_relaxed)) {
                check_deadlock(this_task::get_id());
                return true;
            }
        }
        return false;
    }

    bool limiter::try_lock_until(std::chrono::high_resolution_clock::time_point time_point) {
        interrupt_unsafe_region region;
        size_t expected = values.state.load(std::memory_order_relaxed);
        while (true) {
            while ((expected & LIM_COUNT_MASK) > 0) {
                if (values.state.compare_exchange_weak(expected, expected - 1, std::memory_order_acquire, std::memory_order_relaxed)) {
                    check_deadlock(this_task::get_id());
                    return true;
                }
            }
            if (!futex::wait_on_address_until(&values.state, [](void* addr) {
                    auto& state = *reinterpret_cast<std::atomic_size_t*>(addr);
                    size_t cur = state.load(std::memory_order_relaxed);
                    while (true) {
                        if ((cur & LIM_COUNT_MASK) > 0)
                            return true;
                        if (state.compare_exchange_weak(cur, cur | LIM_HAS_WAITER, std::memory_order_release, std::memory_order_relaxed))
                            return false;
                    } }, time_point))
                return false;
            expected = values.state.load(std::memory_order_relaxed);
        }
    }

    void limiter::unlock() {
        size_t lock_id = this_task::get_id();
        {
            fast_task::lock_guard guard(values.lock_check_lock);
            auto item = std::find(values.lock_check.begin(), values.lock_check.end(), lock_id);
            if (item == values.lock_check.end())
                throw std::logic_error("Invalid unlock. task try unlock already unlocked task limiter");
            values.lock_check.erase(item);
        }
        unchecked_unlock();
    }

    void limiter::unchecked_unlock() {
        size_t max = values.max_threshold.load(std::memory_order_relaxed);
        size_t cached = values.state.load(std::memory_order_relaxed);
        while (true) {
            if ((cached & LIM_COUNT_MASK) == max)
                return;
            if (values.state.compare_exchange_weak(cached, cached + 1, std::memory_order_release, std::memory_order_relaxed))
                break;
        }
        futex::wake_on_address(&values.state, [](void* addr, size_t, bool has_remaining) {
            auto& state = *reinterpret_cast<std::atomic_size_t*>(addr);
            size_t cur = state.load(std::memory_order_relaxed);
            state.store(has_remaining ? (cur | LIM_HAS_WAITER) : (cur & LIM_COUNT_MASK), std::memory_order_release);
        });
    }

    bool limiter::is_locked() {
        return (values.state.load(std::memory_order_relaxed) & LIM_COUNT_MASK) == 0;
    }

    bool limiter::enter_wait(const task& task, enter_state& state) {
        interrupt_unsafe_region region;
        size_t expected = values.state.load(std::memory_order_relaxed);
        while ((expected & LIM_COUNT_MASK) > 0) {
            if (values.state.compare_exchange_weak(expected, expected - 1, std::memory_order_acquire, std::memory_order_relaxed)) {
                check_deadlock(task.get_id());
                return true;
            }
        }
        return futex::enter_wait_on_address_lock(
            task,
            &values.state,
            [](void* addr) {
                auto& state = *reinterpret_cast<std::atomic_size_t*>(addr);
                size_t cur = state.load(std::memory_order_relaxed);
                while (true) {
                    if ((cur & LIM_COUNT_MASK) > 0)
                        return true;
                    if (state.compare_exchange_weak(cur, cur | LIM_HAS_WAITER, std::memory_order_release, std::memory_order_relaxed))
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

    bool limiter::enter_wait_until(const task& task, enter_state& state, std::chrono::high_resolution_clock::time_point time_point) {
        interrupt_unsafe_region region;
        size_t expected = values.state.load(std::memory_order_relaxed);
        while ((expected & LIM_COUNT_MASK) > 0) {
            if (values.state.compare_exchange_weak(expected, expected - 1, std::memory_order_acquire, std::memory_order_relaxed)) {
                check_deadlock(task.get_id());
                return true;
            }
        }
        return futex::enter_wait_on_address_lock_until(
            task,
            &values.state,
            [](void* addr) {
                auto& state = *reinterpret_cast<std::atomic_size_t*>(addr);
                size_t cur = state.load(std::memory_order_relaxed);
                while (true) {
                    if ((cur & LIM_COUNT_MASK) > 0)
                        return true;
                    if (state.compare_exchange_weak(cur, cur | LIM_HAS_WAITER, std::memory_order_release, std::memory_order_relaxed))
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
