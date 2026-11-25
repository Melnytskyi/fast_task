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
    constexpr size_t LIM_COUNT_MASK = ~native_thread_data;
    constexpr size_t LIM_HAS_WAITER = native_thread_data;

    namespace {
        struct lim_enter_lock_ctx {
            bool active = false;
            bool called = false;
            bool acquired = false;
        };

        thread_local lim_enter_lock_ctx g_lim_enter_lock_ctx;

        struct lim_enter_lock_scope {
            lim_enter_lock_ctx& ctx;

            lim_enter_lock_scope(lim_enter_lock_ctx& c) noexcept : ctx(c) {
                ctx = {true, false, false};
            }

            ~lim_enter_lock_scope() noexcept {
                ctx.active = false;
            }
        };

        void limiter_release_waiter_bit(void* address, size_t, bool has_remaining) {
            auto& state = *reinterpret_cast<std::atomic_size_t*>(address);
            if (has_remaining)
                state.fetch_or(LIM_HAS_WAITER, std::memory_order_release);
            else
                state.fetch_and(LIM_COUNT_MASK, std::memory_order_release);
        }

        size_t limiter_wake_some(std::atomic_size_t& state, size_t count) {
            if (count == 0)
                return 0;
            return futex::wake_on_address(&state, limiter_release_waiter_bit, count);
        }

        bool lim_enter_check_callback(void* addr) {
            auto& state = *reinterpret_cast<std::atomic_size_t*>(addr);
            size_t cur = state.load(std::memory_order_relaxed);
            while (true) {
                if ((cur & LIM_COUNT_MASK) > 0)
                    return true;
                if (state.compare_exchange_weak(cur, cur | LIM_HAS_WAITER, std::memory_order_release, std::memory_order_relaxed))
                    return false;
            }
        }
    }

    ptrdiff_t limiter::state_to_limiter_offset(const limiter* self) noexcept {
        static ptrdiff_t offset = reinterpret_cast<const char*>(&self->values.state) - reinterpret_cast<const char*>(self);
        return offset;
    }

    limiter* limiter::from_state_addr(void* addr) noexcept {
        return reinterpret_cast<limiter*>(reinterpret_cast<char*>(addr) - state_to_limiter_offset());
    }

    limiter::limiter() : values{.lock_check = {}, .lock_check_lock = {}, .state = 1, .max_threshold = 1} {
        (void)state_to_limiter_offset(this);
        FT_DEBUG_ONLY(register_object(this));
    }

    limiter::~limiter() {
        FT_DEBUG_ONLY(unregister_object(this));
        bool has_holders = false;
        {
            fast_task::lock_guard guard(values.lock_check_lock);
            has_holders = values.lock_check.count > 0;
        }
        if (has_holders || (values.state.load(std::memory_order_relaxed) & LIM_COUNT_MASK) < values.max_threshold.load(std::memory_order_relaxed)) {
            assert(false && "Tried to destroy locked limiter");
            std::terminate();
        }
    }

    void limiter::check_deadlock(size_t lock_id) {
        bool is_reentrant = false;
        std::exception_ptr push_ex;
        {
            fast_task::lock_guard guard(values.lock_check_lock);
            if (values.lock_check.find(lock_id) != holder_set::npos) {
                is_reentrant = true;
            } else {
                try {
                    values.lock_check.push(lock_id);
                } catch (...) {
                    push_ex = std::current_exception();
                }
            }
        }
        if (is_reentrant) {
            unchecked_unlock();
            throw std::logic_error("Dead lock. task try lock already locked task limiter");
        }
        if (push_ex) {
            unchecked_unlock();
            std::rethrow_exception(push_ex);
        }
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
            if ((expected & LIM_HAS_WAITER) == 0)
                return;
            size_t waiters = futex::wait_items_on(&values.state);
            limiter_wake_some(values.state, std::min(added, waiters));
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

    bool limiter::try_lock_until(fast_task::time_point time_point) {
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
            size_t index = values.lock_check.find(lock_id);
            if (index == holder_set::npos)
                throw std::logic_error("Invalid unlock. task try unlock already unlocked task limiter");
            values.lock_check.erase(index);
        }
        unchecked_unlock();
    }

    void limiter::unchecked_unlock() {
        size_t max = values.max_threshold.load(std::memory_order_relaxed);
        size_t cached = values.state.load(std::memory_order_relaxed);
        while (true) {
            if ((cached & LIM_COUNT_MASK) >= max)
                return;
            if (values.state.compare_exchange_weak(cached, cached + 1, std::memory_order_release, std::memory_order_relaxed))
                break;
        }

        if ((cached & LIM_HAS_WAITER) == 0)
            return;

        limiter_wake_some(values.state, 1);
    }

    bool limiter::is_locked() {
        return (values.state.load(std::memory_order_relaxed) & LIM_COUNT_MASK) == 0;
    }

    bool limiter::enter_wait(const task& task, enter_state& state) {
        interrupt_unsafe_region region;
        auto lock_cb = [](void* addr, const fast_task::task& t, futex::node_data) {
            auto& st = *reinterpret_cast<std::atomic_size_t*>(addr);
            size_t cur = st.load(std::memory_order_relaxed);
            bool try_only = g_lim_enter_lock_ctx.active;
            if (try_only)
                g_lim_enter_lock_ctx.called = true;
            while (true) {
                if ((cur & LIM_COUNT_MASK) > 0) {
                    if (st.compare_exchange_weak(cur, cur - 1, std::memory_order_acquire, std::memory_order_relaxed)) {
                        limiter::from_state_addr(addr)->check_deadlock(t.get_id());
                        if (try_only)
                            g_lim_enter_lock_ctx.acquired = true;
                        return;
                    }
                    continue;
                }
                if (try_only) {
                    g_lim_enter_lock_ctx.acquired = false;
                    return;
                }
                std::this_thread::yield();
                cur = st.load(std::memory_order_relaxed);
            }
        };

        while (true) {
            size_t expected = values.state.load(std::memory_order_relaxed);
            while ((expected & LIM_COUNT_MASK) > 0) {
                if (values.state.compare_exchange_weak(expected, expected - 1, std::memory_order_acquire, std::memory_order_relaxed)) {
                    check_deadlock(task.get_id());
                    return true;
                }
            }
            bool immediate = false;
            bool called = false;
            bool acquired = false;
            {
                lim_enter_lock_scope scope(g_lim_enter_lock_ctx);
                immediate = futex::enter_wait_on_address_lock(
                    task,
                    &values.state,
                    &lim_enter_check_callback,
                    lock_cb,
                    state
                );
                called = g_lim_enter_lock_ctx.called;
                acquired = g_lim_enter_lock_ctx.acquired;
            }
            if (!immediate)
                return false;
            if (!called || acquired)
                return true;
        }
    }

    bool limiter::enter_wait_until(const task& task, enter_state& state, fast_task::time_point time_point) {
        interrupt_unsafe_region region;
        get_data(task).set_time_end(false);
        auto lock_cb = [](void* addr, const fast_task::task& t, futex::node_data) {
            auto& st = *reinterpret_cast<std::atomic_size_t*>(addr);
            size_t cur = st.load(std::memory_order_relaxed);
            bool try_only = g_lim_enter_lock_ctx.active;
            if (try_only)
                g_lim_enter_lock_ctx.called = true;
            while (true) {
                if ((cur & LIM_COUNT_MASK) > 0) {
                    if (st.compare_exchange_weak(cur, cur - 1, std::memory_order_acquire, std::memory_order_relaxed)) {
                        limiter::from_state_addr(addr)->check_deadlock(t.get_id());
                        if (try_only)
                            g_lim_enter_lock_ctx.acquired = true;
                        return;
                    }
                    continue;
                }
                if (try_only) {
                    g_lim_enter_lock_ctx.acquired = false;
                    return;
                }
                std::this_thread::yield();
                cur = st.load(std::memory_order_relaxed);
            }
        };

        while (true) {
            size_t expected = values.state.load(std::memory_order_relaxed);
            while ((expected & LIM_COUNT_MASK) > 0) {
                if (values.state.compare_exchange_weak(expected, expected - 1, std::memory_order_acquire, std::memory_order_relaxed)) {
                    check_deadlock(task.get_id());
                    return true;
                }
            }
            bool immediate = false;
            bool called = false;
            bool acquired = false;
            {
                lim_enter_lock_scope scope(g_lim_enter_lock_ctx);
                immediate = futex::enter_wait_on_address_lock_until(
                    task,
                    &values.state,
                    &lim_enter_check_callback,
                    lock_cb,
                    state,
                    time_point
                );
                called = g_lim_enter_lock_ctx.called;
                acquired = g_lim_enter_lock_ctx.acquired;
            }
            if (!immediate)
                return false;
            if (!called || acquired)
                return true;
        }
    }
}
