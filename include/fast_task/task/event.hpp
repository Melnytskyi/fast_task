// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_INCLUDE_TASK_EVENT
#define FAST_TASK_INCLUDE_TASK_EVENT

#include "../clock.hpp"
#include "../internal/futex.hpp"
#include "enter_state.hpp"
#include "task.hpp"
#include <atomic>
#include <cstdint>

#if __cplusplus >= 202002 || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002)
    #include "../coroutine/core.hpp"
    #include <concepts>
    #include <coroutine>
#endif

namespace fast_task {
    namespace detail {
        inline constexpr uint8_t event_set_bit = 1u << 0;
        inline constexpr uint8_t event_waiter_bit = 1u << 1;

        inline void event_release_waiter_bit(void* addr, size_t, bool has_remaining) noexcept {
            auto& st = *reinterpret_cast<std::atomic<uint8_t>*>(addr);
            if (has_remaining)
                st.fetch_or(event_waiter_bit, std::memory_order_release);
            else
                st.fetch_and(static_cast<uint8_t>(~event_waiter_bit), std::memory_order_release);
        }

#if __cplusplus >= 202002 || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002)
        inline task make_event_foreign_bridge_task(void* handle_addr) {
            static task_vtable vt = {
                nullptr,
                nullptr,
                [](void* addr) {
                    std::coroutine_handle<>::from_address(addr).resume();
                },
                nullptr,
                nullptr,
                false
            };
            return task(handle_addr, &vt, false, true);
        }

        template <class Event>
        struct event_wait_awaiter {
            enter_state state;
            Event& ev;

            bool await_ready() noexcept {
                return ev.try_wait();
            }

            template <class Promise>
            bool await_suspend(std::coroutine_handle<Promise> h) {
                if constexpr (std::derived_from<Promise, task_promise_base>) {
                    return !ev.enter_wait(h.promise().task_object, state);
                } else {
                    auto bridge = make_event_foreign_bridge_task(h.address());
                    return !ev.enter_wait(bridge, state);
                }
            }

            void await_resume() noexcept {}
        };

        template <class Event>
        struct event_wait_until_awaiter {
            enter_state state;
            Event& ev;
            fast_task::time_point deadline;
            task task_obj;
            bool acquired = false;

            bool await_ready() noexcept {
                if (ev.try_wait()) {
                    acquired = true;
                    return true;
                }
                if (fast_task::is_no_deadline(deadline) || fast_task::clock::now() >= deadline) {
                    acquired = false;
                    return true;
                }
                return false;
            }

            template <class Promise>
            bool await_suspend(std::coroutine_handle<Promise> h) {
                if constexpr (std::derived_from<Promise, task_promise_base>) {
                    task_obj = h.promise().task_object;
                } else {
                    task_obj = make_event_foreign_bridge_task(h.address());
                }
                if (ev.enter_wait_until(task_obj, state, deadline)) {
                    acquired = !task_obj.has_wait_timed_out();
                    return false;
                }
                return true;
            }

            bool await_resume() noexcept {
                if (acquired)
                    return true;
                return !task_obj || !task_obj.has_wait_timed_out();
            }
        };
#endif
    }

    // 1-byte futex-backed manual-reset event.
    // Once set(), stays signaled and wakes all waiters until reset().
    class manual_reset_event {
        std::atomic<uint8_t> state_;

        static bool check_set(void* addr) noexcept {
            auto& st = *reinterpret_cast<std::atomic<uint8_t>*>(addr);
            uint8_t cur = st.load(std::memory_order_relaxed);
            for (;;) {
                if ((cur & detail::event_set_bit) != 0)
                    return true;
                if (st.compare_exchange_weak(
                        cur,
                        static_cast<uint8_t>(cur | detail::event_waiter_bit),
                        std::memory_order_acq_rel,
                        std::memory_order_relaxed
                    ))
                    return false;
            }
        }

    public:
        explicit manual_reset_event(bool initially_set = false) noexcept
            : state_(initially_set ? detail::event_set_bit : 0) {}

        manual_reset_event(const manual_reset_event&) = delete;
        manual_reset_event& operator=(const manual_reset_event&) = delete;
        manual_reset_event(manual_reset_event&&) = delete;
        manual_reset_event& operator=(manual_reset_event&&) = delete;

        bool is_set() const noexcept {
            return (state_.load(std::memory_order_acquire) & detail::event_set_bit) != 0;
        }

        bool try_wait() const noexcept {
            return is_set();
        }

        void set() noexcept {
            uint8_t prev = state_.fetch_or(detail::event_set_bit, std::memory_order_acq_rel);
            if ((prev & detail::event_waiter_bit) != 0)
                futex::wake_on_address(&state_, detail::event_release_waiter_bit, SIZE_MAX);
        }

        void reset() noexcept {
            state_.fetch_and(static_cast<uint8_t>(~detail::event_set_bit), std::memory_order_release);
        }

        void wait() {
            while (!is_set())
                futex::wait_on_address(&state_, &check_set);
        }

        bool wait_until(fast_task::time_point time_point) {
            if (is_set())
                return true;
            while (!is_set()) {
                if (!futex::wait_on_address_until(&state_, &check_set, time_point))
                    return is_set();
            }
            return true;
        }

        template <class Rep, class Period>
        bool wait_for(const std::chrono::duration<Rep, Period>& duration) {
            return wait_until(fast_task::deadline_after(duration));
        }

        bool enter_wait(const task& t, enter_state& state) {
            if (is_set())
                return true;
            return futex::enter_wait_on_address(t, &state_, &check_set, state);
        }

        bool enter_wait_until(const task& t, enter_state& state, fast_task::time_point time_point) {
            if (is_set())
                return true;
            return futex::enter_wait_on_address_until(t, &state_, &check_set, state, time_point);
        }

#if __cplusplus >= 202002 || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002)
        [[nodiscard]] auto async_wait() {
            return detail::event_wait_awaiter<manual_reset_event>{{}, *this};
        }

        [[nodiscard]] auto async_wait_until(fast_task::time_point time_point) {
            return detail::event_wait_until_awaiter<manual_reset_event>{{}, *this, time_point, {}};
        }

        template <class Rep, class Period>
        [[nodiscard]] auto async_wait_for(const std::chrono::duration<Rep, Period>& duration) {
            return async_wait_until(fast_task::deadline_after(duration));
        }
#endif
    };

    // 1-byte futex-backed auto-reset event.
    // set() wakes at most one waiter and atomically resets to unsignaled.
    class auto_reset_event {
        std::atomic<uint8_t> state_;

        static bool check_set(void* addr) noexcept {
            auto& st = *reinterpret_cast<std::atomic<uint8_t>*>(addr);
            uint8_t cur = st.load(std::memory_order_relaxed);
            for (;;) {
                if ((cur & detail::event_set_bit) != 0)
                    return true;
                if (st.compare_exchange_weak(
                        cur,
                        static_cast<uint8_t>(cur | detail::event_waiter_bit),
                        std::memory_order_acq_rel,
                        std::memory_order_relaxed
                    ))
                    return false;
            }
        }

        static bool claim_set(void* addr, const task&, futex::node_data) noexcept {
            auto& st = *reinterpret_cast<std::atomic<uint8_t>*>(addr);
            uint8_t cur = st.load(std::memory_order_relaxed);
            while ((cur & detail::event_set_bit) != 0) {
                if (st.compare_exchange_weak(
                        cur,
                        static_cast<uint8_t>(cur & ~detail::event_set_bit),
                        std::memory_order_acq_rel,
                        std::memory_order_relaxed
                    ))
                    return true;
            }
            return false;
        }

    public:
        explicit auto_reset_event(bool initially_set = false) noexcept
            : state_(initially_set ? detail::event_set_bit : 0) {}

        auto_reset_event(const auto_reset_event&) = delete;
        auto_reset_event& operator=(const auto_reset_event&) = delete;
        auto_reset_event(auto_reset_event&&) = delete;
        auto_reset_event& operator=(auto_reset_event&&) = delete;

        bool is_set() const noexcept {
            return (state_.load(std::memory_order_acquire) & detail::event_set_bit) != 0;
        }

        bool try_wait() noexcept {
            uint8_t cur = state_.load(std::memory_order_relaxed);
            while ((cur & detail::event_set_bit) != 0) {
                if (state_.compare_exchange_weak(
                        cur,
                        static_cast<uint8_t>(cur & ~detail::event_set_bit),
                        std::memory_order_acq_rel,
                        std::memory_order_relaxed
                    ))
                    return true;
            }
            return false;
        }

        void set() noexcept {
            uint8_t prev = state_.fetch_or(detail::event_set_bit, std::memory_order_acq_rel);
            if ((prev & detail::event_waiter_bit) != 0)
                futex::wake_on_address(&state_, detail::event_release_waiter_bit, 1);
        }

        void reset() noexcept {
            state_.fetch_and(static_cast<uint8_t>(~detail::event_set_bit), std::memory_order_release);
        }

        void wait() {
            while (!try_wait())
                futex::wait_on_address(&state_, &check_set);
        }

        bool wait_until(fast_task::time_point time_point) {
            if (try_wait())
                return true;
            while (!try_wait()) {
                if (!futex::wait_on_address_until(&state_, &check_set, time_point))
                    return try_wait();
            }
            return true;
        }

        template <class Rep, class Period>
        bool wait_for(const std::chrono::duration<Rep, Period>& duration) {
            return wait_until(fast_task::deadline_after(duration));
        }

        bool enter_wait(const task& t, enter_state& state) {
            if (try_wait())
                return true;
            return futex::enter_wait_on_address_lock(t, &state_, &check_set, &claim_set, state);
        }

        bool enter_wait_until(const task& t, enter_state& state, fast_task::time_point time_point) {
            if (try_wait())
                return true;
            return futex::enter_wait_on_address_lock_until(t, &state_, &check_set, &claim_set, state, time_point);
        }

#if __cplusplus >= 202002 || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002)
        [[nodiscard]] auto async_wait() {
            return detail::event_wait_awaiter<auto_reset_event>{{}, *this};
        }

        [[nodiscard]] auto async_wait_until(fast_task::time_point time_point) {
            return detail::event_wait_until_awaiter<auto_reset_event>{{}, *this, time_point, {}};
        }

        template <class Rep, class Period>
        [[nodiscard]] auto async_wait_for(const std::chrono::duration<Rep, Period>& duration) {
            return async_wait_until(fast_task::deadline_after(duration));
        }
#endif
    };
}

#endif /* FAST_TASK_INCLUDE_TASK_EVENT */
