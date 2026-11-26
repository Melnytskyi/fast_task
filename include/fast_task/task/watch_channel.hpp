// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_INCLUDE_TASK_WATCH_CHANNEL
#define FAST_TASK_INCLUDE_TASK_WATCH_CHANNEL

#include "../clock.hpp"
#include "../internal/futex.hpp"
#include "../native/spin_lock.hpp"
#include "enter_state.hpp"
#include "event.hpp"
#include "mutex.hpp"
#include "task.hpp"
#include <atomic>
#include <cstdint>
#include <memory>
#include <type_traits>
#include <utility>

#if __cplusplus >= 202002 || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002)
    #include "../coroutine/core.hpp"
    #include <concepts>
    #include <coroutine>
#endif

namespace fast_task {
    namespace detail {
        inline constexpr uint64_t watch_closed_bit = 1ull << 0;
        inline constexpr uint64_t watch_waiter_bit = 1ull << 1;
        inline constexpr uint64_t watch_version_shift = 2;
        inline constexpr uint64_t watch_version_inc = 1ull << watch_version_shift;

        inline thread_local uint64_t g_watch_seen_version = 0;

        inline void watch_release_waiter_bit(void* addr, size_t, bool has_remaining) noexcept {
            auto& ver = *reinterpret_cast<std::atomic<uint64_t>*>(addr);
            if (has_remaining)
                ver.fetch_or(watch_waiter_bit, std::memory_order_release);
            else
                ver.fetch_and(~watch_waiter_bit, std::memory_order_release);
        }

        inline bool watch_check_changed(void* addr) noexcept {
            auto& ver = *reinterpret_cast<std::atomic<uint64_t>*>(addr);
            uint64_t cur = ver.load(std::memory_order_acquire);
            for (;;) {
                if ((cur & watch_closed_bit) != 0 || (cur >> watch_version_shift) != g_watch_seen_version)
                    return true;
                if (ver.compare_exchange_weak(
                        cur, cur | watch_waiter_bit, std::memory_order_acq_rel, std::memory_order_acquire
                    ))
                    return false;
            }
        }

        template <class T>
        struct watch_state {
            using lock_t = std::conditional_t<
                std::is_nothrow_copy_constructible_v<T> && std::is_nothrow_move_constructible_v<T>,
                fast_task::native::spin_lock,
                fast_task::mutex>;

            mutable lock_t lock;
            T value;
            alignas(64) std::atomic<uint64_t> version{watch_version_inc};

            template <class... Args>
            explicit watch_state(Args&&... args)
                : value(std::forward<Args>(args)...) {}
        };
    }

    template <class T>
    class watch_channel;

    // Lightweight subscriber handle (8-byte version cursor; zero per-subscriber queue).
    template <class T>
    class watch_receiver {
        std::shared_ptr<detail::watch_state<T>> state_;
        uint64_t seen_version_ = 0;

        friend class watch_channel<T>;

        explicit watch_receiver(std::shared_ptr<detail::watch_state<T>> st) noexcept
            : state_(std::move(st)),
              seen_version_(state_ ? (state_->version.load(std::memory_order_acquire) >> detail::watch_version_shift) : 0) {}

    public:
        watch_receiver() noexcept = default;

        T borrow_copy() const {
            fast_task::lock_guard<typename detail::watch_state<T>::lock_t> guard(state_->lock);
            return state_->value;
        }

        T borrow_and_mark_seen() {
            fast_task::lock_guard<typename detail::watch_state<T>::lock_t> guard(state_->lock);
            seen_version_ = state_->version.load(std::memory_order_acquire) >> detail::watch_version_shift;
            return state_->value;
        }

        bool has_changed() const noexcept {
            if (!state_)
                return false;
            return (state_->version.load(std::memory_order_acquire) >> detail::watch_version_shift) != seen_version_;
        }

        bool is_closed() const noexcept {
            return !state_ || (state_->version.load(std::memory_order_acquire) & detail::watch_closed_bit) != 0;
        }

        // Waits until a newer version is published (returns true) or channel is closed (returns false).
        bool changed() {
            if (!state_)
                return false;
            for (;;) {
                uint64_t raw = state_->version.load(std::memory_order_acquire);
                uint64_t cur_ver = raw >> detail::watch_version_shift;
                if (cur_ver != seen_version_) {
                    seen_version_ = cur_ver;
                    return true;
                }
                if ((raw & detail::watch_closed_bit) != 0)
                    return false;
                detail::g_watch_seen_version = seen_version_;
                futex::wait_on_address(&state_->version, &detail::watch_check_changed);
            }
        }

        bool changed_until(fast_task::time_point time_point) {
            if (!state_)
                return false;
            for (;;) {
                uint64_t raw = state_->version.load(std::memory_order_acquire);
                uint64_t cur_ver = raw >> detail::watch_version_shift;
                if (cur_ver != seen_version_) {
                    seen_version_ = cur_ver;
                    return true;
                }
                if ((raw & detail::watch_closed_bit) != 0)
                    return false;
                detail::g_watch_seen_version = seen_version_;
                if (!futex::wait_on_address_until(&state_->version, &detail::watch_check_changed, time_point)) {
                    uint64_t after = state_->version.load(std::memory_order_acquire) >> detail::watch_version_shift;
                    if (after != seen_version_) {
                        seen_version_ = after;
                        return true;
                    }
                    return false;
                }
            }
        }

        template <class Rep, class Period>
        bool changed_for(const std::chrono::duration<Rep, Period>& duration) {
            return changed_until(fast_task::deadline_after(duration));
        }

        bool enter_changed(const task& t, enter_state& state) {
            if (!state_)
                return true;
            uint64_t raw = state_->version.load(std::memory_order_acquire);
            if ((raw & detail::watch_closed_bit) != 0 || (raw >> detail::watch_version_shift) != seen_version_)
                return true;
            detail::g_watch_seen_version = seen_version_;
            return futex::enter_wait_on_address(t, &state_->version, &detail::watch_check_changed, state);
        }

        bool enter_changed_until(const task& t, enter_state& state, fast_task::time_point time_point) {
            if (!state_)
                return true;
            uint64_t raw = state_->version.load(std::memory_order_acquire);
            if ((raw & detail::watch_closed_bit) != 0 || (raw >> detail::watch_version_shift) != seen_version_)
                return true;
            detail::g_watch_seen_version = seen_version_;
            return futex::enter_wait_on_address_until(t, &state_->version, &detail::watch_check_changed, state, time_point);
        }

#if __cplusplus >= 202002 || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002)
    private:
        struct changed_awaiter {
            enter_state state;
            watch_receiver& rx;

            bool await_ready() noexcept {
                return !rx.state_ || rx.has_changed() || rx.is_closed();
            }

            template <class Promise>
            bool await_suspend(std::coroutine_handle<Promise> h) {
                if constexpr (std::derived_from<Promise, task_promise_base>) {
                    return !rx.enter_changed(h.promise().task_object, state);
                } else {
                    auto bridge = detail::make_event_foreign_bridge_task(h.address());
                    return !rx.enter_changed(bridge, state);
                }
            }

            bool await_resume() noexcept {
                if (!rx.state_)
                    return false;
                uint64_t raw = rx.state_->version.load(std::memory_order_acquire);
                uint64_t cur_ver = raw >> detail::watch_version_shift;
                if (cur_ver != rx.seen_version_) {
                    rx.seen_version_ = cur_ver;
                    return true;
                }
                return false;
            }
        };

    public:
        [[nodiscard]] auto async_changed() {
            return changed_awaiter{{}, *this};
        }
#endif
    };

    // 1-to-N latest-value broadcast channel.
    // Writers never block on slow subscribers; zero allocations per update.
    template <class T>
    class watch_channel {
        std::shared_ptr<detail::watch_state<T>> state_;

    public:
        template <class... Args>
        explicit watch_channel(Args&&... args)
            : state_(std::make_shared<detail::watch_state<T>>(std::forward<Args>(args)...)) {}

        watch_channel(const watch_channel&) = delete;
        watch_channel& operator=(const watch_channel&) = delete;
        watch_channel(watch_channel&&) noexcept = default;
        watch_channel& operator=(watch_channel&&) noexcept = default;

        ~watch_channel() {
            close();
        }

        watch_receiver<T> subscribe() const noexcept {
            return watch_receiver<T>(state_);
        }

        bool send(const T& value) {
            if (!state_)
                return false;
            uint64_t prev = 0;
            {
                fast_task::lock_guard<typename detail::watch_state<T>::lock_t> guard(state_->lock);
                if ((state_->version.load(std::memory_order_acquire) & detail::watch_closed_bit) != 0)
                    return false;
                state_->value = value;
                prev = state_->version.fetch_add(detail::watch_version_inc, std::memory_order_acq_rel);
            }
            if ((prev & detail::watch_waiter_bit) != 0)
                futex::wake_on_address(&state_->version, &detail::watch_release_waiter_bit, SIZE_MAX);
            return true;
        }

        bool send(T&& value) {
            if (!state_)
                return false;
            uint64_t prev = 0;
            {
                fast_task::lock_guard<typename detail::watch_state<T>::lock_t> guard(state_->lock);
                if ((state_->version.load(std::memory_order_acquire) & detail::watch_closed_bit) != 0)
                    return false;
                state_->value = std::move(value);
                prev = state_->version.fetch_add(detail::watch_version_inc, std::memory_order_acq_rel);
            }
            if ((prev & detail::watch_waiter_bit) != 0)
                futex::wake_on_address(&state_->version, &detail::watch_release_waiter_bit, SIZE_MAX);
            return true;
        }

        T borrow_copy() const {
            fast_task::lock_guard<typename detail::watch_state<T>::lock_t> guard(state_->lock);
            return state_->value;
        }

        void close() noexcept {
            if (!state_)
                return;
            uint64_t prev = state_->version.fetch_or(detail::watch_closed_bit, std::memory_order_acq_rel);
            if ((prev & detail::watch_waiter_bit) != 0)
                futex::wake_on_address(&state_->version, &detail::watch_release_waiter_bit, SIZE_MAX);
        }

        bool is_closed() const noexcept {
            return !state_ || (state_->version.load(std::memory_order_acquire) & detail::watch_closed_bit) != 0;
        }
    };
}

#endif /* FAST_TASK_INCLUDE_TASK_WATCH_CHANNEL */
