// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_INCLUDE_TASK_ONESHOT
#define FAST_TASK_INCLUDE_TASK_ONESHOT

#include "../clock.hpp"
#include "../internal/futex.hpp"
#include "enter_state.hpp"
#include "event.hpp"
#include "task.hpp"
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <new>
#include <optional>
#include <stdexcept>
#include <utility>

#if __cplusplus >= 202002 || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002)
    #include "../coroutine/core.hpp"
    #include <concepts>
    #include <coroutine>
#endif

namespace fast_task {
    // Lock-free single-use one-shot value channel.
    // Can be stack-embedded (0 heap allocations) or shared via make_oneshot<T>().
    template <class T>
    class oneshot {
        static constexpr uint8_t STATUS_MASK = 0x07;
        static constexpr uint8_t WAITER_BIT = 0x80;

        static constexpr uint8_t OS_EMPTY = 0;
        static constexpr uint8_t OS_WRITING = 1;
        static constexpr uint8_t OS_VALUE = 2;
        static constexpr uint8_t OS_ERROR = 3;
        static constexpr uint8_t OS_CLOSED = 4;

        std::atomic<uint8_t> state_{OS_EMPTY};
        union {
            alignas(T) std::byte storage_[sizeof(T)];
            std::exception_ptr ex_;
        };
        bool consumed_ = false;

        T* val_ptr() noexcept {
            return std::launder(reinterpret_cast<T*>(storage_));
        }

        static bool check_ready(void* addr) noexcept {
            auto& st = *reinterpret_cast<std::atomic<uint8_t>*>(addr);
            uint8_t prev = st.fetch_or(WAITER_BIT, std::memory_order_acq_rel);
            return (prev & STATUS_MASK) >= OS_VALUE;
        }

        bool claim_write() noexcept {
            uint8_t cur = state_.load(std::memory_order_relaxed);
            while ((cur & STATUS_MASK) == OS_EMPTY) {
                if (state_.compare_exchange_weak(
                        cur,
                        static_cast<uint8_t>((cur & WAITER_BIT) | OS_WRITING),
                        std::memory_order_acq_rel,
                        std::memory_order_relaxed
                    ))
                    return true;
            }
            return false;
        }

        void publish(uint8_t status) noexcept {
            uint8_t prev = state_.exchange(status, std::memory_order_acq_rel);
            if ((prev & WAITER_BIT) != 0)
                futex::wake_on_address(&state_, SIZE_MAX);
        }

    public:
        oneshot() noexcept {}

        oneshot(const oneshot&) = delete;
        oneshot& operator=(const oneshot&) = delete;
        oneshot(oneshot&&) = delete;
        oneshot& operator=(oneshot&&) = delete;

        ~oneshot() noexcept {
            const uint8_t st = state_.load(std::memory_order_acquire) & STATUS_MASK;
            if (st == OS_VALUE && !consumed_) {
                std::destroy_at(val_ptr());
            } else if (st == OS_ERROR) {
                std::destroy_at(&ex_);
            }
        }

        bool is_ready() const noexcept {
            return (state_.load(std::memory_order_acquire) & STATUS_MASK) >= OS_VALUE;
        }

        template <class... Args>
        bool set_value(Args&&... args) {
            if (!claim_write())
                return false;
            try {
                ::new (static_cast<void*>(storage_)) T(std::forward<Args>(args)...);
            } catch (...) {
                ::new (static_cast<void*>(&ex_)) std::exception_ptr(std::current_exception());
                publish(OS_ERROR);
                return true;
            }
            publish(OS_VALUE);
            return true;
        }

        bool set_exception(std::exception_ptr ex) noexcept {
            if (!claim_write())
                return false;
            ::new (static_cast<void*>(&ex_)) std::exception_ptr(std::move(ex));
            publish(OS_ERROR);
            return true;
        }

        void close() noexcept {
            if (!claim_write())
                return;
            publish(OS_CLOSED);
        }

        std::optional<T> try_recv() {
            const uint8_t st = state_.load(std::memory_order_acquire) & STATUS_MASK;
            if (st < OS_VALUE)
                return std::nullopt;
            if (st == OS_ERROR)
                std::rethrow_exception(ex_);
            if (st == OS_CLOSED || consumed_)
                return std::nullopt;
            consumed_ = true;
            std::optional<T> res(std::move(*val_ptr()));
            std::destroy_at(val_ptr());
            return res;
        }

        void wait() {
            while (!is_ready())
                futex::wait_on_address(&state_, &check_ready);
        }

        bool wait_until(fast_task::time_point time_point) {
            while (!is_ready()) {
                if (!futex::wait_on_address_until(&state_, &check_ready, time_point))
                    return is_ready();
            }
            return true;
        }

        template <class Rep, class Period>
        bool wait_for(const std::chrono::duration<Rep, Period>& duration) {
            return wait_until(fast_task::deadline_after(duration));
        }

        std::optional<T> recv() {
            wait();
            return try_recv();
        }

        std::optional<T> recv_until(fast_task::time_point time_point) {
            if (!wait_until(time_point))
                return std::nullopt;
            return try_recv();
        }

        template <class Rep, class Period>
        std::optional<T> recv_for(const std::chrono::duration<Rep, Period>& duration) {
            return recv_until(fast_task::deadline_after(duration));
        }

        T get() {
            auto res = recv();
            if (!res.has_value())
                throw std::runtime_error("fast_task::oneshot closed without value");
            return std::move(*res);
        }

        bool enter_wait(const task& t, enter_state& state) {
            if (is_ready())
                return true;
            return futex::enter_wait_on_address(t, &state_, &check_ready, state);
        }

        bool enter_wait_until(const task& t, enter_state& state, fast_task::time_point time_point) {
            if (is_ready())
                return true;
            return futex::enter_wait_on_address_until(t, &state_, &check_ready, state, time_point);
        }

#if __cplusplus >= 202002 || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002)
    private:
        struct recv_awaiter {
            enter_state state;
            oneshot& os;

            bool await_ready() noexcept {
                return os.is_ready();
            }

            template <class Promise>
            bool await_suspend(std::coroutine_handle<Promise> h) {
                if constexpr (std::derived_from<Promise, task_promise_base>) {
                    return !os.enter_wait(h.promise().task_object, state);
                } else {
                    auto bridge = detail::make_event_foreign_bridge_task(h.address());
                    return !os.enter_wait(bridge, state);
                }
            }

            std::optional<T> await_resume() {
                return os.try_recv();
            }
        };

        struct get_awaiter {
            enter_state state;
            oneshot& os;

            bool await_ready() noexcept {
                return os.is_ready();
            }

            template <class Promise>
            bool await_suspend(std::coroutine_handle<Promise> h) {
                if constexpr (std::derived_from<Promise, task_promise_base>) {
                    return !os.enter_wait(h.promise().task_object, state);
                } else {
                    auto bridge = detail::make_event_foreign_bridge_task(h.address());
                    return !os.enter_wait(bridge, state);
                }
            }

            T await_resume() {
                auto res = os.try_recv();
                if (!res.has_value())
                    throw std::runtime_error("fast_task::oneshot closed without value");
                return std::move(*res);
            }
        };

    public:
        [[nodiscard]] auto async_recv() {
            return recv_awaiter{{}, *this};
        }

        [[nodiscard]] auto async_get() {
            return get_awaiter{{}, *this};
        }
#endif
    };

    template <class T>
    class oneshot_sender {
        std::shared_ptr<oneshot<T>> state_;

    public:
        oneshot_sender() noexcept = default;
        explicit oneshot_sender(std::shared_ptr<oneshot<T>> st) noexcept : state_(std::move(st)) {}

        oneshot_sender(const oneshot_sender&) = delete;
        oneshot_sender& operator=(const oneshot_sender&) = delete;

        oneshot_sender(oneshot_sender&& other) noexcept = default;
        oneshot_sender& operator=(oneshot_sender&& other) noexcept {
            if (this != &other) {
                if (state_)
                    state_->close();
                state_ = std::move(other.state_);
            }
            return *this;
        }

        ~oneshot_sender() noexcept {
            if (state_)
                state_->close();
        }

        template <class... Args>
        bool send(Args&&... args) {
            if (!state_)
                return false;
            auto s = std::move(state_);
            return s->set_value(std::forward<Args>(args)...);
        }

        bool set_exception(std::exception_ptr ex) noexcept {
            if (!state_)
                return false;
            auto s = std::move(state_);
            return s->set_exception(std::move(ex));
        }

        void close() noexcept {
            if (state_) {
                auto s = std::move(state_);
                s->close();
            }
        }
    };

    template <class T>
    class oneshot_receiver {
        std::shared_ptr<oneshot<T>> state_;

    public:
        oneshot_receiver() noexcept = default;
        explicit oneshot_receiver(std::shared_ptr<oneshot<T>> st) noexcept : state_(std::move(st)) {}

        oneshot_receiver(const oneshot_receiver&) = delete;
        oneshot_receiver& operator=(const oneshot_receiver&) = delete;
        oneshot_receiver(oneshot_receiver&&) noexcept = default;
        oneshot_receiver& operator=(oneshot_receiver&&) noexcept = default;

        bool is_ready() const noexcept {
            return state_ && state_->is_ready();
        }

        std::optional<T> try_recv() {
            return state_ ? state_->try_recv() : std::nullopt;
        }

        std::optional<T> recv() {
            return state_ ? state_->recv() : std::nullopt;
        }

        std::optional<T> recv_until(fast_task::time_point tp) {
            return state_ ? state_->recv_until(tp) : std::nullopt;
        }

        template <class Rep, class Period>
        std::optional<T> recv_for(const std::chrono::duration<Rep, Period>& dur) {
            return state_ ? state_->recv_for(dur) : std::nullopt;
        }

        T get() {
            if (!state_)
                throw std::runtime_error("fast_task::oneshot_receiver is empty");
            return state_->get();
        }

        bool enter_wait(const task& t, enter_state& s) {
            return !state_ || state_->enter_wait(t, s);
        }

        bool enter_wait_until(const task& t, enter_state& s, fast_task::time_point tp) {
            return !state_ || state_->enter_wait_until(t, s, tp);
        }

#if __cplusplus >= 202002 || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002)
        [[nodiscard]] auto async_recv() {
            return state_->async_recv();
        }

        [[nodiscard]] auto async_get() {
            return state_->async_get();
        }
#endif
    };

    template <class T>
    [[nodiscard]] std::pair<oneshot_sender<T>, oneshot_receiver<T>> make_oneshot() {
        auto st = std::make_shared<oneshot<T>>();
        return {oneshot_sender<T>(st), oneshot_receiver<T>(std::move(st))};
    }
}

#endif /* FAST_TASK_INCLUDE_TASK_ONESHOT */
