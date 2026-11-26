// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_INCLUDE_TASK_CANCELLATION
#define FAST_TASK_INCLUDE_TASK_CANCELLATION

#include "../clock.hpp"
#include "../internal/futex.hpp"
#include "../native/spin_lock.hpp"
#include "enter_state.hpp"
#include "event.hpp"
#include "task.hpp"
#include <atomic>
#include <cstdint>
#include <memory>
#include <thread>
#include <utility>

#if __cplusplus >= 202002 || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002)
    #include "../coroutine/core.hpp"
    #include <concepts>
    #include <coroutine>
#endif

namespace fast_task {
    namespace detail {
        inline constexpr uint8_t cancel_flag_cancelled = 1u << 0;
        inline constexpr uint8_t cancel_flag_waiter = 1u << 1;

        struct cancel_node {
            cancel_node* prev = nullptr;
            cancel_node* next = nullptr;
            void (*invoke)(cancel_node*) noexcept = nullptr;
            std::atomic<bool> running{false};
            bool linked = false;
        };

        struct cancel_state {
            std::atomic<uint8_t> flags{0};
            fast_task::native::spin_lock cb_lock;
            cancel_node* head = nullptr;
            std::atomic<std::thread::id> cancel_tid{};

            static void release_waiter_bit(void* addr, size_t, bool has_remaining) noexcept {
                auto& f = *reinterpret_cast<std::atomic<uint8_t>*>(addr);
                if (has_remaining)
                    f.fetch_or(cancel_flag_waiter, std::memory_order_release);
                else
                    f.fetch_and(static_cast<uint8_t>(~cancel_flag_waiter), std::memory_order_release);
            }

            static bool check_cancelled(void* addr) noexcept {
                auto& f = *reinterpret_cast<std::atomic<uint8_t>*>(addr);
                uint8_t cur = f.load(std::memory_order_acquire);
                for (;;) {
                    if ((cur & cancel_flag_cancelled) != 0)
                        return true;
                    if (f.compare_exchange_weak(
                            cur,
                            static_cast<uint8_t>(cur | cancel_flag_waiter),
                            std::memory_order_acq_rel,
                            std::memory_order_acquire
                        ))
                        return false;
                }
            }

            bool is_cancelled() const noexcept {
                return (flags.load(std::memory_order_acquire) & cancel_flag_cancelled) != 0;
            }

            bool request_cancel() noexcept {
                uint8_t prev = flags.fetch_or(cancel_flag_cancelled, std::memory_order_acq_rel);
                if ((prev & cancel_flag_cancelled) != 0)
                    return false;

                cancel_tid.store(std::this_thread::get_id(), std::memory_order_release);

                if ((prev & cancel_flag_waiter) != 0)
                    futex::wake_on_address(&flags, &release_waiter_bit, SIZE_MAX);

                for (;;) {
                    cancel_node* node = nullptr;
                    {
                        fast_task::lock_guard<fast_task::native::spin_lock> guard(cb_lock);
                        node = head;
                        if (!node)
                            break;
                        head = node->next;
                        if (head)
                            head->prev = nullptr;
                        node->next = nullptr;
                        node->prev = nullptr;
                        node->linked = false;
                        node->running.store(true, std::memory_order_release);
                    }
                    node->invoke(node);
                    node->running.store(false, std::memory_order_release);
                }
                return true;
            }

            bool register_node(cancel_node* node) noexcept {
                {
                    fast_task::lock_guard<fast_task::native::spin_lock> guard(cb_lock);
                    if (is_cancelled())
                        return false;
                    node->prev = nullptr;
                    node->next = head;
                    if (head)
                        head->prev = node;
                    head = node;
                    node->linked = true;
                }
                return true;
            }

            void unregister_node(cancel_node* node) noexcept {
                bool was_linked = false;
                {
                    fast_task::lock_guard<fast_task::native::spin_lock> guard(cb_lock);
                    if (node->linked) {
                        if (node->prev)
                            node->prev->next = node->next;
                        else
                            head = node->next;
                        if (node->next)
                            node->next->prev = node->prev;
                        node->prev = nullptr;
                        node->next = nullptr;
                        node->linked = false;
                        was_linked = true;
                    }
                }
                if (!was_linked && cancel_tid.load(std::memory_order_acquire) != std::this_thread::get_id()) {
                    while (node->running.load(std::memory_order_acquire))
                        std::this_thread::yield();
                }
            }
        };
    }

    class cancellation_source;

    template <class Callback>
    class cancellation_callback;

    class cancellation_token {
        std::shared_ptr<detail::cancel_state> state_;

        friend class cancellation_source;
        template <class Callback>
        friend class cancellation_callback;

        explicit cancellation_token(std::shared_ptr<detail::cancel_state> st) noexcept
            : state_(std::move(st)) {}

    public:
        cancellation_token() noexcept = default;

        static cancellation_token none() noexcept {
            return cancellation_token{};
        }

        bool can_be_cancelled() const noexcept {
            return state_ != nullptr;
        }

        bool is_cancelled() const noexcept {
            return state_ && state_->is_cancelled();
        }

        bool try_wait() const noexcept {
            return is_cancelled();
        }

        void wait() const {
            if (!state_)
                return;
            while (!state_->is_cancelled())
                futex::wait_on_address(&state_->flags, &detail::cancel_state::check_cancelled);
        }

        bool wait_until(fast_task::time_point time_point) const {
            if (!state_)
                return false;
            if (state_->is_cancelled())
                return true;
            while (!state_->is_cancelled()) {
                if (!futex::wait_on_address_until(&state_->flags, &detail::cancel_state::check_cancelled, time_point))
                    return state_->is_cancelled();
            }
            return true;
        }

        template <class Rep, class Period>
        bool wait_for(const std::chrono::duration<Rep, Period>& duration) const {
            return wait_until(fast_task::deadline_after(duration));
        }

        bool enter_wait(const task& t, enter_state& state) const {
            if (!state_ || state_->is_cancelled())
                return true;
            return futex::enter_wait_on_address(t, &state_->flags, &detail::cancel_state::check_cancelled, state);
        }

        bool enter_wait_until(const task& t, enter_state& state, fast_task::time_point time_point) const {
            if (!state_ || state_->is_cancelled())
                return true;
            return futex::enter_wait_on_address_until(t, &state_->flags, &detail::cancel_state::check_cancelled, state, time_point);
        }

#if __cplusplus >= 202002 || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002)
        [[nodiscard]] auto async_wait() const {
            return detail::event_wait_awaiter<const cancellation_token>{{}, *this};
        }

        [[nodiscard]] auto async_wait_until(fast_task::time_point time_point) const {
            return detail::event_wait_until_awaiter<const cancellation_token>{{}, *this, time_point, {}};
        }

        template <class Rep, class Period>
        [[nodiscard]] auto async_wait_for(const std::chrono::duration<Rep, Period>& duration) const {
            return async_wait_until(fast_task::deadline_after(duration));
        }
#endif
    };

    // Intrusive zero-allocation cancellation callback.
    // Automatically unregisters in destructor (waiting if currently executing on another thread).
    template <class Callback>
    class cancellation_callback {
        struct node_with_cb : detail::cancel_node {
            Callback cb;

            template <class Fn>
            explicit node_with_cb(Fn&& fn)
                : cb(std::forward<Fn>(fn)) {
                this->invoke = [](detail::cancel_node* base) noexcept {
                    static_cast<node_with_cb*>(base)->cb();
                };
            }
        };

        std::shared_ptr<detail::cancel_state> state_;
        node_with_cb node_;

    public:
        template <class Fn>
        cancellation_callback(const cancellation_token& token, Fn&& fn)
            : state_(token.state_), node_(std::forward<Fn>(fn)) {
            if (state_) {
                if (!state_->register_node(&node_)) {
                    state_.reset();
                    node_.cb();
                }
            }
        }

        cancellation_callback(const cancellation_callback&) = delete;
        cancellation_callback& operator=(const cancellation_callback&) = delete;
        cancellation_callback(cancellation_callback&&) = delete;
        cancellation_callback& operator=(cancellation_callback&&) = delete;

        ~cancellation_callback() noexcept {
            if (state_)
                state_->unregister_node(&node_);
        }
    };

    template <class Fn>
    cancellation_callback(const cancellation_token&, Fn&&) -> cancellation_callback<std::decay_t<Fn>>;

    class cancellation_source {
        struct parent_link_node : detail::cancel_node {
            std::weak_ptr<detail::cancel_state> child;

            explicit parent_link_node(std::shared_ptr<detail::cancel_state> c)
                : child(std::move(c)) {
                this->invoke = [](detail::cancel_node* base) noexcept {
                    if (auto st = static_cast<parent_link_node*>(base)->child.lock())
                        st->request_cancel();
                };
            }
        };

        std::shared_ptr<detail::cancel_state> state_;
        std::shared_ptr<detail::cancel_state> parent_state_;
        std::unique_ptr<parent_link_node> parent_node_;

    public:
        cancellation_source()
            : state_(std::make_shared<detail::cancel_state>()) {}

        // Linked child source: cancelling parent automatically cancels this source.
        explicit cancellation_source(const cancellation_token& parent)
            : state_(std::make_shared<detail::cancel_state>()), parent_state_(parent.state_) {
            if (parent_state_) {
                parent_node_ = std::make_unique<parent_link_node>(state_);
                if (!parent_state_->register_node(parent_node_.get())) {
                    parent_node_.reset();
                    parent_state_.reset();
                    state_->request_cancel();
                }
            }
        }

        cancellation_source(const cancellation_source&) = delete;
        cancellation_source& operator=(const cancellation_source&) = delete;
        cancellation_source(cancellation_source&&) noexcept = default;
        cancellation_source& operator=(cancellation_source&&) noexcept = default;

        ~cancellation_source() noexcept {
            if (parent_state_ && parent_node_)
                parent_state_->unregister_node(parent_node_.get());
        }

        cancellation_token token() const noexcept {
            return cancellation_token(state_);
        }

        bool is_cancelled() const noexcept {
            return state_ && state_->is_cancelled();
        }

        bool cancel() noexcept {
            return state_ && state_->request_cancel();
        }
    };
}

#endif /* FAST_TASK_INCLUDE_TASK_CANCELLATION */
