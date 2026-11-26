// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_INCLUDE_TASK_SPSC_CHANNEL
#define FAST_TASK_INCLUDE_TASK_SPSC_CHANNEL

#include "../clock.hpp"
#include "../internal/futex.hpp"
#include "channel.hpp"
#include "enter_state.hpp"
#include "task.hpp"
#include <atomic>
#include <bit>
#include <cstddef>
#include <cstdint>
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
    // Wait-free Single-Producer / Single-Consumer bounded ring buffer channel.
    // Fast path uses zero atomic RMWs (load/store with cached remote indices).
    // Slow path (empty/full) parks via fast_task::futex and supports enter_* & foreign coroutines.
    template <class T>
    class spsc_channel {
        struct slot_t {
            alignas(T) std::byte storage[sizeof(T)];

            T* ptr() noexcept {
                return std::launder(reinterpret_cast<T*>(storage));
            }
        };

        struct alignas(64) futex_word {
            std::atomic<uint64_t> bits{0};
            spsc_channel* owner = nullptr;
        };

        size_t capacity_;
        size_t mask_;
        std::unique_ptr<slot_t[]> slots_;

        alignas(64) std::atomic<size_t> head_{0};
        size_t cached_tail_ = 0;

        alignas(64) std::atomic<size_t> tail_{0};
        size_t cached_head_ = 0;

        futex_word recv_futex_;
        futex_word send_futex_;

        bool has_item() const noexcept {
            return head_.load(std::memory_order_acquire) != tail_.load(std::memory_order_acquire);
        }

        bool has_space() const noexcept {
            return (head_.load(std::memory_order_acquire) - tail_.load(std::memory_order_acquire)) < capacity_;
        }

        static bool check_recv_ready(void* addr) noexcept {
            auto* fw = reinterpret_cast<futex_word*>(addr);
            uint64_t prev = fw->bits.fetch_or(detail::channel_has_waiter_bit, std::memory_order_seq_cst);
            if ((prev & detail::channel_closed_bit) != 0)
                return true;
            return fw->owner->has_item();
        }

        static bool check_send_ready(void* addr) noexcept {
            auto* fw = reinterpret_cast<futex_word*>(addr);
            uint64_t prev = fw->bits.fetch_or(detail::channel_has_waiter_bit, std::memory_order_seq_cst);
            if ((prev & detail::channel_closed_bit) != 0)
                return true;
            return fw->owner->has_space();
        }

        void wake_receiver() noexcept {
            if ((recv_futex_.bits.load(std::memory_order_acquire) & detail::channel_has_waiter_bit) != 0)
                futex::wake_on_address(&recv_futex_.bits, detail::channel_release_waiter_bit, 1);
        }

        void wake_sender() noexcept {
            if ((send_futex_.bits.load(std::memory_order_acquire) & detail::channel_has_waiter_bit) != 0)
                futex::wake_on_address(&send_futex_.bits, detail::channel_release_waiter_bit, 1);
        }

    public:
        static constexpr bool is_lock_free = true;

        // Capacity is rounded up to the next power of 2 (minimum 2) for single-cycle bitmask indexing.
        explicit spsc_channel(size_t min_capacity) {
            if (min_capacity == 0)
                throw std::invalid_argument("spsc_channel capacity must be >= 1");
            size_t cap = std::bit_ceil(min_capacity < 2 ? size_t(2) : min_capacity);
            capacity_ = cap;
            mask_ = cap - 1;
            slots_ = std::make_unique<slot_t[]>(capacity_);
            recv_futex_.owner = this;
            send_futex_.owner = this;
        }

        spsc_channel(const spsc_channel&) = delete;
        spsc_channel& operator=(const spsc_channel&) = delete;
        spsc_channel(spsc_channel&&) = delete;
        spsc_channel& operator=(spsc_channel&&) = delete;

        ~spsc_channel() {
            close();
            while (try_recv().has_value()) {
            }
        }

        void close() noexcept {
            recv_futex_.bits.fetch_or(detail::channel_closed_bit, std::memory_order_seq_cst);
            send_futex_.bits.fetch_or(detail::channel_closed_bit, std::memory_order_seq_cst);
            futex::wake_on_address(&recv_futex_.bits, detail::channel_release_waiter_bit, SIZE_MAX);
            futex::wake_on_address(&send_futex_.bits, detail::channel_release_waiter_bit, SIZE_MAX);
        }

        bool is_closed() const noexcept {
            return (recv_futex_.bits.load(std::memory_order_acquire) & detail::channel_closed_bit) != 0;
        }

        size_t capacity() const noexcept {
            return capacity_;
        }

        size_t size() const noexcept {
            const size_t h = head_.load(std::memory_order_acquire);
            const size_t t = tail_.load(std::memory_order_acquire);
            return h >= t ? (h - t) : 0;
        }

        bool empty() const noexcept {
            return !has_item();
        }

        template <class... Args>
        bool try_emplace(Args&&... args) {
            if (is_closed())
                return false;
            const size_t h = head_.load(std::memory_order_relaxed);
            if (h - cached_tail_ >= capacity_) {
                cached_tail_ = tail_.load(std::memory_order_acquire);
                if (h - cached_tail_ >= capacity_)
                    return false;
            }
            ::new (static_cast<void*>(slots_[h & mask_].storage)) T(std::forward<Args>(args)...);
            head_.store(h + 1, std::memory_order_release);
            std::atomic_thread_fence(std::memory_order_seq_cst);
            wake_receiver();
            return true;
        }

        bool try_send(const T& value) {
            return try_emplace(value);
        }

        bool try_send(T&& value) {
            return try_emplace(std::move(value));
        }

        bool send(const T& value) {
            if (try_send(value))
                return true;
            while (!is_closed()) {
                futex::wait_on_address(&send_futex_.bits, &check_send_ready);
                if (try_send(value))
                    return true;
            }
            return false;
        }

        bool send(T&& value) {
            if (try_send(std::move(value)))
                return true;
            while (!is_closed()) {
                futex::wait_on_address(&send_futex_.bits, &check_send_ready);
                if (try_send(std::move(value)))
                    return true;
            }
            return false;
        }

        bool send_until(T value, fast_task::time_point time_point) {
            if (try_send(std::move(value)))
                return true;
            while (!is_closed()) {
                if (!futex::wait_on_address_until(&send_futex_.bits, &check_send_ready, time_point))
                    return try_send(std::move(value));
                if (try_send(std::move(value)))
                    return true;
            }
            return false;
        }

        template <class Rep, class Period>
        bool send_for(T value, const std::chrono::duration<Rep, Period>& duration) {
            return send_until(std::move(value), fast_task::deadline_after(duration));
        }

        std::optional<T> try_recv() {
            const size_t t = tail_.load(std::memory_order_relaxed);
            if (t == cached_head_) {
                cached_head_ = head_.load(std::memory_order_acquire);
                if (t == cached_head_)
                    return std::nullopt;
            }
            slot_t& slot = slots_[t & mask_];
            std::optional<T> res(std::move(*slot.ptr()));
            std::destroy_at(slot.ptr());
            tail_.store(t + 1, std::memory_order_release);
            std::atomic_thread_fence(std::memory_order_seq_cst);
            wake_sender();
            return res;
        }

        std::optional<T> recv() {
            if (auto v = try_recv())
                return v;
            for (;;) {
                if (is_closed())
                    return try_recv();
                futex::wait_on_address(&recv_futex_.bits, &check_recv_ready);
                if (auto v = try_recv())
                    return v;
                if (is_closed())
                    return try_recv();
            }
        }

        std::optional<T> recv_until(fast_task::time_point time_point) {
            if (auto v = try_recv())
                return v;
            for (;;) {
                if (is_closed())
                    return try_recv();
                if (!futex::wait_on_address_until(&recv_futex_.bits, &check_recv_ready, time_point))
                    return try_recv();
                if (auto v = try_recv())
                    return v;
                if (is_closed())
                    return try_recv();
            }
        }

        template <class Rep, class Period>
        std::optional<T> recv_for(const std::chrono::duration<Rep, Period>& duration) {
            return recv_until(fast_task::deadline_after(duration));
        }

        bool enter_send(const task& t, enter_state& state) {
            if (has_space() || is_closed())
                return true;
            return futex::enter_wait_on_address(t, &send_futex_.bits, &check_send_ready, state);
        }

        bool enter_send_until(const task& t, enter_state& state, fast_task::time_point time_point) {
            if (has_space() || is_closed())
                return true;
            return futex::enter_wait_on_address_until(t, &send_futex_.bits, &check_send_ready, state, time_point);
        }

        bool enter_recv(const task& t, enter_state& state) {
            if (has_item() || is_closed())
                return true;
            return futex::enter_wait_on_address(t, &recv_futex_.bits, &check_recv_ready, state);
        }

        bool enter_recv_until(const task& t, enter_state& state, fast_task::time_point time_point) {
            if (has_item() || is_closed())
                return true;
            return futex::enter_wait_on_address_until(t, &recv_futex_.bits, &check_recv_ready, state, time_point);
        }

#if __cplusplus >= 202002 || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002)
        [[nodiscard]] auto async_send(T value) {
            return detail::channel_send_awaiter<spsc_channel, T>{{}, *this, std::move(value)};
        }

        [[nodiscard]] auto async_send_until(T value, fast_task::time_point time_point) {
            return detail::channel_send_until_awaiter<spsc_channel, T>{{}, *this, std::move(value), time_point, {}};
        }

        template <class Rep, class Period>
        [[nodiscard]] auto async_send_for(T value, const std::chrono::duration<Rep, Period>& duration) {
            return async_send_until(std::move(value), fast_task::deadline_after(duration));
        }

        [[nodiscard]] auto async_recv() {
            return detail::channel_recv_awaiter<spsc_channel, T>{{}, *this};
        }

        [[nodiscard]] auto async_recv_until(fast_task::time_point time_point) {
            return detail::channel_recv_until_awaiter<spsc_channel, T>{{}, *this, time_point, {}};
        }

        template <class Rep, class Period>
        [[nodiscard]] auto async_recv_for(const std::chrono::duration<Rep, Period>& duration) {
            return async_recv_until(fast_task::deadline_after(duration));
        }
#endif
    };
}

#endif /* FAST_TASK_INCLUDE_TASK_SPSC_CHANNEL */
