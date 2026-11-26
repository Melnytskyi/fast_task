// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_INCLUDE_TASK_CHANNEL
#define FAST_TASK_INCLUDE_TASK_CHANNEL

#include "../clock.hpp"
#include "../internal/futex.hpp"
#include "../native/spin_lock.hpp"
#include "condition_variable.hpp"
#include "enter_state.hpp"
#include "mutex.hpp"
#include "task.hpp"
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <new>
#include <optional>
#include <stdexcept>
#include <type_traits>
#include <utility>
#include <vector>

#if __cplusplus >= 202002 || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002)
    #include "../coroutine/core.hpp"
    #include <concepts>
    #include <coroutine>
#endif

namespace fast_task {
    template <class T>
    inline constexpr bool channel_lock_free_eligible_v =
        std::is_nothrow_move_constructible_v<T> && std::is_nothrow_destructible_v<T>;

    namespace detail {
        inline constexpr uint64_t channel_closed_bit = 1ull << 0;
        inline constexpr uint64_t channel_has_waiter_bit = 1ull << 1;

        inline void channel_release_waiter_bit(void* addr, size_t, bool has_remaining) noexcept {
            auto& bits = *reinterpret_cast<std::atomic<uint64_t>*>(addr);
            if (has_remaining)
                bits.fetch_or(channel_has_waiter_bit, std::memory_order_release);
            else
                bits.fetch_and(~channel_has_waiter_bit, std::memory_order_release);
        }

#if __cplusplus >= 202002 || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002)
        inline task make_foreign_coro_bridge_task(void* handle_addr) {
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

        template <class Channel, class T>
        struct channel_send_awaiter {
            enter_state state;
            Channel& ch;
            T value;
            bool done = false;
            bool result = false;

            bool await_ready() {
                if (ch.try_send(std::move(value))) {
                    done = true;
                    result = true;
                    return true;
                }
                if (ch.is_closed()) {
                    done = true;
                    result = false;
                    return true;
                }
                return false;
            }

            template <class Promise>
            bool await_suspend(std::coroutine_handle<Promise> h) {
                if constexpr (std::derived_from<Promise, task_promise_base>) {
                    return !ch.enter_send(h.promise().task_object, state);
                } else {
                    auto bridge = make_foreign_coro_bridge_task(h.address());
                    return !ch.enter_send(bridge, state);
                }
            }

            bool await_resume() {
                if (done)
                    return result;
                if (ch.try_send(std::move(value)))
                    return true;
                if (ch.is_closed())
                    return false;
                return ch.send(std::move(value));
            }
        };

        template <class Channel, class T>
        struct channel_send_until_awaiter {
            enter_state state;
            Channel& ch;
            T value;
            fast_task::time_point deadline;
            task task_obj;
            bool done = false;
            bool result = false;

            bool await_ready() {
                if (ch.try_send(std::move(value))) {
                    done = true;
                    result = true;
                    return true;
                }
                if (ch.is_closed() || fast_task::is_no_deadline(deadline) || fast_task::clock::now() >= deadline) {
                    done = true;
                    result = false;
                    return true;
                }
                return false;
            }

            template <class Promise>
            bool await_suspend(std::coroutine_handle<Promise> h) {
                if constexpr (std::derived_from<Promise, task_promise_base>) {
                    task_obj = h.promise().task_object;
                    return !ch.enter_send_until(task_obj, state, deadline);
                } else {
                    task_obj = make_foreign_coro_bridge_task(h.address());
                    return !ch.enter_send_until(task_obj, state, deadline);
                }
            }

            bool await_resume() {
                if (done)
                    return result;
                if (ch.try_send(std::move(value)))
                    return true;
                if (ch.is_closed() || (task_obj && task_obj.has_wait_timed_out()))
                    return false;
                return ch.send_until(std::move(value), deadline);
            }
        };

        template <class Channel, class T>
        struct channel_recv_awaiter {
            enter_state state;
            Channel& ch;
            std::optional<T> result;
            bool done = false;

            bool await_ready() {
                result = ch.try_recv();
                if (result.has_value() || ch.is_closed()) {
                    done = true;
                    return true;
                }
                return false;
            }

            template <class Promise>
            bool await_suspend(std::coroutine_handle<Promise> h) {
                if constexpr (std::derived_from<Promise, task_promise_base>) {
                    return !ch.enter_recv(h.promise().task_object, state);
                } else {
                    auto bridge = make_foreign_coro_bridge_task(h.address());
                    return !ch.enter_recv(bridge, state);
                }
            }

            std::optional<T> await_resume() {
                if (done)
                    return std::move(result);
                if (auto v = ch.try_recv())
                    return v;
                if (ch.is_closed())
                    return std::nullopt;
                return ch.recv();
            }
        };

        template <class Channel, class T>
        struct channel_recv_until_awaiter {
            enter_state state;
            Channel& ch;
            fast_task::time_point deadline;
            task task_obj;
            std::optional<T> result;
            bool done = false;

            bool await_ready() {
                result = ch.try_recv();
                if (result.has_value() || ch.is_closed() || fast_task::is_no_deadline(deadline) || fast_task::clock::now() >= deadline) {
                    done = true;
                    return true;
                }
                return false;
            }

            template <class Promise>
            bool await_suspend(std::coroutine_handle<Promise> h) {
                if constexpr (std::derived_from<Promise, task_promise_base>) {
                    task_obj = h.promise().task_object;
                    return !ch.enter_recv_until(task_obj, state, deadline);
                } else {
                    task_obj = make_foreign_coro_bridge_task(h.address());
                    return !ch.enter_recv_until(task_obj, state, deadline);
                }
            }

            std::optional<T> await_resume() {
                if (done)
                    return std::move(result);
                if (auto v = ch.try_recv())
                    return v;
                if (ch.is_closed() || (task_obj && task_obj.has_wait_timed_out()))
                    return std::nullopt;
                return ch.recv_until(deadline);
            }
        };
#endif

        // =========================================================================
        // Bounded channel: Lock-free Vyukov MPMC ring buffer (even/odd sequence)
        // Selected for nothrow-movable & nothrow-destructible T.
        // Supports any capacity >= 1 (power-of-2 uses bitmask; arbitrary uses modulo).
        // =========================================================================
        template <class T>
        class bounded_channel_lockfree {
            struct alignas(64) slot_t {
                std::atomic<size_t> seq{0};
                alignas(T) std::byte storage[sizeof(T)];

                T* ptr() noexcept {
                    return std::launder(reinterpret_cast<T*>(storage));
                }
            };

            struct alignas(64) futex_word {
                std::atomic<uint64_t> bits{0};
                bounded_channel_lockfree* owner = nullptr;
            };

            size_t capacity_;
            size_t mask_;
            std::unique_ptr<slot_t[]> slots_;

            alignas(64) std::atomic<size_t> enqueue_pos_{0};
            alignas(64) std::atomic<size_t> dequeue_pos_{0};
            futex_word recv_futex_;
            futex_word send_futex_;

            size_t index_of(size_t pos) const noexcept {
                return mask_ ? (pos & mask_) : (pos % capacity_);
            }

            bool has_ready_item() const noexcept {
                const size_t pos = dequeue_pos_.load(std::memory_order_acquire);
                const size_t seq = slots_[index_of(pos)].seq.load(std::memory_order_acquire);
                return seq == pos * 2 + 1;
            }

            bool has_free_slot() const noexcept {
                const size_t pos = enqueue_pos_.load(std::memory_order_acquire);
                const size_t seq = slots_[index_of(pos)].seq.load(std::memory_order_acquire);
                return seq == pos * 2;
            }

            static bool check_recv_ready(void* addr) noexcept {
                auto* fw = reinterpret_cast<futex_word*>(addr);
                uint64_t prev = fw->bits.fetch_or(channel_has_waiter_bit, std::memory_order_seq_cst);
                if ((prev & channel_closed_bit) != 0)
                    return true;
                return fw->owner->has_ready_item();
            }

            static bool check_send_ready(void* addr) noexcept {
                auto* fw = reinterpret_cast<futex_word*>(addr);
                uint64_t prev = fw->bits.fetch_or(channel_has_waiter_bit, std::memory_order_seq_cst);
                if ((prev & channel_closed_bit) != 0)
                    return true;
                return fw->owner->has_free_slot();
            }

            void wake_one_receiver() noexcept {
                if ((recv_futex_.bits.load(std::memory_order_acquire) & channel_has_waiter_bit) != 0)
                    futex::wake_on_address(&recv_futex_.bits, channel_release_waiter_bit, 1);
            }

            void wake_one_sender() noexcept {
                if ((send_futex_.bits.load(std::memory_order_acquire) & channel_has_waiter_bit) != 0)
                    futex::wake_on_address(&send_futex_.bits, channel_release_waiter_bit, 1);
            }

            template <class... Args>
            bool try_emplace_impl(Args&&... args) {
                if (is_closed())
                    return false;

                size_t pos = enqueue_pos_.load(std::memory_order_relaxed);
                for (;;) {
                    slot_t& slot = slots_[index_of(pos)];
                    const size_t seq = slot.seq.load(std::memory_order_acquire);
                    const ptrdiff_t diff = static_cast<ptrdiff_t>(seq) - static_cast<ptrdiff_t>(pos * 2);
                    if (diff == 0) {
                        if (enqueue_pos_.compare_exchange_weak(pos, pos + 1, std::memory_order_relaxed, std::memory_order_relaxed)) {
                            ::new (static_cast<void*>(slot.storage)) T(std::forward<Args>(args)...);
                            slot.seq.store(pos * 2 + 1, std::memory_order_seq_cst);
                            wake_one_receiver();
                            return true;
                        }
                    } else if (diff < 0) {
                        return false; // full
                    } else {
                        pos = enqueue_pos_.load(std::memory_order_relaxed);
                    }
                    if (is_closed())
                        return false;
                }
            }

        public:
            static constexpr bool is_lock_free = true;

            explicit bounded_channel_lockfree(size_t capacity)
                : capacity_(capacity), mask_((capacity >= 2 && (capacity & (capacity - 1)) == 0) ? (capacity - 1) : 0) {
                if (capacity_ == 0)
                    throw std::invalid_argument("bounded_channel capacity must be >= 1");
                slots_ = std::make_unique<slot_t[]>(capacity_);
                for (size_t i = 0; i < capacity_; ++i)
                    slots_[i].seq.store(i * 2, std::memory_order_relaxed);
                recv_futex_.owner = this;
                send_futex_.owner = this;
            }

            bounded_channel_lockfree(const bounded_channel_lockfree&) = delete;
            bounded_channel_lockfree& operator=(const bounded_channel_lockfree&) = delete;
            bounded_channel_lockfree(bounded_channel_lockfree&&) = delete;
            bounded_channel_lockfree& operator=(bounded_channel_lockfree&&) = delete;

            ~bounded_channel_lockfree() {
                close();
                while (try_recv().has_value()) {
                }
            }

            void close() noexcept {
                recv_futex_.bits.fetch_or(channel_closed_bit, std::memory_order_seq_cst);
                send_futex_.bits.fetch_or(channel_closed_bit, std::memory_order_seq_cst);
                futex::wake_on_address(&recv_futex_.bits, channel_release_waiter_bit, SIZE_MAX);
                futex::wake_on_address(&send_futex_.bits, channel_release_waiter_bit, SIZE_MAX);
            }

            bool is_closed() const noexcept {
                return (recv_futex_.bits.load(std::memory_order_acquire) & channel_closed_bit) != 0;
            }

            size_t capacity() const noexcept {
                return capacity_;
            }

            size_t size() const noexcept {
                const size_t enq = enqueue_pos_.load(std::memory_order_acquire);
                const size_t deq = dequeue_pos_.load(std::memory_order_acquire);
                if (enq <= deq)
                    return 0;
                const size_t diff = enq - deq;
                return diff > capacity_ ? capacity_ : diff;
            }

            bool empty() const noexcept {
                return !has_ready_item();
            }

            template <class... Args>
            bool try_emplace(Args&&... args) {
                return try_emplace_impl(std::forward<Args>(args)...);
            }

            bool try_send(const T& value) {
                return try_emplace_impl(value);
            }

            bool try_send(T&& value) {
                return try_emplace_impl(std::move(value));
            }

            template <class... Args>
            bool emplace(Args&&... args) {
                T tmp(std::forward<Args>(args)...);
                return send(std::move(tmp));
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

            std::optional<T> try_recv() noexcept {
                size_t pos = dequeue_pos_.load(std::memory_order_relaxed);
                for (;;) {
                    slot_t& slot = slots_[index_of(pos)];
                    const size_t seq = slot.seq.load(std::memory_order_acquire);
                    const ptrdiff_t diff = static_cast<ptrdiff_t>(seq) - static_cast<ptrdiff_t>(pos * 2 + 1);
                    if (diff == 0) {
                        if (dequeue_pos_.compare_exchange_weak(pos, pos + 1, std::memory_order_relaxed, std::memory_order_relaxed)) {
                            std::optional<T> res(std::move(*slot.ptr()));
                            std::destroy_at(slot.ptr());
                            slot.seq.store((pos + capacity_) * 2, std::memory_order_seq_cst);
                            wake_one_sender();
                            return res;
                        }
                    } else if (diff < 0) {
                        return std::nullopt; // empty
                    } else {
                        pos = dequeue_pos_.load(std::memory_order_relaxed);
                    }
                }
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

            // Low-level readiness registration API for foreign coroutines / custom schedulers.
            // Returns true if space is available or channel is closed right now;
            // returns false if `t` was registered to be woken on space/close.
            bool enter_send(const task& t, enter_state& state) {
                if (has_free_slot() || is_closed())
                    return true;
                return futex::enter_wait_on_address(t, &send_futex_.bits, &check_send_ready, state);
            }

            bool enter_send_until(const task& t, enter_state& state, fast_task::time_point time_point) {
                if (has_free_slot() || is_closed())
                    return true;
                return futex::enter_wait_on_address_until(t, &send_futex_.bits, &check_send_ready, state, time_point);
            }

            bool enter_recv(const task& t, enter_state& state) {
                if (has_ready_item() || is_closed())
                    return true;
                return futex::enter_wait_on_address(t, &recv_futex_.bits, &check_recv_ready, state);
            }

            bool enter_recv_until(const task& t, enter_state& state, fast_task::time_point time_point) {
                if (has_ready_item() || is_closed())
                    return true;
                return futex::enter_wait_on_address_until(t, &recv_futex_.bits, &check_recv_ready, state, time_point);
            }

#if __cplusplus >= 202002 || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002)
            [[nodiscard]] auto async_send(T value) {
                return channel_send_awaiter<bounded_channel_lockfree, T>{{}, *this, std::move(value)};
            }

            [[nodiscard]] auto async_send_until(T value, fast_task::time_point time_point) {
                return channel_send_until_awaiter<bounded_channel_lockfree, T>{{}, *this, std::move(value), time_point, {}};
            }

            template <class Rep, class Period>
            [[nodiscard]] auto async_send_for(T value, const std::chrono::duration<Rep, Period>& duration) {
                return async_send_until(std::move(value), fast_task::deadline_after(duration));
            }

            [[nodiscard]] auto async_recv() {
                return channel_recv_awaiter<bounded_channel_lockfree, T>{{}, *this};
            }

            [[nodiscard]] auto async_recv_until(fast_task::time_point time_point) {
                return channel_recv_until_awaiter<bounded_channel_lockfree, T>{{}, *this, time_point, {}};
            }

            template <class Rep, class Period>
            [[nodiscard]] auto async_recv_for(const std::chrono::duration<Rep, Period>& duration) {
                return async_recv_until(fast_task::deadline_after(duration));
            }
#endif
        };

        // =========================================================================
        // Bounded channel: Exception-safe blocking fallback
        // Selected when T's move constructor or destructor may throw.
        // =========================================================================
        template <class T>
        class bounded_channel_blocking {
            struct futex_word {
                std::atomic<uint64_t> bits{0};
                bounded_channel_blocking* owner = nullptr;
            };

            mutable mutex mut_;
            size_t capacity_;
            std::vector<std::optional<T>> ring_;
            size_t head_ = 0;
            size_t tail_ = 0;
            size_t count_ = 0;
            futex_word recv_futex_;
            futex_word send_futex_;

            bool closed_locked() const noexcept {
                return (recv_futex_.bits.load(std::memory_order_acquire) & channel_closed_bit) != 0;
            }

            static bool check_recv_ready(void* addr) {
                auto* fw = reinterpret_cast<futex_word*>(addr);
                fw->bits.fetch_or(channel_has_waiter_bit, std::memory_order_seq_cst);
                fast_task::lock_guard<mutex> guard(fw->owner->mut_);
                return fw->owner->count_ > 0 || fw->owner->closed_locked();
            }

            static bool check_send_ready(void* addr) {
                auto* fw = reinterpret_cast<futex_word*>(addr);
                fw->bits.fetch_or(channel_has_waiter_bit, std::memory_order_seq_cst);
                fast_task::lock_guard<mutex> guard(fw->owner->mut_);
                return fw->owner->count_ < fw->owner->capacity_ || fw->owner->closed_locked();
            }

            void wake_one_receiver() noexcept {
                if ((recv_futex_.bits.load(std::memory_order_acquire) & channel_has_waiter_bit) != 0)
                    futex::wake_on_address(&recv_futex_.bits, channel_release_waiter_bit, 1);
            }

            void wake_one_sender() noexcept {
                if ((send_futex_.bits.load(std::memory_order_acquire) & channel_has_waiter_bit) != 0)
                    futex::wake_on_address(&send_futex_.bits, channel_release_waiter_bit, 1);
            }

        public:
            static constexpr bool is_lock_free = false;

            explicit bounded_channel_blocking(size_t capacity)
                : capacity_(capacity), ring_(capacity) {
                if (capacity_ == 0)
                    throw std::invalid_argument("bounded_channel capacity must be >= 1");
                recv_futex_.owner = this;
                send_futex_.owner = this;
            }

            bounded_channel_blocking(const bounded_channel_blocking&) = delete;
            bounded_channel_blocking& operator=(const bounded_channel_blocking&) = delete;
            bounded_channel_blocking(bounded_channel_blocking&&) = delete;
            bounded_channel_blocking& operator=(bounded_channel_blocking&&) = delete;

            ~bounded_channel_blocking() {
                close();
            }

            void close() {
                {
                    fast_task::lock_guard<mutex> guard(mut_);
                    recv_futex_.bits.fetch_or(channel_closed_bit, std::memory_order_seq_cst);
                    send_futex_.bits.fetch_or(channel_closed_bit, std::memory_order_seq_cst);
                }
                futex::wake_on_address(&recv_futex_.bits, channel_release_waiter_bit, SIZE_MAX);
                futex::wake_on_address(&send_futex_.bits, channel_release_waiter_bit, SIZE_MAX);
            }

            bool is_closed() const noexcept {
                return (recv_futex_.bits.load(std::memory_order_acquire) & channel_closed_bit) != 0;
            }

            size_t capacity() const noexcept {
                return capacity_;
            }

            size_t size() const {
                fast_task::lock_guard<mutex> guard(mut_);
                return count_;
            }

            bool empty() const {
                fast_task::lock_guard<mutex> guard(mut_);
                return count_ == 0;
            }

            template <class... Args>
            bool try_emplace(Args&&... args) {
                {
                    fast_task::lock_guard<mutex> guard(mut_);
                    if (closed_locked() || count_ >= capacity_)
                        return false;
                    ring_[tail_].emplace(std::forward<Args>(args)...);
                    tail_ = (tail_ + 1 == capacity_) ? 0 : (tail_ + 1);
                    ++count_;
                }
                wake_one_receiver();
                return true;
            }

            bool try_send(const T& value) {
                return try_emplace(value);
            }

            bool try_send(T&& value) {
                return try_emplace(std::move(value));
            }

            template <class... Args>
            bool emplace(Args&&... args) {
                T tmp(std::forward<Args>(args)...);
                return send(std::move(tmp));
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
                std::optional<T> res;
                {
                    fast_task::lock_guard<mutex> guard(mut_);
                    if (count_ == 0)
                        return std::nullopt;
                    res.emplace(std::move(*ring_[head_]));
                    ring_[head_].reset();
                    head_ = (head_ + 1 == capacity_) ? 0 : (head_ + 1);
                    --count_;
                }
                wake_one_sender();
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
                return futex::enter_wait_on_address(t, &send_futex_.bits, &check_send_ready, state);
            }

            bool enter_send_until(const task& t, enter_state& state, fast_task::time_point time_point) {
                return futex::enter_wait_on_address_until(t, &send_futex_.bits, &check_send_ready, state, time_point);
            }

            bool enter_recv(const task& t, enter_state& state) {
                return futex::enter_wait_on_address(t, &recv_futex_.bits, &check_recv_ready, state);
            }

            bool enter_recv_until(const task& t, enter_state& state, fast_task::time_point time_point) {
                return futex::enter_wait_on_address_until(t, &recv_futex_.bits, &check_recv_ready, state, time_point);
            }

#if __cplusplus >= 202002 || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002)
            [[nodiscard]] auto async_send(T value) {
                return channel_send_awaiter<bounded_channel_blocking, T>{{}, *this, std::move(value)};
            }

            [[nodiscard]] auto async_send_until(T value, fast_task::time_point time_point) {
                return channel_send_until_awaiter<bounded_channel_blocking, T>{{}, *this, std::move(value), time_point, {}};
            }

            template <class Rep, class Period>
            [[nodiscard]] auto async_send_for(T value, const std::chrono::duration<Rep, Period>& duration) {
                return async_send_until(std::move(value), fast_task::deadline_after(duration));
            }

            [[nodiscard]] auto async_recv() {
                return channel_recv_awaiter<bounded_channel_blocking, T>{{}, *this};
            }

            [[nodiscard]] auto async_recv_until(fast_task::time_point time_point) {
                return channel_recv_until_awaiter<bounded_channel_blocking, T>{{}, *this, time_point, {}};
            }

            template <class Rep, class Period>
            [[nodiscard]] auto async_recv_for(const std::chrono::duration<Rep, Period>& duration) {
                return async_recv_until(fast_task::deadline_after(duration));
            }
#endif
        };

        // =========================================================================
        // Unbounded channel: Chunked 64-slot block queue (spin_lock fast path for
        // nothrow-movable types, task::mutex fallback for potentially-throwing types)
        // + futex parking on empty + enter_recv for foreign coroutines.
        // =========================================================================
        template <class T, bool FastSpin>
        class unbounded_channel_impl {
            static constexpr size_t BLOCK_SIZE = 64;

            struct block_t {
                block_t* next = nullptr;
                size_t head = 0;
                size_t tail = 0;
                alignas(T) std::byte storage[BLOCK_SIZE * sizeof(T)];

                T* slot(size_t i) noexcept {
                    return std::launder(reinterpret_cast<T*>(storage + i * sizeof(T)));
                }
            };

            struct alignas(64) futex_word {
                std::atomic<uint64_t> bits{0};
                unbounded_channel_impl* owner = nullptr;
            };

            using lock_t = std::conditional_t<FastSpin, fast_task::native::spin_lock, fast_task::mutex>;

            mutable lock_t lock_;
            block_t* head_block_ = nullptr;
            block_t* tail_block_ = nullptr;
            block_t* cached_block_ = nullptr;
            std::atomic<size_t> count_{0};
            futex_word recv_futex_;

            block_t* alloc_block() {
                if (cached_block_) {
                    block_t* b = cached_block_;
                    cached_block_ = nullptr;
                    b->next = nullptr;
                    b->head = 0;
                    b->tail = 0;
                    return b;
                }
                return new block_t();
            }

            void free_block(block_t* b) noexcept {
                if (!cached_block_) {
                    cached_block_ = b;
                } else {
                    delete b;
                }
            }

            static bool check_recv_ready(void* addr) noexcept {
                auto* fw = reinterpret_cast<futex_word*>(addr);
                uint64_t prev = fw->bits.fetch_or(channel_has_waiter_bit, std::memory_order_seq_cst);
                if ((prev & channel_closed_bit) != 0)
                    return true;
                return fw->owner->count_.load(std::memory_order_acquire) != 0;
            }

            void wake_one_receiver() noexcept {
                if ((recv_futex_.bits.load(std::memory_order_acquire) & channel_has_waiter_bit) != 0)
                    futex::wake_on_address(&recv_futex_.bits, channel_release_waiter_bit, 1);
            }

        public:
            static constexpr bool is_lock_free = false;
            static constexpr bool uses_fast_spin = FastSpin;

            unbounded_channel_impl() {
                recv_futex_.owner = this;
            }

            unbounded_channel_impl(const unbounded_channel_impl&) = delete;
            unbounded_channel_impl& operator=(const unbounded_channel_impl&) = delete;
            unbounded_channel_impl(unbounded_channel_impl&&) = delete;
            unbounded_channel_impl& operator=(unbounded_channel_impl&&) = delete;

            ~unbounded_channel_impl() {
                close();
                while (head_block_) {
                    block_t* b = head_block_;
                    head_block_ = b->next;
                    for (size_t i = b->head; i < b->tail; ++i)
                        std::destroy_at(b->slot(i));
                    delete b;
                }
                delete cached_block_;
            }

            void close() {
                {
                    fast_task::lock_guard<lock_t> guard(lock_);
                    recv_futex_.bits.fetch_or(channel_closed_bit, std::memory_order_seq_cst);
                }
                futex::wake_on_address(&recv_futex_.bits, channel_release_waiter_bit, SIZE_MAX);
            }

            bool is_closed() const noexcept {
                return (recv_futex_.bits.load(std::memory_order_acquire) & channel_closed_bit) != 0;
            }

            size_t size() const noexcept {
                return count_.load(std::memory_order_acquire);
            }

            bool empty() const noexcept {
                return count_.load(std::memory_order_acquire) == 0;
            }

            template <class... Args>
            bool emplace(Args&&... args) {
                {
                    fast_task::lock_guard<lock_t> guard(lock_);
                    if (is_closed())
                        return false;
                    if (!tail_block_ || tail_block_->tail == BLOCK_SIZE) {
                        block_t* nb = alloc_block();
                        if (tail_block_)
                            tail_block_->next = nb;
                        else
                            head_block_ = nb;
                        tail_block_ = nb;
                    }
                    ::new (static_cast<void*>(tail_block_->storage + tail_block_->tail * sizeof(T))) T(std::forward<Args>(args)...);
                    ++tail_block_->tail;
                    count_.fetch_add(1, std::memory_order_seq_cst);
                }
                wake_one_receiver();
                return true;
            }

            bool send(const T& value) {
                return emplace(value);
            }

            bool send(T&& value) {
                return emplace(std::move(value));
            }

            bool try_send(const T& value) {
                return emplace(value);
            }

            bool try_send(T&& value) {
                return emplace(std::move(value));
            }

            std::optional<T> try_recv() {
                if (count_.load(std::memory_order_acquire) == 0)
                    return std::nullopt;
                fast_task::lock_guard<lock_t> guard(lock_);
                if (!head_block_ || head_block_->head == head_block_->tail)
                    return std::nullopt;
                T* ptr = head_block_->slot(head_block_->head);
                std::optional<T> res(std::move(*ptr));
                std::destroy_at(ptr);
                ++head_block_->head;
                count_.fetch_sub(1, std::memory_order_release);
                if (head_block_->head == head_block_->tail) {
                    if (head_block_->next) {
                        block_t* old = head_block_;
                        head_block_ = old->next;
                        free_block(old);
                    } else {
                        head_block_->head = 0;
                        head_block_->tail = 0;
                    }
                }
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

            // Low-level readiness registration API for foreign coroutines / custom schedulers.
            bool enter_recv(const task& t, enter_state& state) {
                if (count_.load(std::memory_order_acquire) != 0 || is_closed())
                    return true;
                return futex::enter_wait_on_address(t, &recv_futex_.bits, &check_recv_ready, state);
            }

            bool enter_recv_until(const task& t, enter_state& state, fast_task::time_point time_point) {
                if (count_.load(std::memory_order_acquire) != 0 || is_closed())
                    return true;
                return futex::enter_wait_on_address_until(t, &recv_futex_.bits, &check_recv_ready, state, time_point);
            }

#if __cplusplus >= 202002 || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002)
            [[nodiscard]] auto async_recv() {
                return channel_recv_awaiter<unbounded_channel_impl, T>{{}, *this};
            }

            [[nodiscard]] auto async_recv_until(fast_task::time_point time_point) {
                return channel_recv_until_awaiter<unbounded_channel_impl, T>{{}, *this, time_point, {}};
            }

            template <class Rep, class Period>
            [[nodiscard]] auto async_recv_for(const std::chrono::duration<Rep, Period>& duration) {
                return async_recv_until(fast_task::deadline_after(duration));
            }
#endif
        };
    }

    // Automatically selects lock-free Vyukov MPMC ring buffer for nothrow-movable &
    // nothrow-destructible T, or exception-safe blocking ring buffer otherwise.
    template <class T>
    using bounded_channel = std::conditional_t<
        channel_lock_free_eligible_v<T>,
        detail::bounded_channel_lockfree<T>,
        detail::bounded_channel_blocking<T>>;

    // Automatically selects chunked spin-lock + futex fast path for nothrow-movable &
    // nothrow-destructible T, or task::mutex blocking fallback otherwise.
    template <class T>
    using unbounded_channel = detail::unbounded_channel_impl<T, channel_lock_free_eligible_v<T>>;
}

#endif /* FAST_TASK_INCLUDE_TASK_CHANNEL */
