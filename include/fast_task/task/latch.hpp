// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_INCLUDE_TASK_LATCH
#define FAST_TASK_INCLUDE_TASK_LATCH

#include "../clock.hpp"
#include "../internal/futex.hpp"
#include "enter_state.hpp"
#include "event.hpp"
#include "task.hpp"
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <utility>

#if __cplusplus >= 202002 || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002)
    #include "../coroutine/core.hpp"
    #include <concepts>
    #include <coroutine>
#endif

namespace fast_task {
    // Task/coroutine/native-thread-friendly std::latch backed by fast_task::futex.
    // Zero heap allocations; count_down() is a single atomic fetch_sub on fast path.
    class latch {
        static constexpr uint64_t WAITER_BIT = 1ull << 63;
        static constexpr uint64_t COUNT_MASK = ~WAITER_BIT;

        std::atomic<uint64_t> state_;

        static void release_waiter_bit(void* addr, size_t, bool has_remaining) noexcept {
            auto& st = *reinterpret_cast<std::atomic<uint64_t>*>(addr);
            if (has_remaining)
                st.fetch_or(WAITER_BIT, std::memory_order_release);
            else
                st.fetch_and(COUNT_MASK, std::memory_order_release);
        }

        static bool check_zero(void* addr) noexcept {
            auto& st = *reinterpret_cast<std::atomic<uint64_t>*>(addr);
            uint64_t cur = st.load(std::memory_order_acquire);
            for (;;) {
                if ((cur & COUNT_MASK) == 0)
                    return true;
                if (st.compare_exchange_weak(cur, cur | WAITER_BIT, std::memory_order_acq_rel, std::memory_order_acquire))
                    return false;
            }
        }

    public:
        explicit latch(std::ptrdiff_t expected)
            : state_(static_cast<uint64_t>(expected)) {
            if (expected < 0)
                throw std::invalid_argument("fast_task::latch expected count must be >= 0");
        }

        latch(const latch&) = delete;
        latch& operator=(const latch&) = delete;
        latch(latch&&) = delete;
        latch& operator=(latch&&) = delete;

        void count_down(std::ptrdiff_t update = 1) noexcept {
            if (update <= 0)
                return;
            const uint64_t delta = static_cast<uint64_t>(update);
            const uint64_t prev = state_.fetch_sub(delta, std::memory_order_acq_rel);
            const uint64_t rem = (prev & COUNT_MASK) - delta;
            if (rem == 0 && (prev & WAITER_BIT) != 0)
                futex::wake_on_address(&state_, &release_waiter_bit, SIZE_MAX);
        }

        bool try_wait() const noexcept {
            return (state_.load(std::memory_order_acquire) & COUNT_MASK) == 0;
        }

        void wait() {
            while (!try_wait())
                futex::wait_on_address(&state_, &check_zero);
        }

        bool wait_until(fast_task::time_point time_point) {
            if (try_wait())
                return true;
            while (!try_wait()) {
                if (!futex::wait_on_address_until(&state_, &check_zero, time_point))
                    return try_wait();
            }
            return true;
        }

        template <class Rep, class Period>
        bool wait_for(const std::chrono::duration<Rep, Period>& duration) {
            return wait_until(fast_task::deadline_after(duration));
        }

        void arrive_and_wait(std::ptrdiff_t update = 1) {
            count_down(update);
            wait();
        }

        bool enter_wait(const task& t, enter_state& state) {
            if (try_wait())
                return true;
            return futex::enter_wait_on_address(t, &state_, &check_zero, state);
        }

        bool enter_wait_until(const task& t, enter_state& state, fast_task::time_point time_point) {
            if (try_wait())
                return true;
            return futex::enter_wait_on_address_until(t, &state_, &check_zero, state, time_point);
        }

#if __cplusplus >= 202002 || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002)
        [[nodiscard]] auto async_wait() {
            return detail::event_wait_awaiter<latch>{{}, *this};
        }

        [[nodiscard]] auto async_wait_until(fast_task::time_point time_point) {
            return detail::event_wait_until_awaiter<latch>{{}, *this, time_point, {}};
        }

        template <class Rep, class Period>
        [[nodiscard]] auto async_wait_for(const std::chrono::duration<Rep, Period>& duration) {
            return async_wait_until(fast_task::deadline_after(duration));
        }
#endif
    };

    namespace detail {
        struct empty_barrier_completion {
            void operator()() noexcept {}
        };
    }

    // Reusable multi-phase barrier backed by fast_task::futex.
    // Uses dual-parity phase futex words for ABA-free, allocation-free phase flips.
    template <class CompletionFunction = detail::empty_barrier_completion>
    class barrier {
        static constexpr uint8_t OPEN_BIT = 1u << 0;
        static constexpr uint8_t WAITER_BIT = 1u << 1;

        static constexpr uint64_t PHASE_SHIFT = 32;
        static constexpr uint64_t COUNT_MASK = 0xFFFFFFFFull;

        std::atomic<uint64_t> state_;
        std::atomic<uint32_t> expected_;
        std::atomic<uint8_t> phase_futex_[2];
        CompletionFunction completion_;

        static void release_waiter_bit(void* addr, size_t, bool has_remaining) noexcept {
            auto& st = *reinterpret_cast<std::atomic<uint8_t>*>(addr);
            if (has_remaining)
                st.fetch_or(WAITER_BIT, std::memory_order_release);
            else
                st.fetch_and(static_cast<uint8_t>(~WAITER_BIT), std::memory_order_release);
        }

        static bool check_phase_open(void* addr) noexcept {
            auto& st = *reinterpret_cast<std::atomic<uint8_t>*>(addr);
            uint8_t cur = st.load(std::memory_order_acquire);
            for (;;) {
                if ((cur & OPEN_BIT) != 0)
                    return true;
                if (st.compare_exchange_weak(
                        cur,
                        static_cast<uint8_t>(cur | WAITER_BIT),
                        std::memory_order_acq_rel,
                        std::memory_order_acquire
                    ))
                    return false;
            }
        }

        void complete_phase(uint32_t completed_phase, uint32_t next_expected) noexcept {
            completion_();
            const uint32_t next_phase = completed_phase + 1;
            // Reset next phase's futex word BEFORE exposing next_phase in state_.
            phase_futex_[next_phase & 1u].store(0, std::memory_order_release);
            const uint64_t next_state = (static_cast<uint64_t>(next_phase) << PHASE_SHIFT) | next_expected;
            state_.store(next_state, std::memory_order_release);

            auto& pf = phase_futex_[completed_phase & 1u];
            uint8_t prev = pf.fetch_or(OPEN_BIT, std::memory_order_acq_rel);
            if ((prev & WAITER_BIT) != 0)
                futex::wake_on_address(&pf, &release_waiter_bit, SIZE_MAX);
        }

    public:
        using arrival_token = uint32_t;

        explicit barrier(std::ptrdiff_t expected, CompletionFunction f = CompletionFunction())
            : state_(static_cast<uint64_t>(expected)),
              expected_(static_cast<uint32_t>(expected)),
              completion_(std::move(f)) {
            if (expected <= 0)
                throw std::invalid_argument("fast_task::barrier expected count must be > 0");
            phase_futex_[0].store(0, std::memory_order_relaxed);
            phase_futex_[1].store(0, std::memory_order_relaxed);
        }

        barrier(const barrier&) = delete;
        barrier& operator=(const barrier&) = delete;
        barrier(barrier&&) = delete;
        barrier& operator=(barrier&&) = delete;

        [[nodiscard]] arrival_token arrive(std::ptrdiff_t update = 1) noexcept {
            const uint32_t delta = static_cast<uint32_t>(update);
            uint64_t cur = state_.load(std::memory_order_acquire);
            for (;;) {
                const uint32_t phase = static_cast<uint32_t>(cur >> PHASE_SHIFT);
                const uint32_t rem = static_cast<uint32_t>(cur & COUNT_MASK);
                if (rem <= delta) {
                    const uint32_t next_exp = expected_.load(std::memory_order_acquire);
                    // Claim completion by setting remaining to 0 in current phase.
                    const uint64_t zero_state = static_cast<uint64_t>(phase) << PHASE_SHIFT;
                    if (state_.compare_exchange_weak(cur, zero_state, std::memory_order_acq_rel, std::memory_order_acquire)) {
                        complete_phase(phase, next_exp);
                        return phase;
                    }
                } else {
                    const uint64_t next_state = (static_cast<uint64_t>(phase) << PHASE_SHIFT) | (rem - delta);
                    if (state_.compare_exchange_weak(cur, next_state, std::memory_order_acq_rel, std::memory_order_acquire))
                        return phase;
                }
            }
        }

        void wait(arrival_token token) {
            while (static_cast<uint32_t>(state_.load(std::memory_order_acquire) >> PHASE_SHIFT) == token)
                futex::wait_on_address(&phase_futex_[token & 1u], &check_phase_open);
        }

        void arrive_and_wait() {
            wait(arrive());
        }

        void arrive_and_drop() noexcept {
            const uint32_t next_exp = expected_.fetch_sub(1, std::memory_order_acq_rel) - 1;
            uint64_t cur = state_.load(std::memory_order_acquire);
            for (;;) {
                const uint32_t phase = static_cast<uint32_t>(cur >> PHASE_SHIFT);
                const uint32_t rem = static_cast<uint32_t>(cur & COUNT_MASK);
                if (rem <= 1) {
                    const uint64_t zero_state = static_cast<uint64_t>(phase) << PHASE_SHIFT;
                    if (state_.compare_exchange_weak(cur, zero_state, std::memory_order_acq_rel, std::memory_order_acquire)) {
                        complete_phase(phase, next_exp);
                        return;
                    }
                } else {
                    const uint64_t next_state = (static_cast<uint64_t>(phase) << PHASE_SHIFT) | (rem - 1);
                    if (state_.compare_exchange_weak(cur, next_state, std::memory_order_acq_rel, std::memory_order_acquire))
                        return;
                }
            }
        }

        bool enter_wait(const task& t, enter_state& state, arrival_token token) {
            if (static_cast<uint32_t>(state_.load(std::memory_order_acquire) >> PHASE_SHIFT) != token)
                return true;
            return futex::enter_wait_on_address(t, &phase_futex_[token & 1u], &check_phase_open, state);
        }

#if __cplusplus >= 202002 || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002)
    private:
        struct wait_awaiter {
            enter_state state;
            barrier& b;
            arrival_token token;

            bool await_ready() noexcept {
                return static_cast<uint32_t>(b.state_.load(std::memory_order_acquire) >> PHASE_SHIFT) != token;
            }

            template <class Promise>
            bool await_suspend(std::coroutine_handle<Promise> h) {
                if constexpr (std::derived_from<Promise, task_promise_base>) {
                    return !b.enter_wait(h.promise().task_object, state, token);
                } else {
                    auto bridge = detail::make_event_foreign_bridge_task(h.address());
                    return !b.enter_wait(bridge, state, token);
                }
            }

            void await_resume() noexcept {}
        };

    public:
        [[nodiscard]] auto async_wait(arrival_token token) {
            return wait_awaiter{{}, *this, token};
        }

        [[nodiscard]] auto async_arrive_and_wait() {
            return wait_awaiter{{}, *this, arrive()};
        }
#endif
    };
}

#endif /* FAST_TASK_INCLUDE_TASK_LATCH */
