// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_CORE_NOTIFIER
#define FAST_TASK_CORE_NOTIFIER

#include <atomic>
#include <cstdint>

namespace fast_task {
    struct alignas(64) pool_park_line {
        static constexpr uint64_t sleepers_one = uint64_t(1);
        static constexpr uint64_t spinners_one = uint64_t(1) << 16;
        static constexpr uint64_t pending_bit = uint64_t(1) << 32;
        static constexpr uint64_t tag_one = uint64_t(1) << 33;
        static constexpr uint64_t sleepers_mask = 0xFFFF;
        static constexpr uint64_t spinners_mask = uint64_t(0xFFFF) << 16;

        std::atomic<uint64_t> state{0};
        std::atomic<uint32_t> wake_epoch{0};

        static uint16_t sleepers_in(uint64_t s) noexcept {
            return static_cast<uint16_t>(s & sleepers_mask);
        }

        static uint16_t spinners_in(uint64_t s) noexcept {
            return static_cast<uint16_t>((s & spinners_mask) >> 16);
        }

        static bool pending_in(uint64_t s) noexcept {
            return (s & pending_bit) != 0;
        }

        uint64_t load(std::memory_order order) const noexcept {
            return state.load(order);
        }

        uint16_t sleepers() const noexcept {
            return sleepers_in(state.load(std::memory_order_relaxed));
        }

        bool has_sleepers() const noexcept {
            return sleepers() != 0;
        }

        bool has_pending() const noexcept {
            return pending_in(state.load(std::memory_order_relaxed));
        }

        void add_sleeper() noexcept {
            state.fetch_add(sleepers_one, std::memory_order_seq_cst);
        }

        void remove_sleeper() noexcept {
            state.fetch_sub(sleepers_one, std::memory_order_relaxed);
        }

        bool try_add_spinner(uint16_t cap) noexcept {
            uint64_t s = state.load(std::memory_order_relaxed);
            for (;;) {
                if (spinners_in(s) >= cap)
                    return false;
                if (state.compare_exchange_weak(s, s + spinners_one + tag_one, std::memory_order_acq_rel, std::memory_order_relaxed))
                    return true;
            }
        }

        void remove_spinner() noexcept {
            state.fetch_sub(spinners_one, std::memory_order_release);
        }

        bool clear_pending() noexcept {
            if (!has_pending())
                return false;
            return (state.fetch_and(~pending_bit, std::memory_order_seq_cst) & pending_bit) != 0;
        }

        bool begin_wake(uint64_t observed) noexcept {
            return state.compare_exchange_strong(observed, (observed | pending_bit) + tag_one, std::memory_order_acq_rel, std::memory_order_relaxed);
        }

        uint32_t epoch() const noexcept {
            return wake_epoch.load(std::memory_order_acquire);
        }

        void bump_epoch() noexcept {
            wake_epoch.fetch_add(1, std::memory_order_release);
        }
    };

    static_assert(sizeof(pool_park_line) == 64, "pool_park_line must occupy exactly one cache line");

    class spinner_ticket {
        pool_park_line* line;
        bool held = false;

    public:
        explicit spinner_ticket(pool_park_line& l) noexcept
            : line(&l) {}

        spinner_ticket(const spinner_ticket&) = delete;
        spinner_ticket& operator=(const spinner_ticket&) = delete;

        ~spinner_ticket() {
            release();
        }

        bool try_acquire(uint16_t cap) noexcept {
            if (!held)
                held = line->try_add_spinner(cap);
            return held;
        }

        void release() noexcept {
            if (!held)
                return;
            held = false;
            line->remove_spinner();
        }
    };
}

#endif /* FAST_TASK_CORE_NOTIFIER */
