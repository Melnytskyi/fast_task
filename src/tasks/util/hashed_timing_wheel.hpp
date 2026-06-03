// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#pragma once
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <queue>
#include <task.hpp>
#include <vector>

namespace fast_task {
    struct task_object;

    struct timing {
        std::chrono::high_resolution_clock::time_point wait_timepoint;
        task awake_task;

        timing* wheel_next = nullptr;
        timing* wheel_prev = nullptr;
        uint16_t check_id;
        uint8_t wheel_level = 0;
        uint8_t wheel_slot = 0;
        bool in_overflow = false;

        timing() = default;

        timing(std::chrono::high_resolution_clock::time_point tp, task t, uint16_t cid) noexcept
            : wait_timepoint(tp), awake_task(std::move(t)), check_id(cid) {}

        bool operator>(const timing& other) const {
            return wait_timepoint > other.wait_timepoint;
        }
    };

    class timing_pool {
    public:
        static constexpr size_t CHUNK_SIZE = 64;

        struct chunk {
            chunk* next;
            timing nodes[CHUNK_SIZE];
        };

        timing_pool() noexcept;
        ~timing_pool();

        timing_pool(const timing_pool&) = delete;
        timing_pool& operator=(const timing_pool&) = delete;

        timing* allocate();
        void deallocate(timing* t) noexcept;

    private:
        chunk* chunks_ = nullptr;
        timing* freelist_ = nullptr;
        size_t count_ = 0;
    };

    class hashed_timing_wheel {
    public:
        static constexpr size_t LEVELS = 4;
        static constexpr size_t SLOT_BITS = 8;
        static constexpr size_t SLOTS = 1u << SLOT_BITS;
        static constexpr uint64_t MAX_TICK_RANGE = uint64_t(1) << (LEVELS * SLOT_BITS);

        hashed_timing_wheel();
        ~hashed_timing_wheel();

        hashed_timing_wheel(const hashed_timing_wheel&) = delete;
        hashed_timing_wheel& operator=(const hashed_timing_wheel&) = delete;

        timing* insert(timing&& t);
        void remove(timing* handle);

        template <typename F>
        void collect_expired(std::chrono::high_resolution_clock::time_point now, F&& handler) {
            uint64_t target = to_ticks(now);
            if (target <= current_tick_)
                return;

            while (current_tick_ < target) {
                uint64_t next_tick = current_tick_ + 1;
                if ((next_tick & 0xFFFFFFFFULL) == 0)
                    drain_overflow();

                advance_one_tick(handler);
            }

            collect_slot(static_cast<size_t>(current_tick_ & 0xFF), handler);
            drain_overflow_to(now, handler);
        }

        std::chrono::high_resolution_clock::time_point next_deadline() const;

        bool empty() const;
        size_t size() const;

        template <typename F>
        void clear(F&& handler) {
            for (size_t level = 0; level < LEVELS; ++level) {
                for (size_t slot = 0; slot < SLOTS; ++slot) {
                    timing* t = slots_[level][slot];
                    while (t) {
                        timing* next = t->wheel_next;
                        t->wheel_next = nullptr;
                        t->wheel_prev = nullptr;
                        handler(*t);
                        pool_.deallocate(t);
                        t = next;
                    }
                    slots_[level][slot] = nullptr;
                }
            }
            while (!overflow_.empty()) {
                timing* t = overflow_.top();
                overflow_.pop();
                t->in_overflow = false;
                handler(*t);
                pool_.deallocate(t);
            }
            has_overflow_ = false;
            overflow_drain_head_ = nullptr;

            epoch_ = std::chrono::high_resolution_clock::now();
            current_tick_ = 0;
        }

    private:
        timing* slots_[LEVELS][SLOTS];

        uint64_t current_tick_ = 0;
        std::chrono::high_resolution_clock::time_point epoch_;

        timing_pool pool_;

        struct overflow_cmp {
            bool operator()(const timing* a, const timing* b) const {
                return a->wait_timepoint > b->wait_timepoint;
            }
        };

        std::priority_queue<timing*, std::vector<timing*>, overflow_cmp> overflow_;
        timing* overflow_drain_head_ = nullptr;
        bool has_overflow_ = false;

        static size_t slot_of(uint64_t tick, size_t level);
        static uint64_t ticks_per_level(size_t level);

        uint64_t to_ticks(std::chrono::high_resolution_clock::time_point tp) const;
        std::chrono::high_resolution_clock::time_point to_timepoint(uint64_t ticks) const;

        void link(timing& t, size_t level, uint64_t use_tick);
        void unlink(timing& t);

        template <typename F>
        void advance_one_tick(F& handler) {
            ++current_tick_;
            uint64_t tick = current_tick_;
            for (size_t L = 1; L < LEVELS; ++L) {
                uint64_t mask = (uint64_t(1) << (L * SLOT_BITS)) - 1;
                if ((tick & mask) == 0)
                    cascade_from(L);
                else
                    break;
            }
            collect_slot(static_cast<size_t>(current_tick_ & 0xFF), handler);
        }

        void cascade_from(size_t level);

        template <typename F>
        void collect_slot(size_t slot, F& handler) {
            timing* t = slots_[0][slot];
            slots_[0][slot] = nullptr;
            while (t) {
                timing* next = t->wheel_next;
                t->wheel_next = nullptr;
                t->wheel_prev = nullptr;
                handler(*t);
                pool_.deallocate(t);
                t = next;
            }
        }

        void drain_overflow();

        template <typename F>
        void drain_overflow_to(std::chrono::high_resolution_clock::time_point now, F& handler) {
            if (!has_overflow_)
                return;
            while (!overflow_.empty()) {
                timing* t = overflow_.top();
                if (t->wait_timepoint > now)
                    break;
                overflow_.pop();
                t->in_overflow = false;
                handler(*t);
                pool_.deallocate(t);
            }
            if (overflow_.empty())
                has_overflow_ = false;
        }
    };

} // namespace fast_task