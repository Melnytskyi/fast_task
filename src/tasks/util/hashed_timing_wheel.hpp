// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#pragma once
#include <atomic>
#include <bit>
#include <chrono>
#include <concurrentqueue/moodycamel/concurrentqueue.h>
#include <cstddef>
#include <cstdint>
#include <fast_task/task.hpp>
#include <mutex>
#include <tasks/util/macro.hpp>
#include <tasks/util/os_alloc.hpp>
#include <vector>

namespace fast_task {
    struct task_object;

    struct alignas(32) timing {
        struct flags_f {
            enum {
                in_overflow = 0x1,
                is_cold = 0x2,
                is_cancelled = 0x4
            };

            using t = uint8_t;
        };
        uint64_t wait_ticks;
        task awake_task;

        std::atomic<timing*> wheel_next;
        uint16_t check_id;
        uint8_t wheel_level = 0;
        uint8_t wheel_slot = 0;
        std::atomic<flags_f::t> flags{0};
        uint16_t arena_offset_pages;

        timing() = default;

        timing(uint64_t ticks, task t, uint16_t cid, bool cold = false) noexcept
            : wait_ticks(ticks), awake_task(std::move(t)), check_id(cid), flags(cold ? flags_f::is_cold : 0) {
            wheel_next.store(nullptr, std::memory_order_relaxed);
        }

        bool get_is_overflow() const noexcept {
            return (flags.load(std::memory_order_relaxed) & flags_f::in_overflow) != 0;
        }

        bool get_is_cold() const noexcept {
            return (flags.load(std::memory_order_relaxed) & flags_f::is_cold) != 0;
        }

        bool get_is_canceled() const noexcept {
            return (flags.load(std::memory_order_acquire) & flags_f::is_cancelled) != 0;
        }

        void set_is_overflow(bool value) noexcept {
            set_flag<flags_f::in_overflow>(flags, value);
        }

        void set_is_cold(bool value) noexcept {
            set_flag<flags_f::is_cold>(flags, value);
        }

        void set_is_canceled(bool value) noexcept {
            set_flag<flags_f::is_cancelled>(flags, value);
        }

        template <flags_f::t flag>
        static void set_flag(std::atomic<flags_f::t>& state, bool on) noexcept {
            flags_f::t cur = state.load(std::memory_order_relaxed), next;
            do {
                next = on ? flags_f::t(cur | (flag)) : flags_f::t(cur & ~(flag));
            } while (!state.compare_exchange_weak(cur, next, std::memory_order_acq_rel, std::memory_order_relaxed));
        }
    };

    static_assert(sizeof(timing) <= 32, "timing must fit in 32 bytes");

    class timing_allocator {
    public:
        static constexpr size_t block_size = 32;
        static constexpr size_t block_alignment = 32;
        static constexpr size_t init_batch = 128;
        static constexpr size_t max_local = 256;
        static constexpr size_t min_arena_blocks = 1024;
        static constexpr size_t max_arena_blocks = 131072;

        struct alignas(32) free_node {
            free_node* next;
        };

        struct alignas(16) tagged_node {
            free_node* ptr;
            uint64_t counter;
        };

        static_assert(sizeof(tagged_node) == 16, "tagged_node must be 16 bytes for DWCAS");

    private:
        static constexpr uint32_t CLEANING_BIT = 1u << 31;

        std::atomic<tagged_node> global_stack_;
        std::atomic<size_t> global_available_{0};
        std::atomic<uint32_t> pop_state_{0};
        std::atomic<bool> expanding_{false};
        std::atomic<bool> is_cleaning{false};

        struct alignas(block_alignment) arena {
            arena* next;
            void* base;
            size_t size;
            size_t cleanup_current_free : sizeof(size_t) * 8 - 1;
            size_t to_release : 1;
        };

        fast_task::native::spin_lock arena_lock;
        arena* arena_list_ = nullptr;
        size_t last_arena_size_ = 0;

        void expand();

    public:
        static arena* get_arena(void* any_node);
        timing_allocator() noexcept;
        ~timing_allocator();
        timing_allocator(const timing_allocator&) = delete;
        timing_allocator& operator=(const timing_allocator&) = delete;

        free_node* pop_batch(size_t count);
        void push_batch(free_node* head, free_node* tail, size_t count);
        void claim_unused();

        size_t available() const noexcept {
            return global_available_.load(std::memory_order_relaxed);
        }
    };

    struct FT_API_LOCAL tl_timing_alloc_cache {
        timing_allocator::free_node* free_list = nullptr;
        size_t free_count = 0;

        void* allocate();
        void deallocate(void* p);
        void release();
    };

    class hashed_timing_wheel {
    public:
        static constexpr size_t LEVELS = 4;
        static constexpr size_t SLOT_BITS = 8;
        static constexpr size_t SLOTS = 1u << SLOT_BITS;
        static constexpr uint64_t MAX_TICK_RANGE =
            uint64_t(1) << (LEVELS * SLOT_BITS);

        hashed_timing_wheel();
        ~hashed_timing_wheel();

        hashed_timing_wheel(const hashed_timing_wheel&) = delete;
        hashed_timing_wheel& operator=(const hashed_timing_wheel&) = delete;

        timing* insert(uint64_t wait_ticks, task awake_task, uint16_t check_id, bool is_cold);

        void remove(timing* handle);

        uint64_t to_ticks(fast_task::time_point tp) const;
        fast_task::time_point to_timepoint(uint64_t ticks) const;

        template <typename F>
        void collect_expired(fast_task::time_point now, F&& handler) {
            uint64_t target = to_ticks(now);
            uint64_t cur = current_tick_.load(std::memory_order_acquire);
            if (target > cur) {
                if (target - cur >= SLOTS && empty()) {
                    std::lock_guard guard(wheel_lock_);
                    if (empty()) {
                        current_tick_.store(target, std::memory_order_release);
                        cur = target;
                    }
                }
                if (cur < target) {
                    while (cur < target) {
                        uint64_t next_tick = cur + 1;
                        if ((next_tick & 0xFFFFFFFFULL) == 0)
                            drain_overflow();

                        cur = advance_one_tick(handler);
                    }

                    drain_expired_overflow(now, handler);
                }
            }

            collect_overdue(handler);
        }

        void drain_overflow();

        fast_task::time_point next_deadline() const;

        bool empty() const;
        size_t size() const;

        template <typename F>
        void clear(F&& handler) {
            for (size_t level = 0; level < LEVELS; ++level) {
                for (size_t slot = 0; slot < SLOTS; ++slot) {
                    timing* t = nullptr;
                    {
                        std::lock_guard guard(wheel_lock_);
                        t = slots_[level][slot].exchange(nullptr, std::memory_order_acq_rel);
                    }
                    while (t) {
                        timing* next =
                            t->wheel_next.load(std::memory_order_relaxed);
                        t->wheel_next.store(nullptr, std::memory_order_relaxed);
                        if (!t->get_is_canceled())
                            handler(*t);
                        deallocate_node(t);
                        t = next;
                    }
                }
            }

            timing* batch[256];
            size_t n;
            while ((n = overflow_.try_dequeue_bulk(batch, 256)) > 0) {
                for (size_t i = 0; i < n; ++i) {
                    if (!batch[i]->get_is_canceled())
                        handler(*batch[i]);
                    deallocate_node(batch[i]);
                }
            }
            has_overflow_.store(false, std::memory_order_release);

            {
                std::lock_guard guard(wheel_lock_);
                for (auto& word : level0_occupancy_)
                    word.store(0, std::memory_order_relaxed);
                for (auto& level : overdue_mask_)
                    for (auto& word : level)
                        word.store(0, std::memory_order_relaxed);

                epoch_ = fast_task::clock::now();
                current_tick_.store(0, std::memory_order_release);
            }
        }

    private:
        static constexpr size_t OCCUPANCY_WORDS = SLOTS / 64;

        mutable fast_task::native::spin_lock wheel_lock_;

        std::atomic<timing*> slots_[LEVELS][SLOTS];

        std::atomic<uint64_t> level0_occupancy_[OCCUPANCY_WORDS];

        std::atomic<uint64_t> overdue_mask_[LEVELS][OCCUPANCY_WORDS];

        std::atomic<uint64_t> current_tick_{0};
        fast_task::time_point epoch_;

        moodycamel::ConcurrentQueue<timing*> overflow_;
        std::atomic<bool> has_overflow_{false};

        static size_t slot_of(uint64_t tick, size_t level);
        static uint64_t ticks_per_level(size_t level);

        void push_slot(size_t level, size_t slot, timing* node);

        template <typename F>
        uint64_t advance_one_tick(F& handler) {
            uint64_t tick = current_tick_.fetch_add(1, std::memory_order_seq_cst) + 1;
            for (size_t L = 1; L < LEVELS; ++L) {
                uint64_t mask = (uint64_t(1) << (L * SLOT_BITS)) - 1;
                if ((tick & mask) == 0)
                    cascade_from(L);
                else
                    break;
            }
            collect_slot(static_cast<size_t>(tick & (SLOTS - 1)), handler);
            return tick;
        }

        void cascade_from(size_t level);

        static int next_occupied_slot(const uint64_t* occupancy, size_t from) noexcept;

        template <typename F>
        void collect_overdue(F& handler) {
            for (size_t level = 0; level < LEVELS; ++level) {
                for (size_t word = 0; word < OCCUPANCY_WORDS; ++word) {
                    uint64_t bits = overdue_mask_[level][word].load(std::memory_order_acquire);
                    while (bits != 0) {
                        const size_t slot = word * 64 + static_cast<size_t>(std::countr_zero(bits));
                        bits &= bits - 1;
                        overdue_mask_[level][word].fetch_and(
                            ~(uint64_t(1) << (slot & (64 - 1))), std::memory_order_acq_rel
                        );
                        sweep_slot(level, slot, handler);
                    }
                }
            }
        }

        template <typename F>
        void sweep_slot(size_t level, size_t slot, F& handler) {
            timing* chain = nullptr;
            {
                std::lock_guard guard(wheel_lock_);
                if (level == 0)
                    level0_occupancy_[slot >> 6].fetch_and(
                        ~(uint64_t(1) << (slot & (64 - 1))), std::memory_order_acq_rel
                    );
                chain = slots_[level][slot].exchange(nullptr, std::memory_order_acq_rel);
            }
            const uint64_t cur = current_tick_.load(std::memory_order_acquire);
            while (chain) {
                timing* next = chain->wheel_next.load(std::memory_order_relaxed);
                chain->wheel_next.store(nullptr, std::memory_order_relaxed);
                if (chain->get_is_canceled())
                    deallocate_node(chain);
                else if (chain->wait_ticks <= cur) {
                    handler(*chain);
                    deallocate_node(chain);
                } else {
                    const uint64_t delta = chain->wait_ticks - cur;
                    if (delta >= MAX_TICK_RANGE) {
                        chain->set_is_overflow(true);
                        overflow_.enqueue(chain);
                        has_overflow_.store(true, std::memory_order_release);
                    } else {
                        size_t target_level = 0;
                        while (target_level + 1 < LEVELS && delta >= ticks_per_level(target_level + 1))
                            ++target_level;
                        push_slot(target_level, slot_of(chain->wait_ticks, target_level), chain);
                    }
                }
                chain = next;
            }
        }

        template <typename F>
        void collect_slot(size_t slot, F& handler) {
            timing* chain = nullptr;
            {
                std::lock_guard guard(wheel_lock_);
                level0_occupancy_[slot >> 6].fetch_and(
                    ~(uint64_t(1) << (slot & 63)), std::memory_order_acq_rel
                );
                chain = slots_[0][slot].exchange(nullptr, std::memory_order_acq_rel);
            }
            while (chain) {
                timing* next =
                    chain->wheel_next.load(std::memory_order_relaxed);
                chain->wheel_next.store(nullptr, std::memory_order_relaxed);
                if (!chain->get_is_canceled())
                    handler(*chain);
                deallocate_node(chain);
                chain = next;
            }
        }

        template <typename F>
        void drain_expired_overflow(fast_task::time_point now, F& handler) {
            if (!has_overflow_.exchange(false, std::memory_order_acq_rel))
                return;

            constexpr size_t BATCH = 256;
            timing* batch[BATCH];
            std::vector<timing*> requeue;
            size_t n;

            while ((n = overflow_.try_dequeue_bulk(batch, BATCH)) > 0) {
                for (size_t i = 0; i < n; ++i) {
                    timing* t = batch[i];
                    if (t->get_is_canceled()) {
                        deallocate_node(t);
                        continue;
                    }

                    auto tp = to_timepoint(t->wait_ticks);
                    if (tp <= now) {
                        t->set_is_overflow(false);
                        handler(*t);
                        deallocate_node(t);
                    } else
                        requeue.push_back(t);
                }
            }

            if (!requeue.empty()) {
                overflow_.enqueue_bulk(requeue.data(), requeue.size());
                has_overflow_.store(true, std::memory_order_release);
            }
        }

        static timing* allocate_node();
        static void deallocate_node(timing* t);
    };

} // namespace fast_task