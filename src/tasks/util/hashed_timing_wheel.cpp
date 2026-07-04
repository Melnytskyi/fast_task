// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include "hashed_timing_wheel.hpp"
#include <limits>
#include <new>
#include <tasks/_internal.hpp>
#include <tasks/util/macro.hpp>

namespace fast_task {
    void timing_allocator::expand() {
        bool expected = false;
        if (!expanding_.compare_exchange_strong(expected, true, std::memory_order_acquire))
            return;
        interrupt_unsafe_region ir;

        size_t num_blocks = min_arena_blocks;
        if (last_arena_size_ != 0) {
            num_blocks = last_arena_size_ / block_size * 2;
            if (num_blocks < min_arena_blocks)
                num_blocks = min_arena_blocks;
            if (num_blocks > max_arena_blocks)
                num_blocks = max_arena_blocks;
        }
        size_t arena_size = num_blocks * block_size;
        size_t alloc_size = arena_size + sizeof(arena);

        void* base = os_alloc(alloc_size);
        if (!base) {
            expanding_.store(false, std::memory_order_release);
            throw std::bad_alloc();
        }

        auto* a = static_cast<arena*>(base);
        a->base = static_cast<std::byte*>(base) + sizeof(arena);
        a->size = arena_size;
        {
            std::lock_guard guard(arena_lock);
            a->next = arena_list_;
            arena_list_ = a;
            last_arena_size_ = arena_size;
        }

        auto* begin = static_cast<std::byte*>(a->base);
        auto* end = begin + arena_size;
        free_node* tail = nullptr;
        free_node* head = nullptr;
        for (auto* pos = begin; pos < end; pos += block_size) {
            auto* node = reinterpret_cast<free_node*>(pos);
            node->next = head;
            head = node;
            if (!tail)
                tail = node;
        }

        tagged_node old = global_stack_.load(std::memory_order_acquire);
        while (true) {
            tail->next = old.ptr;
            tagged_node desired{head, old.counter + 1};
            if (global_stack_.compare_exchange_weak(
                    old,
                    desired,
                    std::memory_order_release,
                    std::memory_order_acquire
                )) {
                break;
            }
        }
        global_available_.fetch_add(num_blocks, std::memory_order_relaxed);
        expanding_.store(false, std::memory_order_release);
    }

    timing_allocator::timing_allocator() noexcept {
        tagged_node init{nullptr, 0};
        global_stack_.store(init, std::memory_order_relaxed);
    }

    timing_allocator::~timing_allocator() {
        std::lock_guard guard(arena_lock);
        arena* a = arena_list_;
        while (a) {
            arena* next = a->next;
            os_free(a, a->size + sizeof(arena));
            a = next;
        }
        arena_list_ = nullptr;
    }

    timing_allocator::free_node* timing_allocator::pop_batch(size_t count) {
        free_node* head = nullptr;
        free_node* tail = nullptr;
        size_t popped = 0;

        while (popped < count) {
            tagged_node old = global_stack_.load(std::memory_order_acquire);
            if (!old.ptr) {
                if (popped == 0) {
                    expand();
                    continue;
                }
                break;
            }
            tagged_node desired{old.ptr->next, old.counter + 1};
            if (global_stack_.compare_exchange_weak(
                    old,
                    desired,
                    std::memory_order_release,
                    std::memory_order_acquire
                )) {
                old.ptr->next = nullptr;
                if (!head) {
                    head = tail = old.ptr;
                } else {
                    tail->next = old.ptr;
                    tail = old.ptr;
                }
                ++popped;
            }
        }

        global_available_.fetch_sub(popped, std::memory_order_relaxed);
        return head;
    }

    void timing_allocator::push_batch(free_node* head, free_node* tail, size_t count) {
        tagged_node old = global_stack_.load(std::memory_order_acquire);
        while (true) {
            tail->next = old.ptr;
            tagged_node desired{head, old.counter + 1};
            if (global_stack_.compare_exchange_weak(
                    old,
                    desired,
                    std::memory_order_release,
                    std::memory_order_acquire
                )) {
                break;
            }
        }
        global_available_.fetch_add(count, std::memory_order_relaxed);
    }

    void timing_allocator::claim_unused() {
        tagged_node old = global_stack_.load(std::memory_order_acquire);
        while (true) {
            tagged_node desired{nullptr, old.counter + 1};
            if (global_stack_.compare_exchange_weak(
                    old,
                    desired,
                    std::memory_order_release,
                    std::memory_order_acquire
                ))
                break;
        }
        global_available_.store(0, std::memory_order_relaxed);

        if (!old.ptr) {
            arena* to_free;
            {
                std::lock_guard guard(arena_lock);
                to_free = arena_list_;
                arena_list_ = nullptr;
                last_arena_size_ = 0;
            }
            while (to_free) {
                arena* next = to_free->next;
                os_free(to_free, to_free->size + sizeof(arena));
                to_free = next;
            }
            return;
        }

        free_node* tail = old.ptr;
        size_t cnt = 1;
        while (tail->next) {
            tail = tail->next;
            ++cnt;
        }
        push_batch(old.ptr, tail, cnt);
    }

    static timing_allocator g_timing_alloc;

    void* tl_timing_alloc_cache::allocate() {
        if (!free_list) {
            auto* batch = g_timing_alloc.pop_batch(timing_allocator::init_batch);
            if (!batch)
                throw std::bad_alloc();

            size_t actual = 0;
            auto* cur = batch;
            while (cur) {
                ++actual;
                cur = cur->next;
            }

            free_list = batch;
            free_count = actual;
        }

        auto* node = free_list;
        free_list = node->next;
        node->next = nullptr;
        --free_count;
        return node;
    }

    void tl_timing_alloc_cache::deallocate(void* p) {
        auto* node = static_cast<timing_allocator::free_node*>(p);
        node->next = free_list;
        free_list = node;
        ++free_count;

        if (free_count > timing_allocator::max_local) {
            auto* head = free_list;
            auto* cur = head;
            size_t count = timing_allocator::init_batch;
            for (size_t i = 1; i < count; ++i)
                cur = cur->next;
            free_list = cur->next;
            cur->next = nullptr;
            free_count -= count;

            auto* tail = head;
            for (size_t i = 1; i < count; ++i)
                tail = tail->next;

            g_timing_alloc.push_batch(head, tail, count);
        }
    }

    void tl_timing_alloc_cache::release() {
        if (free_list) {
            auto* head = free_list;
            auto* cur = head;
            while (cur->next)
                cur = cur->next;

            g_timing_alloc.push_batch(head, cur, free_count);
            free_list = nullptr;
            free_count = 0;
        }
    }

    timing* hashed_timing_wheel::allocate_node() {
        void* p = get_loc().timing_alloc_cache.allocate();
        return static_cast<timing*>(p);
    }

    void hashed_timing_wheel::deallocate_node(timing* t) {
        t->wheel_next.store(nullptr, std::memory_order_relaxed);
        t->wheel_level = 0;
        t->wheel_slot = 0;
        t->in_overflow = false;
        t->is_cold = false;
        t->cancelled.store(false, std::memory_order_relaxed);
        get_loc().timing_alloc_cache.deallocate(t);
    }

    hashed_timing_wheel::hashed_timing_wheel() {
        epoch_ = std::chrono::high_resolution_clock::now();
        for (auto& level : slots_)
            for (auto& slot : level)
                slot.store(nullptr, std::memory_order_relaxed);
    }

    hashed_timing_wheel::~hashed_timing_wheel() = default;

    uint64_t hashed_timing_wheel::ticks_per_level(size_t level) {
        uint64_t t = 1;
        for (size_t i = 0; i < level; ++i)
            t *= SLOTS;
        return t;
    }

    size_t hashed_timing_wheel::slot_of(uint64_t tick, size_t level) {
        return static_cast<size_t>((tick >> (level * SLOT_BITS)) & (SLOTS - 1));
    }

    uint64_t hashed_timing_wheel::to_ticks(std::chrono::high_resolution_clock::time_point tp) const {
        auto dur = tp - epoch_;
        auto us = std::chrono::duration_cast<std::chrono::microseconds>(dur).count();
#if FT_TIMER_PRECISION == 1
        return static_cast<uint64_t>(us);
#elif FT_TIMER_PRECISION == 1000
        return static_cast<uint64_t>(us / 1000) + (us % 1000 ? 1 : 0);
#else
        return static_cast<uint64_t>(us / 10000) + (us % 10000 ? 1 : 0);
#endif
    }

    std::chrono::high_resolution_clock::time_point hashed_timing_wheel::to_timepoint(uint64_t ticks) const {
#if FT_TIMER_PRECISION == 1
        auto dur = std::chrono::microseconds(ticks);
#elif FT_TIMER_PRECISION == 1000
        auto dur = std::chrono::milliseconds(ticks);
#else
        auto dur = std::chrono::milliseconds(ticks * 10);
#endif
        return epoch_ + dur;
    }

    void hashed_timing_wheel::push_slot(size_t level, size_t slot, timing* node) {
        node->wheel_level = static_cast<uint8_t>(level);
        node->wheel_slot = static_cast<uint8_t>(slot);
        node->in_overflow = false;

        timing* old_head = slots_[level][slot].load(std::memory_order_acquire);
        do {
            node->wheel_next.store(old_head, std::memory_order_relaxed);
        } while (
            !slots_[level][slot].compare_exchange_weak(
                old_head,
                node,
                std::memory_order_release,
                std::memory_order_acquire
            ));
    }

    timing* hashed_timing_wheel::insert(uint64_t wait_ticks, task awake_task, uint16_t check_id, bool is_cold) {
        timing* node = allocate_node();
        ::new (node) timing(wait_ticks, std::move(awake_task), check_id, is_cold);
        uint64_t tick = node->wait_ticks;

        uint64_t cur = current_tick_;
        if (tick <= cur)
            tick = cur + 1;

        uint64_t delta = tick - cur;

        if (delta >= MAX_TICK_RANGE) {
            node->in_overflow = true;
            overflow_.enqueue(node);
            has_overflow_.store(true, std::memory_order_release);
            return node;
        }

        size_t level = 0;
        while (level + 1 < LEVELS &&
               delta >= ticks_per_level(level + 1))
            ++level;

        push_slot(level, slot_of(tick, level), node);
        return node;
    }

    void hashed_timing_wheel::remove(timing* handle) {
        if (!handle)
            return;

        handle->cancelled.store(true, std::memory_order_release);
    }

    void hashed_timing_wheel::cascade_from(size_t level) {
        size_t slot = slot_of(current_tick_, level);
        timing* chain = slots_[level][slot].exchange(nullptr, std::memory_order_acquire);

        while (chain) {
            timing* next = chain->wheel_next.load(std::memory_order_relaxed);
            chain->wheel_next.store(nullptr, std::memory_order_relaxed);

            if (chain->cancelled.load(std::memory_order_acquire)) {
                deallocate_node(chain);
                chain = next;
                continue;
            }

            uint64_t tick = chain->wait_ticks;
            if (tick <= current_tick_)
                tick = current_tick_ + 1;

            uint64_t delta = tick - current_tick_;
            size_t finer = 0;
            while (finer + 1 < level && delta >= ticks_per_level(finer + 1))
                ++finer;

            push_slot(finer, slot_of(tick, finer), chain);
            chain = next;
        }
    }

    void hashed_timing_wheel::drain_overflow() {
        if (!has_overflow_.load(std::memory_order_relaxed))
            return;

        constexpr size_t BATCH = 256;
        timing* batch[BATCH];
        size_t drained = 0;

        size_t n;
        while ((n = overflow_.try_dequeue_bulk(batch, BATCH)) > 0) {
            for (size_t i = 0; i < n; ++i) {
                timing* t = batch[i];

                if (t->cancelled.load(std::memory_order_acquire)) {
                    deallocate_node(t);
                    continue;
                }

                uint64_t tick = t->wait_ticks;
                if (tick <= current_tick_)
                    tick = current_tick_ + 1;

                uint64_t delta = tick - current_tick_;

                if (delta >= MAX_TICK_RANGE) {
                    batch[drained++] = t;
                    continue;
                }

                t->in_overflow = false;
                size_t level = 0;
                while (level + 1 < LEVELS && delta >= ticks_per_level(level + 1))
                    ++level;
                push_slot(level, slot_of(tick, level), t);
            }
        }

        if (drained > 0)
            overflow_.enqueue_bulk(batch, drained);

        has_overflow_.store(drained > 0, std::memory_order_relaxed);
    }

    std::chrono::high_resolution_clock::time_point hashed_timing_wheel::next_deadline() const {
        auto earliest = std::chrono::high_resolution_clock::time_point::max();

        size_t start = static_cast<size_t>((current_tick_ + 1) & (SLOTS - 1));
        for (size_t i = 0; i < SLOTS; ++i) {
            size_t slot = (start + i) & (SLOTS - 1);
            timing* t = slots_[0][slot].load(std::memory_order_acquire);
            if (t) {
                while (t) {
                    if (!t->cancelled.load(std::memory_order_acquire)) {
                        auto tp = to_timepoint(t->wait_ticks);
                        if (tp < earliest)
                            earliest = tp;
                    }
                    t = t->wheel_next.load(std::memory_order_acquire);
                }
                break;
            }
        }

        if (earliest == std::chrono::high_resolution_clock::time_point::max()) {
            for (size_t L = 1; L < LEVELS; ++L) {
                for (size_t slot = 0; slot < SLOTS; ++slot) {
                    timing* t = slots_[L][slot].load(std::memory_order_acquire);
                    if (t) {
                        while (t) {
                            if (!t->cancelled.load(
                                    std::memory_order_acquire
                                )) {
                                auto tp = to_timepoint(t->wait_ticks);
                                if (tp < earliest)
                                    earliest = tp;
                            }
                            t = t->wheel_next.load(
                                std::memory_order_acquire
                            );
                        }
                        break;
                    }
                }
                if (earliest != std::chrono::high_resolution_clock::time_point::max())
                    break;
            }
        }

        if (has_overflow_.load(std::memory_order_acquire)) {
            auto now_plus_range = to_timepoint(current_tick_ + MAX_TICK_RANGE);
            if (earliest == std::chrono::high_resolution_clock::time_point::max() || now_plus_range < earliest)
                earliest = now_plus_range;
        }

        return earliest;
    }

    bool hashed_timing_wheel::empty() const {
        for (auto& level : slots_)
            for (auto& slot : level)
                if (slot.load(std::memory_order_relaxed))
                    return false;
        if (has_overflow_.load(std::memory_order_relaxed))
            return false;
        return true;
    }

    size_t hashed_timing_wheel::size() const {
        size_t n = 0;
        for (auto& level : slots_)
            for (auto& slot : level)
                for (
                    timing* t = slot.load(std::memory_order_relaxed);
                    t;
                    t = t->wheel_next.load(std::memory_order_relaxed))
                    ++n;
        if (has_overflow_.load(std::memory_order_relaxed))
            n += overflow_.size_approx();
        return n;
    }
} // namespace fast_task