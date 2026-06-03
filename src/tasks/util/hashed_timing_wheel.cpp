// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include "hashed_timing_wheel.hpp"
#include <limits>

namespace fast_task {
    timing_pool::timing_pool() noexcept {}

    timing_pool::~timing_pool() {
        chunk* c = chunks_;
        while (c) {
            chunk* next = c->next;
            delete c;
            c = next;
        }
    }

    timing* timing_pool::allocate() {
        if (!freelist_) {
            auto* c = new chunk;
            c->next = chunks_;
            chunks_ = c;
            for (size_t i = 0; i < CHUNK_SIZE; ++i) {
                c->nodes[i].wheel_next = freelist_;
                c->nodes[i].wheel_prev = nullptr;
                c->nodes[i].wheel_level = 0;
                c->nodes[i].wheel_slot = 0;
                c->nodes[i].in_overflow = false;
                freelist_ = &c->nodes[i];
            }
        }

        timing* t = freelist_;
        freelist_ = t->wheel_next;
        t->wheel_next = nullptr;
        ++count_;
        return t;
    }

    void timing_pool::deallocate(timing* t) noexcept {
        t->wheel_next = freelist_;
        t->wheel_prev = nullptr;
        t->wheel_level = 0;
        t->wheel_slot = 0;
        t->in_overflow = false;
        freelist_ = t;
        --count_;
    }

    hashed_timing_wheel::hashed_timing_wheel() {
        epoch_ = std::chrono::high_resolution_clock::now();
        for (auto& level : slots_)
            for (auto& slot : level)
                slot = nullptr;
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

    uint64_t hashed_timing_wheel::to_ticks(
        std::chrono::high_resolution_clock::time_point tp
    ) const {
        auto dur = tp - epoch_;
        auto us = std::chrono::duration_cast<std::chrono::microseconds>(dur).count();
#if FT_TIMER_PRECISION == 1
        return static_cast<uint64_t>(us);
#elif FT_TIMER_PRECISION == 1000
        return static_cast<uint64_t>(us / 1000);
#else
        return static_cast<uint64_t>(us / 10000);
#endif
    }

    std::chrono::high_resolution_clock::time_point
    hashed_timing_wheel::to_timepoint(uint64_t ticks) const {
#if FT_TIMER_PRECISION == 1
        auto dur = std::chrono::microseconds(ticks);
#elif FT_TIMER_PRECISION == 1000
        auto dur = std::chrono::milliseconds(ticks);
#else
        auto dur = std::chrono::milliseconds(ticks * 10);
#endif
        return epoch_ + dur;
    }

    void hashed_timing_wheel::link(timing& t, size_t level, uint64_t use_tick) {
        size_t slot = slot_of(use_tick, level);
        t.wheel_level = static_cast<uint8_t>(level);
        t.wheel_slot = static_cast<uint8_t>(slot);
        t.in_overflow = false;

        if (slots_[level][slot]) {
            slots_[level][slot]->wheel_prev = &t;
        }
        t.wheel_next = slots_[level][slot];
        t.wheel_prev = nullptr;
        slots_[level][slot] = &t;
    }

    void hashed_timing_wheel::unlink(timing& t) {
        if (t.wheel_next)
            t.wheel_next->wheel_prev = t.wheel_prev;
        if (t.wheel_prev)
            t.wheel_prev->wheel_next = t.wheel_next;
        else
            slots_[t.wheel_level][t.wheel_slot] = t.wheel_next;

        t.wheel_next = nullptr;
        t.wheel_prev = nullptr;
    }

    timing* hashed_timing_wheel::insert(timing&& t) {
        timing* node = pool_.allocate();
        ::new (node) timing(std::move(t));

        uint64_t tick = to_ticks(node->wait_timepoint);

        if (tick <= current_tick_)
            tick = current_tick_ + 1;

        uint64_t delta = tick - current_tick_;

        if (delta >= MAX_TICK_RANGE) {
            node->in_overflow = true;
            overflow_.push(node);
            has_overflow_ = true;
            return node;
        }

        size_t level = 0;
        while (level + 1 < LEVELS && delta >= ticks_per_level(level + 1))
            ++level;

        link(*node, level, tick);
        return node;
    }

    void hashed_timing_wheel::remove(timing* handle) {
        if (!handle)
            return;

        if (handle->in_overflow) {
            handle->wait_timepoint = std::chrono::high_resolution_clock::time_point::min();
            return;
        }

        unlink(*handle);
        pool_.deallocate(handle);
    }

    void hashed_timing_wheel::cascade_from(size_t level) {
        size_t slot = slot_of(current_tick_, level);
        timing* t = slots_[level][slot];
        slots_[level][slot] = nullptr;

        while (t) {
            timing* next = t->wheel_next;
            t->wheel_next = nullptr;
            t->wheel_prev = nullptr;

            uint64_t delta = to_ticks(t->wait_timepoint) - current_tick_;
            size_t finer = 0;
            while (finer + 1 < level && delta >= ticks_per_level(finer + 1))
                ++finer;
            link(*t, finer, to_ticks(t->wait_timepoint));

            t = next;
        }
    }

    void hashed_timing_wheel::drain_overflow() {
        while (!overflow_.empty()) {
            timing* t = overflow_.top();
            overflow_.pop();

            if (t->wait_timepoint ==
                std::chrono::high_resolution_clock::time_point::min()) {
                pool_.deallocate(t);
                continue;
            }

            t->in_overflow = false;

            uint64_t tick = to_ticks(t->wait_timepoint);
            if (tick <= current_tick_)
                tick = current_tick_ + 1;

            uint64_t delta = tick - current_tick_;

            if (delta >= MAX_TICK_RANGE) {
                overflow_.push(t);
                t->in_overflow = true;
                continue;
            }

            size_t level = 0;
            while (level + 1 < LEVELS && delta >= ticks_per_level(level + 1))
                ++level;
            link(*t, level, tick);
        }

        has_overflow_ = false;
    }

    std::chrono::high_resolution_clock::time_point
    hashed_timing_wheel::next_deadline() const {
        auto earliest = std::chrono::high_resolution_clock::time_point::max();

        size_t start = static_cast<size_t>((current_tick_ + 1) & 0xFF);
        for (size_t i = 0; i < SLOTS; ++i) {
            size_t slot = (start + i) & 0xFF;
            if (slots_[0][slot]) {
                timing* t = slots_[0][slot];
                while (t) {
                    if (t->wait_timepoint < earliest)
                        earliest = t->wait_timepoint;
                    t = t->wheel_next;
                }
                break;
            }
        }

        if (earliest == std::chrono::high_resolution_clock::time_point::max()) {
            for (size_t L = 1; L < LEVELS; ++L) {
                for (size_t slot = 0; slot < SLOTS; ++slot) {
                    if (slots_[L][slot]) {
                        timing* t = slots_[L][slot];
                        while (t) {
                            if (t->wait_timepoint < earliest)
                                earliest = t->wait_timepoint;
                            t = t->wheel_next;
                        }
                        break;
                    }
                }
                if (earliest != std::chrono::high_resolution_clock::time_point::max())
                    break;
            }
        }

        if (has_overflow_ && !overflow_.empty()) {
            auto* t = overflow_.top();
            if (t->wait_timepoint !=
                std::chrono::high_resolution_clock::time_point::min()) {
                if (t->wait_timepoint < earliest)
                    earliest = t->wait_timepoint;
            }
        }

        return earliest;
    }

    bool hashed_timing_wheel::empty() const {
        for (auto& level : slots_)
            for (auto& slot : level)
                if (slot)
                    return false;
        if (has_overflow_)
            return false;
        return true;
    }

    size_t hashed_timing_wheel::size() const {
        size_t n = 0;
        for (auto& level : slots_)
            for (auto& slot : level)
                for (timing* t = slot; t; t = t->wheel_next)
                    ++n;
        if (has_overflow_)
            n += overflow_.size();
        return n;
    }
} // namespace fast_task