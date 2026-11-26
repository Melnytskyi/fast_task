// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_CORE_EXECUTOR_REGISTRY
#define FAST_TASK_CORE_EXECUTOR_REGISTRY

#include <atomic>
#include <cstdint>

#include <fast_task/native/spin_lock.hpp>
#include <fast_task/shared.hpp>
#include <fast_task/task.hpp>
#include <tasks/util/macro.hpp>
#include <tasks/util/pcg32.hpp>
#include <tasks/util/work_stealing_deque.hpp>

namespace fast_task {
    inline constexpr uint8_t slot_flag_nonempty = 0x1;

    template <uint32_t MaxSlots, bool PadSlots = (MaxSlots > FT_BINDED_MAX_SLOTS)>
    struct FT_API_LOCAL executor_registry {
        struct alignas(PadSlots ? 64 : alignof(void*)) slot_entry {
            std::atomic<work_stealing_deque<task_object*>*> deque{nullptr};
            mutable fast_task::native::spin_lock lock;
            std::atomic<uint8_t> flags{0};
            std::atomic<uint8_t> llc{UINT8_MAX};
        };

        slot_entry entries[MaxSlots]{};
        std::atomic<uint32_t> active_indices[MaxSlots]{};

        std::atomic<uint32_t> active_count{0};
        std::atomic<uint32_t> next_free_hint{0};
        fast_task::native::spin_lock lock;

        executor_registry() noexcept = default;

        executor_registry(const executor_registry&) = delete;
        executor_registry& operator=(const executor_registry&) = delete;
        executor_registry(executor_registry&&) = delete;
        executor_registry& operator=(executor_registry&&) = delete;

        uint32_t active() const noexcept {
            return active_count.load(std::memory_order_acquire);
        }

        void store_slot_flags(uint32_t idx, uint8_t flags) noexcept {
            entries[idx].flags.store(flags, std::memory_order_relaxed);
        }

        bool maybe_nonempty(uint32_t idx) const noexcept {
            return (entries[idx].flags.load(std::memory_order_relaxed) & slot_flag_nonempty) != 0;
        }

        uint32_t claim(work_stealing_deque<task_object*>* deque, uint8_t llc) noexcept {
            const uint32_t start = next_free_hint.load(std::memory_order_relaxed);
            for (uint32_t i = 0; i < MaxSlots; ++i) {
                uint32_t idx = start + i;
                if (idx >= MaxSlots)
                    idx -= MaxSlots;
                work_stealing_deque<task_object*>* expected = nullptr;
                if (!entries[idx].deque.compare_exchange_strong(expected, deque, std::memory_order_release, std::memory_order_relaxed))
                    continue;
                next_free_hint.store(idx + 1 >= MaxSlots ? 0 : idx + 1, std::memory_order_relaxed);
                entries[idx].flags.store(0, std::memory_order_relaxed);
                entries[idx].llc.store(llc, std::memory_order_relaxed);

                lock.lock();
                const uint32_t pos = active_count.load(std::memory_order_relaxed);
                active_indices[pos].store(idx, std::memory_order_relaxed);
                active_count.store(pos + 1, std::memory_order_release);
                lock.unlock();
                return idx;
            }
            return UINT32_MAX;
        }

        void release(uint32_t idx) noexcept {
            if (idx >= MaxSlots)
                return;

            entries[idx].flags.store(0, std::memory_order_relaxed);
            entries[idx].llc.store(UINT8_MAX, std::memory_order_relaxed);
            lock.lock();
            const uint32_t n = active_count.load(std::memory_order_relaxed);
            for (uint32_t pos = 0; pos < n; ++pos) {
                if (active_indices[pos].load(std::memory_order_relaxed) == idx) {
                    const uint32_t last = active_indices[n - 1].load(std::memory_order_relaxed);
                    active_indices[pos].store(last, std::memory_order_relaxed);
                    active_count.store(n - 1, std::memory_order_release);
                    break;
                }
            }
            lock.unlock();

            entries[idx].deque.store(nullptr, std::memory_order_release);
            entries[idx].lock.lock();
            entries[idx].lock.unlock();
        }

        bool any_work() const noexcept {
            const uint32_t n = active_count.load(std::memory_order_acquire);
            for (uint32_t pos = 0; pos < n; ++pos) {
                const uint32_t idx = active_indices[pos].load(std::memory_order_acquire);
                if (idx >= MaxSlots)
                    continue;
                if (entries[idx].deque.load(std::memory_order_acquire) == nullptr)
                    continue;
                entries[idx].lock.lock();
                auto* deque = entries[idx].deque.load(std::memory_order_acquire);
                const bool non_empty = deque != nullptr && deque->size() != 0;
                entries[idx].lock.unlock();
                if (non_empty)
                    return true;
            }
            return false;
        }

        bool try_steal(work_stealing_deque<task_object*>* self, pcg32& rand, uint32_t* last_index, task_object*& out, uint8_t llc) noexcept {
            auto steal_from = [&](uint32_t idx) -> bool {
                if (idx >= MaxSlots)
                    return false;
                if (!maybe_nonempty(idx))
                    return false;
                if (!entries[idx].lock.try_lock())
                    return false;
                auto* deque = entries[idx].deque.load(std::memory_order_acquire);
                const bool got = deque != nullptr && deque != self && deque->steal(out);
                entries[idx].lock.unlock();
                return got;
            };

            if (last_index && *last_index != UINT32_MAX && steal_from(*last_index))
                return true;

            const uint32_t n = active_count.load(std::memory_order_acquire);
            if (n == 0)
                return false;

            uint32_t attempts = FT_MAX_STEAL_ATTEMPTS;
            if (attempts > n)
                attempts = n;

            const uint32_t start = rand.next() % n;
            for (uint32_t i = 0; i < attempts; ++i) {
                uint32_t pos = start + i;
                if (pos >= n)
                    pos -= n;
                const uint32_t idx = active_indices[pos].load(std::memory_order_acquire);
                if (llc != UINT8_MAX && idx < MaxSlots && entries[idx].llc.load(std::memory_order_relaxed) != llc)
                    continue;
                if (steal_from(idx)) {
                    if (last_index)
                        *last_index = idx;
                    return true;
                }
            }
            if (llc != UINT8_MAX) {
                for (uint32_t i = 0; i < n; ++i) {
                    uint32_t pos = start + i;
                    if (pos >= n)
                        pos -= n;
                    const uint32_t idx = active_indices[pos].load(std::memory_order_acquire);
                    if (idx < MaxSlots && entries[idx].llc.load(std::memory_order_relaxed) == llc)
                        continue;
                    if (steal_from(idx)) {
                        if (last_index)
                            *last_index = idx;
                        return true;
                    }
                }
            }
            return false;
        }
    };

    using global_executor_registry = executor_registry<FT_MAX_EXECUTORS>;
    using binded_executor_registry = executor_registry<FT_BINDED_MAX_SLOTS>;
}

#endif /* FAST_TASK_CORE_EXECUTOR_REGISTRY */
