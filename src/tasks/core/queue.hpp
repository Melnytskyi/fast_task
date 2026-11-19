// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)
//
// Queue layer: the registry of work-stealing deques and the per-`queue` object
// storage. Split out of tasks/_internal.hpp by S0b (plans/pool-architecture.md
// §4) without behaviour changes.
//
// S2a replaced the "scan every slot" registry with the layout from §4:
//
//   * `executor_registry_header` holds the counters, the mutation epoch and the
//     claim/release lock;
//   * `active_indices` is a dense list of the claimed slots, so a thief with two
//     peers never has to walk 1023 empty slots to find them;
//   * `slot_locks` is the thief-versus-release handshake: a thief takes the slot
//     lock around `deque->steal()`, `release()` clears the slot and then drains
//     an in-flight steal before the owner destroys the deque. Owner push/pop
//     never touches the slot lock, so the hot path is unchanged;
//   * `worker_registry_view` is the non-owning, fixed-size view (`header`,
//     `slots`, `active_indices`, `slot_locks`) that a pool storage keeps. The
//     global pool points its view at the 1024-slot `global_registry` living in
//     the runtime instead of at its own inline 64-slot registry.

#ifndef FAST_TASK_CORE_QUEUE
#define FAST_TASK_CORE_QUEUE

#include <atomic>
#include <cstdint>
#include <list>
#include <new>

#include <concurrentqueue/moodycamel/concurrentqueue.h>

#include <fast_task/native/spin_lock.hpp>
#include <fast_task/shared.hpp>
#include <fast_task/task.hpp>
#include <fast_task/task/scheduler.hpp>
#include <tasks/util/pcg32.hpp>
#include <tasks/util/work_stealing_deque.hpp>

namespace fast_task {
    // A pause instruction for the registry's claim/release spin. Kept local so
    // this header does not pull in the scheduler headers that own cpu_relax().
    inline void FT_API_LOCAL executor_registry_relax() noexcept {
#if defined(__x86_64__) || defined(__i386__)
        __builtin_ia32_pause();
#elif defined(__aarch64__) || defined(__arm__)
        asm volatile("yield" ::: "memory");
#else
        std::atomic_signal_fence(std::memory_order_seq_cst);
#endif
    }

    struct FT_API_LOCAL executor_registry_header {
        // Number of claimed slots. Maintained by claim/release only.
        alignas(hardware_destructive_interference_size) std::atomic<uint32_t> count{0};
        // Rotating start of the free-slot scan.
        alignas(hardware_destructive_interference_size) std::atomic<uint32_t> next_free_hint{0};
        // Set by the registry constructor; immutable afterwards.
        uint32_t max_slots = 0;
        // Length of the dense `active_indices` list.
        std::atomic<uint32_t> active_count{0};
        // Bumped on release/swap-remove. A scan that found nothing re-scans once
        // when it changed, so an entry swapped under the cursor is not skipped.
        std::atomic<uint32_t> mutation_epoch{0};
        // Claim/release only. Never taken by push/pop/steal.
        std::atomic_flag lock = ATOMIC_FLAG_INIT;
    };

    struct FT_API_LOCAL worker_registry_view {
        executor_registry_header* header = nullptr;
        std::atomic<work_stealing_deque<task_object*>*>* slots = nullptr;
        std::atomic<uint32_t>* active_indices = nullptr;
        fast_task::native::spin_lock* slot_locks = nullptr;

        bool valid() const noexcept {
            return header != nullptr;
        }

        void lock() noexcept {
            while (header->lock.test_and_set(std::memory_order_acquire))
                executor_registry_relax();
        }

        void unlock() noexcept {
            header->lock.clear(std::memory_order_release);
        }

        uint32_t claimed_count() const noexcept {
            return header->count.load(std::memory_order_acquire);
        }

        uint32_t active_count() const noexcept {
            return header->active_count.load(std::memory_order_acquire);
        }

        uint32_t mutation_epoch() const noexcept {
            return header->mutation_epoch.load(std::memory_order_acquire);
        }

        // Claim a slot for `deque` and append it to the dense list.
        uint32_t claim(work_stealing_deque<task_object*>* deque) noexcept {
            if (!header)
                return UINT32_MAX;

            const uint32_t max_slots = header->max_slots;
            uint32_t start = header->next_free_hint.load(std::memory_order_relaxed);
            for (uint32_t i = 0; i < max_slots; ++i) {
                uint32_t idx = start + i;
                if (idx >= max_slots)
                    idx -= max_slots;
                work_stealing_deque<task_object*>* expected = nullptr;
                if (slots[idx].compare_exchange_strong(expected, deque, std::memory_order_release, std::memory_order_relaxed)) {
                    header->next_free_hint.store(idx + 1 >= max_slots ? 0 : idx + 1, std::memory_order_relaxed);

                    lock();
                    const uint32_t pos = header->active_count.load(std::memory_order_relaxed);
                    active_indices[pos].store(idx, std::memory_order_relaxed);
                    header->active_count.store(pos + 1, std::memory_order_release);
                    header->mutation_epoch.fetch_add(1, std::memory_order_release);
                    unlock();

                    header->count.fetch_add(1, std::memory_order_release);
                    return idx;
                }
            }
            return UINT32_MAX;
        }

        // Release `idx`: remove it from the dense list, clear the slot, then
        // wait out an in-flight steal before the caller may destroy the deque.
        void release(uint32_t idx) noexcept {
            if (!header || idx >= header->max_slots)
                return;

            lock();
            const uint32_t n = header->active_count.load(std::memory_order_relaxed);
            for (uint32_t pos = 0; pos < n; ++pos) {
                if (active_indices[pos].load(std::memory_order_relaxed) == idx) {
                    // Swap-remove: the last entry fills the hole.
                    const uint32_t last = active_indices[n - 1].load(std::memory_order_relaxed);
                    active_indices[pos].store(last, std::memory_order_relaxed);
                    header->active_count.store(n - 1, std::memory_order_release);
                    header->mutation_epoch.fetch_add(1, std::memory_order_release);
                    break;
                }
            }
            unlock();

            slots[idx].store(nullptr, std::memory_order_release);
            // A thief that is inside deque->steal() holds this lock; waiting for
            // it is what makes it safe to free the deque right after.
            slot_locks[idx].lock();
            slot_locks[idx].unlock();

            header->count.fetch_sub(1, std::memory_order_release);
        }

        // Is any claimed deque non-empty? Walks the dense list only.
        bool any_work() const noexcept {
            const uint32_t n = active_count();
            for (uint32_t pos = 0; pos < n; ++pos) {
                uint32_t idx = active_indices[pos].load(std::memory_order_acquire);
                if (idx >= header->max_slots)
                    continue;
                auto* deque = slots[idx].load(std::memory_order_acquire);
                if (deque && deque->size() != 0)
                    return true;
            }
            return false;
        }

        // Steal one task from another worker's deque.
        //
        // `last_index` is the caller's steal cache (the last slot that produced
        // a task). The scan is bounded by FT_MAX_STEAL_ATTEMPTS and starts at a
        // random position of the dense list.
        bool try_steal(work_stealing_deque<task_object*>* self, pcg32& rand, uint32_t* last_index, task_object*& out) noexcept {
            if (!header)
                return false;

            const uint32_t max_slots = header->max_slots;
            auto steal_from = [&](uint32_t idx) -> bool {
                if (idx >= max_slots)
                    return false;
                // Lock first, then load: release() clears the slot before it
                // takes this lock, so holding it proves the deque is alive.
                if (!slot_locks[idx].try_lock())
                    return false;
                auto* deque = slots[idx].load(std::memory_order_acquire);
                bool got = deque != nullptr && deque != self && deque->steal(out);
                slot_locks[idx].unlock();
                return got;
            };

            if (last_index && *last_index != UINT32_MAX && steal_from(*last_index))
                return true;

            const uint32_t n = active_count();
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
                uint32_t idx = active_indices[pos].load(std::memory_order_acquire);
                if (steal_from(idx)) {
                    if (last_index)
                        *last_index = idx;
                    return true;
                }
            }
            return false;
        }
    };

    template <uint32_t MaxSlots>
    struct FT_API_LOCAL executor_registry {
        static constexpr uint32_t max_slots = MaxSlots;

        executor_registry_header header;
        std::atomic<work_stealing_deque<task_object*>*> slots[MaxSlots]{};
        std::atomic<uint32_t> active_indices[MaxSlots]{};  // dense list of claimed slots
        fast_task::native::spin_lock slot_locks[MaxSlots]; // thief vs release

        executor_registry() noexcept {
            header.max_slots = MaxSlots;
        }

        executor_registry(const executor_registry&) = delete;
        executor_registry& operator=(const executor_registry&) = delete;
        executor_registry(executor_registry&&) = delete;
        executor_registry& operator=(executor_registry&&) = delete;

        worker_registry_view view() noexcept {
            return worker_registry_view{&header, slots, active_indices, slot_locks};
        }

        uint32_t claim(work_stealing_deque<task_object*>* deque) noexcept {
            return view().claim(deque);
        }

        void release(uint32_t idx) noexcept {
            view().release(idx);
        }
    };

    using global_executor_registry = executor_registry<FT_MAX_EXECUTORS>;
    using binded_executor_registry = executor_registry<FT_BINDED_MAX_SLOTS>;

    // Queue storage per policy (§2.6). Only the queues live here: the registry
    // view is identical for every policy and stays in `worker_pool_storage`, so
    // a pool's storage is the base struct followed by this one.
    template <scheduler::queue_policy Q>
    struct queue_storage;

    template <>
    struct FT_API_LOCAL queue_storage<scheduler::queue_policy::work_stealing_lifo> {
        // Shared queue: producers push, workers drain in bulk into their inline
        // LIFO deque and steal from each other.
        moodycamel::ConcurrentQueue<task_object*> tasks;
        // Global pool only: tasks pushed while `task::max_running_tasks` is
        // reached. Workers drain it only when the hot queue is empty and the
        // limit allows it again.
        moodycamel::ConcurrentQueue<task_object*> cold_tasks;
    };

    struct queue_handle {                     //96 [sizeof]
        std::list<task> tasks;                //24
        condition_variable_any end_of_queue;  //16
        fast_task::native::spin_lock no_race; //8
        queue* tq = nullptr;                  //8
        size_t now_at_execution = 0;          //8
        size_t at_execution_max = 0;          //8
        bool destructed = false;              //1
        bool is_running = false;              //1
                                              //6 [padding]
    };
}

#endif /* FAST_TASK_CORE_QUEUE */
