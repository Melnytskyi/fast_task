// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)
//
// Pool layer: the pool storage that every worker serves (plans/pool-architecture.md
// §2.2). Split out of tasks/_internal.hpp by S0b; S1 replaced the condition
// variables with two eventcounts (§2.8).
//
// S2a replaced the old `binded_context`/`executor_global` pair with:
//
//   * `worker_pool_storage` — one self-contained pool: its inline 64-slot
//     registry (`pool_entry`), its configuration, its per-pool accounting, its
//     two eventcounts and its queues. The whole struct fits in
//     `worker_pool_storage_size` (8192) bytes with room for the S2b policy
//     storage, which is why the global pool can live in a reserved buffer and a
//     user pool can live in a `worker_pool` object;
//   * `worker_pool_runtime` — the counters that used to be globals
//     (`executing_tasks`, `in_run_tasks`, worker counts, completed tasks).
//
// The table that maps a `uint8_t` pool index to its storage lives in the
// runtime (slot 255 is the global pool) because the storage itself must not
// know about the table.

#ifndef FAST_TASK_CORE_POOL
#define FAST_TASK_CORE_POOL

#include <atomic>
#include <cstdint>
#include <optional>

#include <concurrentqueue/moodycamel/concurrentqueue.h>

#include <fast_task/native/condition_variable.hpp>
#include <fast_task/native/mutex.hpp>
#include <fast_task/native/spin_lock.hpp>
#include <fast_task/shared.hpp>
#include <fast_task/task.hpp>
#include <tasks/core/event.hpp>
#include <tasks/core/pool_ops.hpp>
#include <tasks/core/queue.hpp>
#include <tasks/util/hill_climbing.hpp>

namespace fast_task {
    // 0..254 are user pools, 255 is the global pool (§2.2).
    constexpr uint8_t user_pool_count = 255;
    constexpr uint8_t global_pool_index = 255;
    // Number of table slots: the user pools plus the global slot.
    constexpr size_t pool_table_size = 256;

    // Legacy id -> table slot. Ids 0..254 map to their slot; anything else
    // (including the old "no bind" sentinel) is the global pool. This is
    // transitional and disappears with the legacy API in S2c.
    inline constexpr uint8_t bind_pool_index(uint16_t id) noexcept {
        return id < static_cast<uint16_t>(global_pool_index) ? static_cast<uint8_t>(id) : global_pool_index;
    }

    // Fixed budget of one pool storage. `FAST_TASK_BINDED_MAX_SLOTS` is capped at
    // 64 by CMake because the registry is inline; growing it requires growing
    // this budget.
    constexpr size_t worker_pool_storage_size = 8192;

    // Per-pool accounting (§2.11).
    //
    //   executing_tasks: created-but-not-completed (queued, running, suspended)
    //   in_run_tasks:    currently executing on a pool worker
    //
    // They are per pool so `wait_idle`/`await_no_tasks` can be answered without
    // a global RMW on every task completion.
    struct FT_API_LOCAL worker_pool_runtime {
        // Control plane: written on pool (re)configuration and worker
        // start/stop only, read by workers in their idle loop. One line.
        std::atomic<uint16_t> target_workers{0};
        std::atomic<uint16_t> active_workers{0};
        std::atomic<uint16_t> foreign_workers{0};
        std::atomic<uint16_t> dormant_workers{0};
        std::atomic<uint16_t> borrowed_in{0};
        std::atomic<uint16_t> borrowed_out{0};
        std::atomic<uint16_t> live_threads{0};
        std::atomic<uint32_t> affinity_failures{0};
        std::atomic<bool> stop_requested{false};
        std::atomic<bool> paused{false};

        // Data plane. Each of these is RMW'ed on every task, so each gets its
        // own cache line. Sharing one line between `executing_tasks` (every
        // publisher adds, every completing task subtracts) and `in_run_tasks`
        // (each worker adds and subtracts twice per executed task) cost 150 ns
        // of publish time at 1M empty tasks: the publisher's lock-xadd had to
        // steal the line back from whichever of the 16 workers had just
        // touched it. Keep them apart (plans/pool-architecture.md §6.9).
        alignas(64) std::atomic<size_t> executing_tasks{0};
        alignas(64) std::atomic<size_t> in_run_tasks{0};
        alignas(64) std::atomic<uint64_t> completed_tasks{0};
    };

    // The inline registry of one user pool (§2.2/§4).
    struct FT_API_LOCAL pool_entry {
        binded_executor_registry registry; // 64 slots, inline; owns the dense active list
        uint32_t ordinal = 0;
    };

    inline void FT_API_LOCAL init_registry_slot(pool_entry& entry, uint8_t index) noexcept {
        entry.ordinal = index;
    }

    // One pool, policy independent part (§2.5). Non-movable: it is either
    // placement-new'ed into the reserved global buffer or into a heap
    // `configured_worker_pool_storage`, and every pointer handed out for it
    // (executors_local::owner_pool, the table slot) must stay valid.
    //
    // Nothing here depends on the queue policy: the queues live in the derived
    // storage and are reached only through `ops`, so the router, the worker loop
    // and the notification paths carry no policy branch.
    struct alignas(64) FT_API_LOCAL worker_pool_storage {
        pool_entry entry;
        scheduler::worker_pool_options config;
        worker_pool_runtime runtime;
        scheduler_event work_event;    // active idle workers (§2.8)
        scheduler_event dormant_event; // dormant and paused workers

        // View onto the registry that owns this pool's worker deques: the
        // inline `entry.registry` for a user pool, the runtime's 1024-slot
        // registry for the global pool.
        worker_registry_view registry;

        // Dispatch table of the (queue, idle) policy of the concrete storage.
        worker_pool_ops ops{};

        // Inline hill climber (§2.2; wired in S4).
        std::optional<util::hill_climb> climber;

        // Transitional members used by the legacy close protocol only. S2c
        // replaces this with the join/leave lifecycle of §2.13 and §2.17.
        condition_variable_any closed_notifier;
        fast_task::native::rw_mutex no_race;

        uint8_t pool_index = global_pool_index; // 0..254 user, 255 global
        bool is_global : 1 = false;
        bool started : 1 = false;
        bool closing : 1 = false;
        bool explicitly_configured : 1 = false;
        bool lazily_initialized : 1 = false;
        // shut_down() unregistered the slot but the storage still exists.
        std::atomic<bool> slot_released{false};

    protected:
        // Only a concrete `configured_worker_pool_storage<Q, I>` may exist: it
        // is the one that installs `ops`, and every entry point here assumes a
        // non-empty table. A directly constructed base would call through null
        // pointers on the first publish, so it is not constructible at all.
        worker_pool_storage() noexcept = default;

    public:
        worker_pool_storage(const worker_pool_storage&) = delete;
        worker_pool_storage& operator=(const worker_pool_storage&) = delete;
        worker_pool_storage(worker_pool_storage&&) = delete;
        worker_pool_storage& operator=(worker_pool_storage&&) = delete;

        uint8_t index() const noexcept {
            return pool_index;
        }

        bool queue_empty() const noexcept {
            return ops.pending(*this) == 0;
        }
    };

    // Storage of one concrete pool: the base plus the queue storage of Q. The
    // idle policy I only selects function pointers, so it costs no bytes.
    template <scheduler::queue_policy Q, scheduler::idle_policy I>
    struct FT_API_LOCAL configured_worker_pool_storage : worker_pool_storage {
        queue_storage<Q> queue_data;

        // Defined in tasks/core/pool_ops.cpp next to make_ops<Q, I>(), so the
        // dispatch table is installed in exactly one place.
        configured_worker_pool_storage() noexcept;

        configured_worker_pool_storage(const configured_worker_pool_storage&) = delete;
        configured_worker_pool_storage& operator=(const configured_worker_pool_storage&) = delete;
        configured_worker_pool_storage(configured_worker_pool_storage&&) = delete;
        configured_worker_pool_storage& operator=(configured_worker_pool_storage&&) = delete;
    };

    // S2b ships exactly one combination; S3a adds priority_fifo and busy_spin.
    using default_pool_storage = configured_worker_pool_storage<
        scheduler::queue_policy::work_stealing_lifo,
        scheduler::idle_policy::wait>;

    static_assert(sizeof(default_pool_storage) <= worker_pool_storage_size, "worker_pool_storage must fit into worker_pool_storage_size (8192)");
    static_assert(alignof(default_pool_storage) <= 64, "worker_pool_storage alignment must not exceed a cache line");

    // Point `storage` at the table slot `index`. The global pool keeps its
    // registry in the runtime (1024 slots) and only borrows the view, so its
    // inline `entry.registry` stays unused.
    void FT_API_LOCAL init_pool_storage(worker_pool_storage& storage, uint8_t index, bool is_global) noexcept;

    // Install a user pool in the first free table slot (0..254) and return the
    // slot. Throws std::length_error when the table is full: the 255-slot table
    // is the S2a gate for table exhaustion.
    uint8_t allocate_pool_slot(worker_pool_storage* storage);

    // Recompute the cached "first pool that allows implicit start". Must be
    // called after a pool is installed, its `allow_implicit_start` changes or a
    // slot is released (plans/pool-architecture.md §2.10).
    void FT_API_LOCAL refresh_implicit_pool();

    // Unregister slot `index` and return the storage that was there. The caller
    // owns it (legacy pools are heap-allocated). The global slot is never
    // released here.
    worker_pool_storage* release_pool_slot(uint8_t index) noexcept;

    // Move a task's in-flight accounting to `to` (plans/pool-architecture.md
    // §2.11). The destination counter is incremented before the source is
    // decremented, so the sum across pools never transiently reaches zero.
    // `in_run_tasks` is deliberately not moved: the task is still running on
    // the old worker.
    void FT_API_LOCAL retarget_task(task_object& t, worker_pool_storage& to) noexcept;
}

#endif /* FAST_TASK_CORE_POOL */
