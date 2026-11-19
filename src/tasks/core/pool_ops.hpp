// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)
//
// Policy dispatch (plans/pool-architecture.md §2.5).
//
// `worker_pool_storage` is policy independent; `configured_worker_pool_storage
// <Q, I>` appends the queue storage of Q and installs the table below, which is
// specialised for (Q, I). Every call site therefore pays one indirect call and
// has no policy branch at all:
//
//   route_task          -> ops.enqueue
//   fetch_one           -> ops.dequeue_bulk
//   idle wait / prober  -> ops.wait_until, ops.has_queued_work
//   park witnesses      -> ops.has_runnable_work
//   close / clean_up    -> ops.drain_all, ops.drain_cold, ops.destroy
//
// S2b ships exactly one combination (`work_stealing_lifo` + `wait`); S3a adds
// `priority_fifo` and `busy_spin`, which replace the function bodies and not
// the worker loop.

#ifndef FAST_TASK_CORE_POOL_OPS
#define FAST_TASK_CORE_POOL_OPS

#include <cstddef>
#include <vector>

#include <fast_task/shared.hpp>
#include <fast_task/task/scheduler.hpp>

namespace fast_task {
    struct executors_local;      // tasks/core/worker.hpp
    struct worker_pool_storage;  // tasks/core/pool.hpp

    struct FT_API_LOCAL worker_pool_ops {
        // ---- publish path ---------------------------------------------------

        // Publish `raw` (null is the retire signal). Returns true when the task
        // went into this worker's inline deque and needs no shared wake, i.e.
        // the caller must not touch the queue again.
        bool (*enqueue)(worker_pool_storage&, executors_local*, task_object*) noexcept;

        // Put a task back on the shared queue *without* notifying: the caller
        // owns the wake (worker teardown drains, bulk-drain leftovers).
        bool (*requeue)(worker_pool_storage&, task_object*) noexcept;

        // Timing-wheel "cold" tasks (global pool throttle).
        bool (*enqueue_cold)(worker_pool_storage&, task_object*) noexcept;

        // ---- consume path ---------------------------------------------------

        // Take up to `max` runnable tasks into `out`; returns the count. Empty
        // means "nothing to run", never "retry".
        size_t (*dequeue_bulk)(worker_pool_storage&, executors_local*, task_object** out, size_t max) noexcept;

        // ---- idle path ------------------------------------------------------

        // Cheap witness: work that a single `dequeue_bulk` would return. This
        // is the one the spin prober uses, because it must not drag the other
        // workers' deque heads (= their cache lines) on every iteration.
        bool (*has_queued_work)(const worker_pool_storage&, const executors_local*) noexcept;

        // Full witness: queued work *or* a peer's deque with a stealable task.
        // Used where a missed wake would strand a task: the eventcount
        // predicate and the driver's park re-check. Scans the dense active list
        // (§2.6), so it is O(active workers) and never called in a spin loop.
        bool (*has_runnable_work)(const worker_pool_storage&, const executors_local*) noexcept;

        // Idle wait of policy I. Returns true if the caller should look for
        // work again, false if the deadline passed. A deadline of
        // time_point::max() means "until woken".
        bool (*wait_until)(worker_pool_storage&, executors_local*, fast_task::time_point) noexcept;

        // ---- control / legacy close path (S2c replaces the protocol) --------

        void (*drain_all)(worker_pool_storage&, std::vector<task_object*>& out) noexcept;
        void (*drain_cold)(worker_pool_storage&) noexcept;
        size_t (*pending)(const worker_pool_storage&) noexcept;

        // Run the concrete storage's destructor in place (reserved global
        // buffer), and free a heap-allocated one. `deallocate` also destroys.
        void (*destroy)(worker_pool_storage&) noexcept;
        void (*deallocate)(worker_pool_storage&) noexcept;
    };

    template <scheduler::queue_policy Q, scheduler::idle_policy I>
    constexpr worker_pool_ops make_ops() noexcept;
}

#endif /* FAST_TASK_CORE_POOL_OPS */
