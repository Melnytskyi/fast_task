// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)
//
// Driver layer: the single floating driver that owns the multiplexer and the
// timer-wheel entry points. Split out of tasks/_internal.hpp/_internal.cpp by
// S0b (plans/pool-architecture.md §4) without behaviour changes; S1 added the
// wake token, the parked-pool handshake and the handoff (§2.9).

#ifndef FAST_TASK_CORE_DRIVER
#define FAST_TASK_CORE_DRIVER

#include <atomic>

#include <fast_task/native/spin_lock.hpp>
#include <fast_task/shared.hpp>
#include <fast_task/task/task.hpp>

namespace fast_task {
    struct executors_local; // tasks/core/worker.hpp

    // Single "floating" driver that replaces the dedicated taskTimer thread and
    // the per-shard io_uring dispatcher threads. Whichever worker holds
    // driver_lock owns the multiplexer for the duration of one poll/park cycle;
    // any other thread can call wake() to interrupt a parked driver.
    //
    // Locking rules:
    //   * poll() and park_until() must be called with driver_lock held.
    //   * wake() must never take driver_lock (it is called from arbitrary task
    //     threads, including from inside insert()).
    //   * handoff() must be called *without* driver_lock held: it is the one
    //     step a worker performs after releasing the driver, and a candidate
    //     only claims the driver while the lock is genuinely free.
    //   * Because insert() and next_deadline() are serialised by driver_lock
    //     only when the inserter also holds it, the "became earliest" hint is
    //     still unsound for unlocked inserters. Do not reintroduce it here
    //     unless the insert path takes driver_lock.
    struct FT_API_LOCAL driver_context {
        fast_task::native::spin_lock driver_lock;

        // Monotonic handoff counter. A worker snapshots it *before* poll() and
        // hands the snapshot to park_until(), so a wake that lands between
        // poll() and the "parked" store is caught by the post-publish re-check
        // instead of being lost.
        std::atomic<uint32_t> wake_token{0};
        std::atomic<bool> parked{false};
        // Pool the driver is currently parked on, or UINT16_MAX when it is not
        // parked. 255 is the global pool slot, so it is a legitimate value and
        // the "none" sentinel has to be UINT16_MAX.
        std::atomic<uint16_t> parked_pool{UINT16_MAX};

        // Set when a worker gives the driver away (handoff()/ensure_driver())
        // and cleared by whoever claims the lock next.
        //
        // An idle worker must only treat "driver_lock is free" as a reason to
        // wake when this is set. Without the gate, every worker waiting for
        // work races for the driver the instant the current driver releases the
        // lock to run a batch -- which on an enqueue-bound workload means N
        // workers stampede per batch and the idle path is entered several times
        // per task.
        std::atomic<bool> claim_handoff{false};

        // Collect expired timers and drain ready I/O completions, publishing
        // woken tasks to loc (or to the global/bound queues when loc is null or
        // bound). Caller holds driver_lock.
        void poll(executors_local* loc);

        // Block until max_wait elapses, the next timer deadline fires, the
        // caller's work event changed since work_epoch_before, or a wake()
        // newer than token_before is published. Caller holds driver_lock.
        //
        // The work-event epoch is what closes the enqueue-versus-park race: a
        // producer bumps its pool's work_event (and the driver token when it
        // sees us parked on that pool), so at least one of the two post-publish
        // re-checks always observes it.
        void park_until(executors_local* loc, fast_task::time_point max_wait, uint32_t token_before, uint32_t work_epoch_before);

        // Interrupt a parked driver. Safe from any thread, never blocks.
        void wake();

        // Give the driver away. Call after releasing driver_lock and before
        // running user code, parking dormant or exiting: it pokes a multiplexer
        // parked in another thread and wakes one idle worker whose wait
        // predicate accepts an unlocked driver, so that worker claims it.
        void handoff();

        // Same, for paths that may run while another thread is already parked
        // as the driver (timer insertion): a candidate is only woken when the
        // driver lock is free, so the common case costs one atomic load.
        void ensure_driver();

        // Wake one idle worker that is allowed to poll the driver.
        void wake_driver_candidate();
    };

    // Timer-wheel entry points, implemented in tasks/timer.cpp.
    void FT_API_LOCAL startTimeController();
    void FT_API_LOCAL makeTimeWait(fast_task::time_point t);
    void FT_API_LOCAL makeTimeWait_extern(task, fast_task::time_point time_point);
    void FT_API_LOCAL resetTimeWait();
}

#endif /* FAST_TASK_CORE_DRIVER */
