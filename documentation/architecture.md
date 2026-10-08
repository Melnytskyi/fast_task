# Architecture Overview

This page describes the internal design of Fast Task: the work-stealing scheduler,
timer management, preemption mechanics, and scheduler-aware synchronization.

## Work-Stealing Scheduler

To minimize scheduling overhead and lock contention, Fast Task uses a multi-tiered
queue system:

- `loc.local_tasks` — a lock-free, thread-local work-stealing deque. Prioritizes
  cache locality, since a worker usually resumes its own most recently pushed task.
- `glob.tasks` — a global queue for hot tasks ready to be picked up by any
  available scheduler thread.
- `glob.cold_tasks` — a fallback queue for uninitialized tasks (for example,
  stackful tasks waiting for stack allocation).

Workers prefer their local deque, then steal from the global queue, and finally
attempt to steal from random peers. The number of steal attempts is bounded by
`FAST_TASK_MAX_STEAL_ATTEMPTS` (see [Getting Started](getting-started.md#tuning-parameters)).

## Time and Awake Management

Task timeouts and deadlines are handled by a dedicated `taskTimer` thread. To
prevent race conditions and redundant wake-ups, each task maintains an
`awake_check` counter. If a task is awakened via synchronization before its timer
expires, this counter invalidates the pending timed event, so the stale timer
callback is ignored.

The timer wheel precision is configurable via `FAST_TASK_TIMER_PRECISION`
(`1us`, `1ms`, or `10ms`). See [Getting Started](getting-started.md#tuning-parameters).

## Scheduler-Aware Synchronization & Preemption Limits

Fast Task's custom synchronization primitives (for example
[`mutex`](synchronization.md#mutex)) and its own native locks
([`fast_task::native::mutex`](native.md#nativemutex)) are scheduler-aware. When the
preemptive scheduler is enabled, they automatically prevent context switching while
a lock is held.

> **Crucially, standard library features that rely on hidden internal OS locks —
> such as `malloc`, `new`, `std::cout`, and `std::mutex` — lack this awareness and
> are completely incompatible with preemption.** If the scheduler hijacks a thread
> while it holds an internal system lock, it can cause deadlocks.

To safely use standard library allocations, I/O streams, or OS-level locks with
preemption enabled, wrap those operations in an
[`interrupt_unsafe_region`](synchronization.md#interrupt-unsafe-regions).

Additionally, the library's primitives solve standard C++ spurious wakeups using
dedicated condition variables with targeted per-thread flags.

## Preemption Mechanics

If enabled, preemption runs outside the standard time controller:

- **Windows:** an `interrupt_processor` intercepts expired timers and uses
  `insert_context` to hijack the execution flow.
- **Linux:** a dedicated `PREEMPTION_SIGNAL` interrupts the thread.

In both cases, the handler safely checks for lock-free boundaries before invoking
`swapCtx` to forcibly yield the task. The time slice per priority level is
configurable (see [Getting Started](getting-started.md#preemption-quantum-tuning)).

## Cooperative Transfers

Fast Task avoids a full context switch when one task can hand off execution
directly to another. [`this_task::transfer_to`](task/coroutines.md#this_tasktransfer_to)
performs such a transfer, subject to strict conditions (same worker binding, target
schedulable, no pending transfers, and within the cooperative transfer limit set by
`FAST_TASK_TASK_TRANSFERS_LIMIT`).

## Execution Contexts

A task can run in one of two modes, controlled by the `is_on_scheduler` flag:

- **Own stack** (default) — the task has its own stack and behaves like a native
  thread. It can use all synchronization primitives and block freely.
- **On scheduler stack** (`is_on_scheduler = true`) — the task runs directly on the
  scheduler's worker stack, reducing memory usage. Such tasks are effectively
  cooperative only: the scheduler cannot interrupt itself, so the task must never
  consume too much time and must use the `enter_*` methods for synchronization.
  Regular blocking operations throw an exception. This mode is how stackless
  coroutines are implemented.

## Task Object Layout

The [`task`](tasks.md) class internally uses callbacks (`on_start`, `on_exception`,
`on_await`, `on_cancel`, `on_destruct`) described by
[`task_vtable`](../include/fast_task/task/task.hpp:42). The `on_await` and
`on_cancel` callbacks execute on the calling thread and can be used, for example, to
wrap sockets in the task interface. The `on_start` callback executes on its own
stack like a normal task and allows using all synchronization primitives.

The task has a small-buffer optimization (SBO) to reduce memory consumption for
simple tasks that only have `on_start` and `on_exception` callbacks. The inline
buffer size is [`task::sbo_size`](../include/fast_task/task/task.hpp:97) (64 bytes).

## Related Pages

- [Scheduler](scheduler.md) — the public scheduler API.
- [Synchronization](synchronization.md) — the primitives referenced above.
- [Coroutines](task/coroutines.md) — the stackless execution model.
