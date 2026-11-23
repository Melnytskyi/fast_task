# Scheduler

The scheduler is the runtime that owns worker threads, distributes tasks, and
drives timers. This page documents the public control surface: the
[`scheduler`](../include/fast_task/task/scheduler.hpp:25) namespace, the
[`worker_pool`](../include/fast_task/task/scheduler.hpp:259) and
[`worker_context`](../include/fast_task/task/scheduler.hpp:197) types, the
[`queue`](../include/fast_task/task/queue.hpp:18) type, and the
[`deadline_timer`](../include/fast_task/task/deadline_timer.hpp:21) type.

For the internal design (work-stealing deques, the two eventcounts per pool, the
timer wheel, preemption mechanics), see [Architecture](architecture.md).

Header: [`fast_task/task/scheduler.hpp`](../include/fast_task/task/scheduler.hpp)
(included by [`fast_task.hpp`](../include/fast_task.hpp)).

---

## Scheduling tasks

| Function | Description |
|----------|-------------|
| [`start(task&&)`](../include/fast_task/task/scheduler.hpp:362) / [`start(const task&)`](../include/fast_task/task/scheduler.hpp:365) | Submits a task to the global pool for immediate execution |
| [`start(std::list<task>&)`](../include/fast_task/task/scheduler.hpp:363) / [`start(std::vector<task>&)`](../include/fast_task/task/scheduler.hpp:364) | Submits a batch |
| [`schedule_until(task, tp)`](../include/fast_task/task/scheduler.hpp:349) | Runs a task no earlier than `tp` |
| [`schedule(task, duration)`](../include/fast_task/task/scheduler.hpp:352) | Runs a task after a delay |

```cpp
fast_task::task t = fast_task::task::create([]{ /* work */ });
fast_task::scheduler::start(std::move(t));
```

A task with no pool assigned is routed to the global pool unless some pool
opted into implicit routing with `allow_implicit_start` — see
[Global pool and default routing](#global-pool-and-default-routing).

---

## Worker pools

A [`worker_pool`](../include/fast_task/task/scheduler.hpp:259) owns a set of
worker threads, its own queues, and its own wake events. A pool is
**non-movable**: its storage lives inside the object, so the object's address is
part of the pool's identity and must not change. [`create()`](../include/fast_task/task/scheduler.hpp:284)
returns a prvalue, so `auto pool = worker_pool::create(options);` constructs the
pool in the caller's storage without a copy.

```cpp
fast_task::scheduler::worker_pool_options options;
options.name = "render";
options.min_workers = 2;
options.max_workers = 8;
options.balancer = fast_task::scheduler::worker_balancer::hill_climb;

auto pool = fast_task::scheduler::worker_pool::create(std::move(options));

fast_task::task t = fast_task::task::create([]{ /* work */ });
pool.post(std::move(t));
```

The pool is registered in a fixed table: 255 user pools plus the reserved global
pool. When the table is full the constructor throws `std::length_error`; the slot
is released by the destructor.

### Lifecycle

| Member | Description |
|--------|-------------|
| [`worker_pool(options)`](../include/fast_task/task/scheduler.hpp:276) | Constructs, registers a slot, spawns the initial workers |
| [`create(options)`](../include/fast_task/task/scheduler.hpp:284) | Same, as an elided prvalue |
| [`~worker_pool()`](../include/fast_task/task/scheduler.hpp:277) | Drains, then stops the pool; releases the slot |
| [`global()`](../include/fast_task/task/scheduler.hpp:291) | Handle to the process-wide pool |
| [`configure_global(options)`](../include/fast_task/task/scheduler.hpp:295) | Configures the lazy global pool before it runs |
| [`is_global()`](../include/fast_task/task/scheduler.hpp:297) | Whether this handle fronts the global pool |

Destruction is graceful by default: queued tasks are drained and finished before
the workers stop. Set `abort_tasks_on_shutdown` in the options to cancel queued
and suspended tasks instead. Destroying a pool from a task that belongs to it is
a fatal error; a host thread that joined the pool is detached first.

Retirement during shutdown is driven by the pool's active-worker counter, not by
a per-worker signal: a worker leaves as soon as a full pass finds no work left
and the pool is stopping, so a worker that consumed the stop signal together
with the last task still exits. Workers that join a pool that is already
stopping are allowed to join and count themselves, which is what makes the
counter reach zero.

### Posting work

| Member | Description |
|--------|-------------|
| [`bind(t)`](../include/fast_task/task/scheduler.hpp:305) | Assigns the task to this pool without scheduling it |
| [`post(t)`](../include/fast_task/task/scheduler.hpp:306) | Assigns and schedules; spawns or borrows a worker when needed |
| [`post(span)`](../include/fast_task/task/scheduler.hpp:308) | Batch form; one control-plane wake for the whole batch |
| [`schedule_until(t, tp)`](../include/fast_task/task/scheduler.hpp:309) | Assigns and arms the timing wheel |
| [`schedule(t, duration)`](../include/fast_task/task/scheduler.hpp:313) | Relative form of `schedule_until` |

`bind` is for the paths that enqueue themselves (`queue::add`, future factories):
it must not report "already scheduled". `post` is the one call that both binds and
schedules. Publishing to a paused pool only enqueues — it does not wake a worker.

### Options

[`worker_pool_options`](../include/fast_task/task/scheduler.hpp:91):

| Field | Default | Description |
|-------|---------|-------------|
| `name` | `""` | Diagnostic name; defaults to `pool <slot>` |
| `min_workers` | `1` | Floor for the live target; `0` allows a host-only pool |
| `max_workers` | `UINT16_MAX` | Ceiling for the live target |
| `initial_workers` | `0` | Explicit warm-up count; `> 0` wins over `start_with_worker_per_core` |
| `start_with_worker_per_core` | `true` | Warm up to one worker per core (clamped to `[min_workers, max_workers]`) |
| `policy` | `allows_preempt` | `cooperative_only` disables time-sliced preemption for this pool |
| `balancer` | `none` | `hill_climb` sizes the target from measured throughput and CPU load |
| `allow_driver_polling` | `true` | Lets this pool's workers drive the I/O multiplexer |
| `prevent_thread_naming` | `false` | Skips naming the OS threads |
| `abort_tasks_on_shutdown` | `false` | Cancel instead of drain on destruction |
| `allow_dormant_sharing` | `false` | Opts the pool in as a dormant-worker lender |
| `inherit_pool_on_spawn` | `false` | Tasks spawned by this pool's tasks stay on this pool |
| `allow_implicit_start` | `false` | Offers unassigned tasks to this pool (see routing) |
| `queue` | `work_stealing_lifo` | Queue policy, see below |
| `idle` | `wait` | Idle policy, see below |
| `affinity` | empty mask | CPU affinity of the workers, see below |
| `hooks` | none | `thread_initializer` / `worker_body` / `state` for embedders |

The constructor rejects `round_robin` affinity with an empty CPU list
(`std::invalid_argument`), because every spawn would have to divide by zero. A
`max_workers` below `min_workers` is corrected upwards: the minimum is the
stronger promise and a pool must be able to honour it.

### Queue policies

[`queue_policy`](../include/fast_task/task/scheduler.hpp:42):

- `work_stealing_lifo` (default) — one shared concurrent queue plus a
  per-worker LIFO deque. Fresh work stays hot on the publishing worker; idle
  workers steal from the peers' deques. No policy checks on the hot path.
- `priority_fifo` — seven priority queues plus a cold queue. A batch scans the
  classes from highest to lowest and is FIFO within a class. Opt-in: it costs one
  scan per batch and pays for the ordering only when priority matters.

### Idle policies

[`idle_policy`](../include/fast_task/task/scheduler.hpp:47):

- `wait` (default) — a worker parks on the pool's eventcount until work, a
  control wake, or the next timer deadline. No spinning, no timed wake on a
  quiet pool.
- `busy_spin` — a worker polls the queue before parking. Trades CPU for latency;
  choose it deliberately, for pools that need sub-microsecond handoff.

### CPU affinity

[`worker_affinity_options`](../include/fast_task/task/scheduler.hpp:65) is applied
before a worker runs its first instruction:

- [`mask`](../include/fast_task/task/scheduler.hpp:52) — every worker gets the
  whole list.
- `round_robin` — worker *n* is pinned to entry *n mod size*, spreading the pool
  across the listed processors.

A rejected mask (unsupported processor, permission, platform without affinity)
is counted in `worker_pool_stats::affinity_failures` and never stops the worker
from running. Pinned lenders are skipped by dormant sharing, since a borrowed
worker must be able to run on the borrower's cards.

### Live control

| Member | Description |
|--------|-------------|
| [`request_workers(target)`](../include/fast_task/task/scheduler.hpp:325) | Absolute target, clamped to `[min_workers, max_workers]` |
| [`add_workers(count)`](../include/fast_task/task/scheduler.hpp:326) | Delta up; throws `std::logic_error` while the pool is stopping |
| [`remove_workers(count)`](../include/fast_task/task/scheduler.hpp:327) | Delta down; the surplus parks as dormant instead of retiring |
| [`set_min_workers(min)`](../include/fast_task/task/scheduler.hpp:339) | Raising the floor above the ceiling raises the ceiling too |
| [`set_max_workers(max)`](../include/fast_task/task/scheduler.hpp:340) | Lowering the ceiling below the floor lowers the floor with it |
| [`pause()`](../include/fast_task/task/scheduler.hpp:332) / [`resume()`](../include/fast_task/task/scheduler.hpp:333) | Stops / restarts task dispatch |
| [`is_paused()`](../include/fast_task/task/scheduler.hpp:334) | Reads the pause flag |
| [`stats()`](../include/fast_task/task/scheduler.hpp:342) | Snapshot of the live counters |
| [`wait_idle(deadline)`](../include/fast_task/task/scheduler.hpp:346) | Blocks until no task is executing or running, or the deadline passes |

A paused pool runs no task, but it keeps the timer wheel and the I/O multiplexer
moving, so a paused pool does not freeze timers or sockets. Publishing to a
paused pool only enqueues; `resume()` wakes the workers and spawns one if the
pool was paused before it ever had a worker. `set_min_workers`, `set_max_workers`
and `add_workers` throw `std::logic_error` once the pool is stopping — a stopping
pool accepts work, not reconfiguration.

The sizing policy (`balancer`), the queue policy and the idle policy are chosen
in `worker_pool_options` and cannot be changed afterwards: the pool storage is
built for them, so a different policy would need a different pool. A pool created
with `max_workers <= 1` also never steals work from its own workers, because it
has exactly one.

### Dormant worker sharing

With `allow_dormant_sharing`, a worker that has nothing to do in its own pool
parks as *dormant* rather than exiting; it stays counted in `live_threads`. A
burst on another pool that opted in can then borrow it for a bounded batch
instead of waiting for a free thread or starting one. The lender is woken when
the borrowed worker returns. A pool with a single worker is never a lender, and
pinned lenders are skipped. Dormant workers consume the pool's `dormant_event`
rather than its `work_event`, so they never absorb a work wake.

### Statistics

[`worker_pool_stats`](../include/fast_task/task/scheduler.hpp:115) reports what
the pool is doing *now*, which is not necessarily what it was constructed with:

| Field | Meaning |
|-------|---------|
| `min_workers` / `max_workers` / `target_workers` | Live limits and the current size target |
| `active_workers` | Workers currently serving the pool |
| `foreign_workers` | Host threads joined to the pool |
| `dormant_workers` | Parked workers kept alive for possible sharing |
| `borrowed_in` / `borrowed_out` | Dormant workers serving / lent to another pool |
| `live_threads` | Threads that exist, including dormant ones |
| `queued_tasks_approx` / `executing_tasks` / `in_run_tasks` | Work in the queues and in flight |
| `completed_tasks` | Completed since the pool was created |
| `balance_samples` | Throughput samples fed to the balancer; `0` while `balancer == none` |
| `affinity_failures` | Rejected affinity attempts |
| `paused` / `shutting_down` | Control-plane state |

[`get_runtime_stats()`](../include/fast_task/task/scheduler.hpp:403) aggregates
the same view over every live pool, plus `timers_pending` and the global
shutdown flag. It replaces the removed global `executing_tasks` /
`in_run_tasks` counters and `total_executors()`.

---

## Worker contexts

A [`worker_context`](../include/fast_task/task/scheduler.hpp:197) lets a thread
you own serve a pool — the intended shape for a UI, render, or game loop that
must not block in a scheduler-owned thread.

The context is **inert until joined**: the constructor only prepares the
stack-resident state, and every `poll*()`/`next*()` throws `std::logic_error`
while the context is unjoined. Join with
[`worker_pool::join_pool(ctx)`](../include/fast_task/task/scheduler.hpp:299) and
release with [`leave_pool(ctx)`](../include/fast_task/task/scheduler.hpp:300);
the destructor leaves the pool if the context is still joined.

```cpp
fast_task::scheduler::worker_context ctx;

while (running) {
    // The thread is only registered with the scheduler inside poll()/next(),
    // so it cannot block request_stw() while it is drawing the frame.
    ctx.poll(8);

    ctx.next_for(std::chrono::milliseconds(4));
}
```

| Member | Description |
|--------|-------------|
| [`poll(count)`](../include/fast_task/task/scheduler.hpp:237) | Runs up to `count` tasks |
| [`poll_all()`](../include/fast_task/task/scheduler.hpp:230) | Serves until the pools are shut down |
| [`poll_drained()`](../include/fast_task/task/scheduler.hpp:236) | Serves until the queues are empty, then returns |
| [`poll_until(tp)`](../include/fast_task/task/scheduler.hpp:238) / `poll_until(count, tp)` | Serves until a deadline |
| [`next()`](../include/fast_task/task/scheduler.hpp:222) / [`next_until(tp)`](../include/fast_task/task/scheduler.hpp:223) | Parks until there is work, then runs one task |

Options ([`worker_context_options`](../include/fast_task/task/scheduler.hpp:163)):
`policy`, `allow_driver_polling`, `prevent_thread_naming`. There is no bind id —
a context belongs to exactly one pool, the one it joined.

Because a context only registers as in-scheduler while it is inside
`poll*()`/`next*()`, a UI thread that spends most of its time outside those calls
is quiescent for stop-the-world, and a paused/serving pool never makes it wait in
`SwapBuffers()`.

---

## Global pool and default routing

[`worker_pool::global()`](../include/fast_task/task/scheduler.hpp:291) fronts the
reserved global slot. It does not spawn eagerly: workers appear on the publish
path or when a host context joins. `configure_global(options)` rebuilds the
global storage for the requested `queue`, `idle` and `balancer` while the pool is
still pristine, so a configuration written before the first task or worker is
honoured in full, and repeated calls keep the last one. Once the pool has been
used — a spawned or joined worker, a queued task, a claimed worker slot — the
storage has live references and `configure_global` throws `std::logic_error`
instead of ignoring the request.

Unassigned tasks go to the global pool. `allow_implicit_start` is the
transitional escape hatch: a pool that sets it is offered the tasks that nobody
assigned. Prefer explicit `bind`/`post`, or `inherit_pool_on_spawn` when a task
tree must stay on one pool.

---

## Moving a task between pools

Inside a task, [`this_task`](tasks.md#worker-binding) provides the pool controls:

| Function | Description |
|----------|-------------|
| [`this_task::switch_to(pool)`](../include/fast_task/task/this_task.hpp:32) | Moves the task to `pool` now; stackful only |
| [`this_task::set_pool(pool)`](../include/fast_task/task/this_task.hpp:33) | Rebinds without yielding; the next reschedule uses `pool` |
| [`this_task::current_pool()`](../include/fast_task/task/this_task.hpp:34) | The pool this task or worker is executing on |
| [`this_task::async_switch_to(pool)`](../include/fast_task/task/this_task.hpp:74) | Coroutine form: rebinds, then yields |

A stackless coroutine cannot switch to a different pool: `switch_to` throws
`invalid_context` unless the coroutine already runs on the target, and
`async_switch_to` is the suspension-safe form. In-flight tasks are retargeted
destination-first, so the accounting of both pools stays balanced.

---

## Lifecycle and draining

| Function | Description |
|----------|-------------|
| [`become_task_executor()`](../include/fast_task/task/scheduler.hpp:370) | Turns the calling thread into a worker of the global pool |
| [`await_no_tasks(be_executor)`](../include/fast_task/task/scheduler.hpp:371) | Blocks until no tasks remain queued |
| [`await_end_tasks(be_executor)`](../include/fast_task/task/scheduler.hpp:372) | Blocks until all tasks finish |
| [`explicit_start_timer()`](../include/fast_task/task/scheduler.hpp:374) | Starts the timer thread explicitly |
| [`shut_down()`](../include/fast_task/task/scheduler.hpp:375) | Stops the scheduler and joins the internal threads |
| [`current_context_task()`](../include/fast_task/task/scheduler.hpp:377) | Returns the task currently running on this worker |

`shut_down()` should be called before `main` returns to release the worker
threads and internal resources. A pool's own lifetime is independent of it: a
pool is drained and stopped by its destructor.

---

## Stop-the-world

[`request_stw(func)`](../include/fast_task/task/scheduler.hpp:390) halts all
workers and internal threads, runs `func`, then resumes. It is intended for
garbage collection or debugging and may only be called from a native thread —
calling it from a task throws `invalid_native_context`.

```cpp
fast_task::scheduler::request_stw([] {
    // all workers are paused here
});
```

Only workers that are inside a task or inside `poll*()`/`next*()` count as
active; a host thread between poll calls does not block the request.

---

## Memory cleanup

| Function | Description |
|----------|-------------|
| [`clean_up()`](../include/fast_task/task/scheduler.hpp:393) | Releases unused memory across the scheduler |
| [`local_clean_up()`](../include/fast_task/task/scheduler.hpp:394) | Releases unused memory for the current worker |

---

## Preemption

[`preemption_enabled()`](../include/fast_task/task/scheduler.hpp:396) reports
whether the build supports preemptive scheduling. When enabled, long-running
tasks are time-sliced so they cannot starve others. See
[Architecture](architecture.md) for the mechanics and the
`FAST_TASK_ENABLE_PREEMPTIVE_SCHEDULER` build option.

---

## `queue`

A [`queue`](../include/fast_task/task/queue.hpp:18) is a bounded work queue that
runs at most `at_execution_max` tasks concurrently. It is useful for throttling
fan-out work.

```cpp
fast_task::queue q(4); // at most 4 concurrent tasks
q.add(some_task);
q.wait();
```

| Member | Description |
|--------|-------------|
| [`queue(at_execution_max)`](../include/fast_task/task/queue.hpp:24) | Constructs a queue with a concurrency limit |
| [`add(task&)`](../include/fast_task/task/queue.hpp:26) / [`add(task&&)`](../include/fast_task/task/queue.hpp:27) | Enqueues a task |
| [`enable()`](../include/fast_task/task/queue.hpp:28) / [`disable()`](../include/fast_task/task/queue.hpp:29) | Pauses or resumes dispatch |
| [`in_queue(task)`](../include/fast_task/task/queue.hpp:30) | Whether a task is still queued |
| [`set_max_at_execution(val)`](../include/fast_task/task/queue.hpp:31) / [`get_max_at_execution()`](../include/fast_task/task/queue.hpp:32) | Adjust or query the concurrency limit |
| [`wait()`](../include/fast_task/task/queue.hpp:33) | Blocks until the queue drains |
| [`wait_until(tp)`](../include/fast_task/task/queue.hpp:34) / [`wait_for(duration)`](../include/fast_task/task/queue.hpp:36) | Timed drain |
| [`enter_wait()`](../include/fast_task/task/queue.hpp:41) / [`enter_wait_until()`](../include/fast_task/task/queue.hpp:42) | Stackful-task suspension |
| [`async_wait()`](../include/fast_task/task/queue.hpp:45) | Coroutine awaiter |
| [`async_wait_until(tp)`](../include/fast_task/task/queue.hpp:64) / [`async_wait_for(duration)`](../include/fast_task/task/queue.hpp:94) | Timed coroutine awaiter |

---

## `deadline_timer`

A [`deadline_timer`](../include/fast_task/task/deadline_timer.hpp:21) fires once
at a deadline and can wake any number of waiters.

```cpp
fast_task::deadline_timer timer(std::chrono::seconds(1));
fast_task::deadline_timer::status s = timer.wait(); // timeouted
```

### Status

[`status`](../include/fast_task/task/deadline_timer.hpp:27) is one of
`timeouted`, `canceled`, or `shutdown`.

### Construction

| Constructor | Description |
|-------------|-------------|
| [`deadline_timer()`](../include/fast_task/task/deadline_timer.hpp:32) | Default; set the deadline later |
| [`deadline_timer(duration)`](../include/fast_task/task/deadline_timer.hpp:33) | Fires after a duration |
| [`deadline_timer(time_point)`](../include/fast_task/task/deadline_timer.hpp:34) | Fires at an absolute time |

### Waiting

| Member | Description |
|--------|-------------|
| [`wait()`](../include/fast_task/task/deadline_timer.hpp:53) | Blocks until the timer fires |
| [`wait(unique_lock<mutex_unify>&)`](../include/fast_task/task/deadline_timer.hpp:54) | Waits while holding a lock |
| [`async_wait()`](../include/fast_task/task/deadline_timer.hpp:69) | Coroutine awaiter returning `status` |
| [`async_wait(unique_lock<mutex_unify>&)`](../include/fast_task/task/deadline_timer.hpp:95) | Awaiter that releases the lock while waiting |
| [`async_wait(std::function<void(status)>)`](../include/fast_task/task/deadline_timer.hpp:47) | Callback form |
| [`enter_wait(...)`](../include/fast_task/task/deadline_timer.hpp:59) | Stackful-task suspension |

### Control

| Member | Description |
|--------|-------------|
| [`cancel()`](../include/fast_task/task/deadline_timer.hpp:40) | Cancels all waiters; returns the count |
| [`cancel_one()`](../include/fast_task/task/deadline_timer.hpp:41) | Cancels a single waiter |
| [`expires_at(tp)`](../include/fast_task/task/deadline_timer.hpp:51) | Resets the deadline; returns canceled count |
| [`expires_from_now(duration)`](../include/fast_task/task/deadline_timer.hpp:64) | Resets the deadline relative to now |
| [`timed_out()`](../include/fast_task/task/deadline_timer.hpp:57) | Whether the deadline has passed |

---

## Related Pages

- [Tasks](tasks.md) — task creation and per-task controls
- [Architecture](architecture.md) — scheduler internals and preemption
- [Futures](futures.md) — pool-aware future factories
- [Synchronization](synchronization.md) — `mutex_unify` used with timers
