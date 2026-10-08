# Scheduler

The scheduler is the runtime that owns worker threads, distributes tasks, and
drives timers. This page documents the public control surface: the
[`scheduler`](../include/fast_task/task/scheduler.hpp:16) namespace, the
[`queue`](../include/fast_task/task/queue.hpp:18) type, and the
[`deadline_timer`](../include/fast_task/task/deadline_timer.hpp:21) type.

For the internal design (work-stealing deques, the timer wheel, preemption
mechanics), see [Architecture](architecture.md).

Header: [`fast_task/task/scheduler.hpp`](../include/fast_task/task/scheduler.hpp)
(included by [`fast_task.hpp`](../include/fast_task.hpp)).

---

## Scheduling tasks

| Function | Description |
|----------|-------------|
| [`start(task)`](../include/fast_task/task/scheduler.hpp:38) | Submits a task for immediate execution |
| [`start(std::list<task>&)`](../include/fast_task/task/scheduler.hpp:39) | Submits a batch of tasks |
| [`start(std::vector<task>&)`](../include/fast_task/task/scheduler.hpp:40) | Submits a batch of tasks |
| [`schedule_until(task, tp)`](../include/fast_task/task/scheduler.hpp:25) | Runs a task no earlier than `tp` |
| [`schedule(task, duration)`](../include/fast_task/task/scheduler.hpp:29) | Runs a task after a delay |

```cpp
fast_task::task t = fast_task::task::create([]{ /* work */ });
fast_task::scheduler::start(std::move(t));
```

---

## Executors

Executors are the worker threads that run tasks. The scheduler creates them
lazily, but you can control the pool explicitly.

| Function | Description |
|----------|-------------|
| [`create_executor(count)`](../include/fast_task/task/scheduler.hpp:47) | Adds `count` worker threads |
| [`total_executors()`](../include/fast_task/task/scheduler.hpp:48) | Returns the current worker count |
| [`reduce_executor(count)`](../include/fast_task/task/scheduler.hpp:49) | Removes `count` worker threads |
| [`become_task_executor()`](../include/fast_task/task/scheduler.hpp:51) | Turns the calling native thread into a worker |

### Bound executors

A *bound executor* is a dedicated worker (or set of workers) identified by an
ID. Tasks assigned to that ID via [`task::set_worker_id`](tasks.md) always run
there — useful for thread-affinity requirements.

| Function | Description |
|----------|-------------|
| [`create_bind_only_executor(fixed_count, allow_implicit_start, policy)`](../include/fast_task/task/scheduler.hpp:43) | Creates a bound executor and returns its ID |
| [`assign_bind_only_executor(id, fixed_count, allow_implicit_start, policy)`](../include/fast_task/task/scheduler.hpp:44) | Reconfigures an existing bound executor |
| [`close_bind_only_executor(id, abort_tasks)`](../include/fast_task/task/scheduler.hpp:45) | Shuts down a bound executor |

The [`preemption_policy`](../include/fast_task/task/scheduler.hpp:17) argument
selects `allows_preempt` (default) or `cooperative_only`, which disables
time-sliced preemption for that executor.

---

## Lifecycle and draining

| Function | Description |
|----------|-------------|
| [`await_no_tasks(be_executor)`](../include/fast_task/task/scheduler.hpp:52) | Blocks until no tasks remain queued |
| [`await_end_tasks(be_executor)`](../include/fast_task/task/scheduler.hpp:53) | Blocks until all tasks finish |
| [`explicit_start_timer()`](../include/fast_task/task/scheduler.hpp:55) | Starts the timer thread explicitly |
| [`shut_down()`](../include/fast_task/task/scheduler.hpp:56) | Stops the scheduler and joins workers |
| [`current_context_task()`](../include/fast_task/task/scheduler.hpp:58) | Returns the task currently running on this worker |

`shut_down()` should be called before `main` returns to release worker threads
and internal resources.

---

## Stop-the-world

[`request_stw(func)`](../include/fast_task/task/scheduler.hpp:71) halts all
workers and internal threads, runs `func`, then resumes. It is intended for
garbage collection or debugging and may only be called from a native thread —
calling it from a task throws `invalid_native_context`.

```cpp
fast_task::scheduler::request_stw([] {
    // all workers are paused here
});
```

---

## Memory cleanup

| Function | Description |
|----------|-------------|
| [`clean_up()`](../include/fast_task/task/scheduler.hpp:74) | Releases unused memory across the scheduler |
| [`local_clean_up()`](../include/fast_task/task/scheduler.hpp:75) | Releases unused memory for the current worker |

---

## Preemption

[`preemption_enabled()`](../include/fast_task/task/scheduler.hpp:77) reports
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

- [Tasks](tasks.md) — task creation and worker binding
- [Architecture](architecture.md) — scheduler internals and preemption
- [Futures](futures.md) — queue-aware future factories
- [Synchronization](synchronization.md) — `mutex_unify` used with timers
