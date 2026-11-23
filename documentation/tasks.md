# Tasks

The [`fast_task::task`](../include/fast_task/task/task.hpp:57) class is the core
stackful green thread. A task owns its own execution stack and behaves like a
native thread, but context switches happen in user space and are much faster than
OS thread switches.

## Creating and Running Tasks

The simplest way to run work is [`task::run`](../include/fast_task/task/task.hpp:166),
which creates a task and starts it immediately:

```cpp
fast_task::task t = fast_task::task::run([] {
    // work
});
t.await_task();
```

To create a task without starting it, use
[`task::create`](../include/fast_task/task/task.hpp:173):

```cpp
fast_task::task t = fast_task::task::create([] { /* work */ });
// ... later
t.start();
```

### `run` / `create` parameters

```cpp
template <typename Func, typename ExHandle = std::nullptr_t>
static task run(
    Func&& func,
    ExHandle&& ex_handle = nullptr,
    fast_task::time_point timeout = fast_task::time_point::min(),
    task_priority priority = task_priority::high,
    bool is_on_scheduler = false
);
```

| Parameter | Description |
|-----------|-------------|
| `func` | The callable executed as the task body. |
| `ex_handle` | Optional exception handler invoked with an `std::exception_ptr` if `func` throws. |
| `timeout` | Absolute deadline after which the task is cancelled. |
| `priority` | Scheduling priority (see below). |
| `is_on_scheduler` | Run on the scheduler stack (cooperative only). See [Architecture](architecture.md#execution-contexts). |

## Task Priorities

[`task_priority`](../include/fast_task/task/task.hpp:23) controls scheduling order
and, when preemption is enabled, the time slice:

```cpp
enum class task_priority {
    background,
    low,
    lower,
    normal,
    higher,
    high,
    semi_realtime,
};
```

Set it at creation or later with
[`set_priority`](../include/fast_task/task/task.hpp:132) and read it with
[`get_priority`](../include/fast_task/task/task.hpp:134).

The order is honoured by the `priority_fifo` queue policy; the default
`work_stealing_lifo` policy runs what is available first. See
[Scheduler](scheduler.md#queue-policies).

## Lifecycle and State

| Method | Description |
|--------|-------------|
| [`start()`](../include/fast_task/task/task.hpp:147) | Schedules the task for execution. |
| [`is_ended()`](../include/fast_task/task/task.hpp:140) | Returns `true` once the task has completed. |
| [`await_task()`](../include/fast_task/task/task.hpp:141) | Blocks the caller until the task ends. |
| [`await_task_until(tp)`](../include/fast_task/task/task.hpp:142) | Waits until a time point; returns `false` on timeout. |
| [`await_task_for(dur)`](../include/fast_task/task/task.hpp:228) | Convenience wrapper over `await_task_until`. |
| [`await_multiple(container)`](../include/fast_task/task/task.hpp:216) | Starts (optionally) and awaits every task in a container. |
| [`reset()`](../include/fast_task/task/task.hpp:127) | Releases the task object reference. |
| [`release()`](../include/fast_task/task/task.hpp:128) | Detaches the raw `task_object*`. |
| [`adopt(raw)`](../include/fast_task/task/task.hpp:129) | Wraps a raw `task_object*` in a `task`. |

## Cancellation

| Method | Description |
|--------|-------------|
| [`notify_cancel()`](../include/fast_task/task/task.hpp:144) | Requests cancellation of the task. |
| [`await_notify_cancel()`](../include/fast_task/task/task.hpp:145) | Requests cancellation and waits for it to take effect. |
| [`is_cancellation_requested()`](../include/fast_task/task/task.hpp:139) | Checks whether cancellation was requested. |

Inside a running task, use the [`this_task`](task/coroutines.md#this_task-namespace)
namespace to cooperate with cancellation:

```cpp
fast_task::this_task::check_cancellation(); // throws task_cancellation if requested
bool requested = fast_task::this_task::is_cancellation_requested();
fast_task::this_task::self_cancel();
```

## Timeouts

| Method | Description |
|--------|-------------|
| [`set_timeout(tp)`](../include/fast_task/task/task.hpp:133) | Sets an absolute deadline. |
| [`get_timeout()`](../include/fast_task/task/task.hpp:137) | Returns the current deadline. |
| [`has_wait_timed_out()`](../include/fast_task/task/task.hpp:138) | Checks (and resets) the timed-out flag for timed waits. |
| [`reset_awake()`](../include/fast_task/task/task.hpp:146) | Resets the time-end and awake flags. |

## Worker Binding

There is no per-task worker id any more. A task belongs to a
[worker pool](scheduler.md#worker-pools), and every path that runs it assigns
one:

```cpp
fast_task::scheduler::worker_pool pool(options);

fast_task::task t = fast_task::task::create([]{ /* work */ });
pool.post(std::move(t));                 // assign + schedule
```

| Way to assign | Description |
|---------------|-------------|
| [`worker_pool::post(t)`](../include/fast_task/task/scheduler.hpp:306) | Assigns and schedules in one step; the batch form takes a `std::span<const task>` |
| [`worker_pool::bind(t)`](../include/fast_task/task/scheduler.hpp:305) | Assigns without scheduling; use it before `queue::add`/`start` |
| [`worker_pool::schedule_until(t, tp)`](../include/fast_task/task/scheduler.hpp:309) | Assigns and arms the timer wheel |
| [`future::start(fn, &pool)`](../include/fast_task/task/future.hpp:33) | Runs the future's task on `pool` |
| [`this_task::set_pool(pool)`](../include/fast_task/task/this_task.hpp:33) / [`switch_to(pool)`](../include/fast_task/task/this_task.hpp:32) | Reassigns the running task |
| `inherit_pool_on_spawn` | Tasks spawned by this pool's tasks inherit it |

A task with no pool assigned goes to the global pool. A pool that sets
`allow_implicit_start` is offered unassigned tasks, which is the transitional
replacement for the removed `set_auto_bind_worker`. Neither
`task::set_worker_id` nor `task::set_auto_bind_worker` exists any more; see the
[removed API table](scheduler.md#removed-api).

## Callbacks

A task can register a continuation that runs when it completes:

```cpp
fast_task::task t = fast_task::task::create([] { /* work */ });
t.callback(fast_task::task::create([] { /* runs after t */ }));
```

- [`callback(task)`](../include/fast_task/task/task.hpp:143) — schedules `task` to
  run after this task completes.
- [`callback_dummy(...)`](../include/fast_task/task/task.hpp:224) — creates a task
  from raw callbacks (`on_start`, `on_await`, `on_cancel`, `on_destruct`).

## Introspection

| Method | Description |
|--------|-------------|
| [`get_id()`](../include/fast_task/task/task.hpp:148) | Returns the unique task id. |
| [`get_counter_interrupt()`](../include/fast_task/task/task.hpp:135) | Number of interrupts the task received. |
| [`get_counter_context_switch()`](../include/fast_task/task/task.hpp:136) | Number of context switches the task performed. |

For scheduler-wide counters (workers, queues, in-flight tasks) use
[`get_runtime_stats()`](scheduler.md#statistics); the removed global
`executing_tasks`/`in_run_tasks` counters live there, per pool.

## Static Configuration

| Member | Description |
|--------|-------------|
| [`max_running_tasks`](../include/fast_task/task/task.hpp:101) | Maximum number of concurrently running tasks. |
| [`enable_task_naming`](../include/fast_task/task/task.hpp:102) | Enables task naming (used by debuggers). |
| [`sbo_size`](../include/fast_task/task/task.hpp:103) | Inline storage size for the small-buffer optimization. |

## Awaiting a Task from a Coroutine

A `task` can be awaited directly from a stackless coroutine via
[`operator co_await`](../include/fast_task/coroutine/core.hpp:369):

```cpp
fast_task::task_coro<void> example() {
    fast_task::task t = fast_task::task::run([] { /* work */ });
    co_await t;
}
```

## Related Pages

- [Coroutines](task/coroutines.md) — the stackless alternative.
- [Scheduler](scheduler.md) — worker pools, contexts, and starting tasks.
- [Synchronization](synchronization.md) — primitives usable inside tasks.
