# Tasks

The [`fast_task::task`](../include/fast_task/task/task.hpp:51) class is the core
stackful green thread. A task owns its own execution stack and behaves like a
native thread, but context switches happen in user space and are much faster than
OS thread switches.

## Creating and Running Tasks

The simplest way to run work is [`task::run`](../include/fast_task/task/task.hpp:162),
which creates a task and starts it immediately:

```cpp
fast_task::task t = fast_task::task::run([] {
    // work
});
t.await_task();
```

To create a task without starting it, use
[`task::create`](../include/fast_task/task/task.hpp:169):

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
    std::chrono::high_resolution_clock::time_point timeout = /* min */,
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

[`task_priority`](../include/fast_task/task/task.hpp:17) controls scheduling order
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
[`set_priority`](../include/fast_task/task/task.hpp:128) and read it with
[`get_priority`](../include/fast_task/task/task.hpp:130).

## Lifecycle and State

| Method | Description |
|--------|-------------|
| [`start()`](../include/fast_task/task/task.hpp:143) | Schedules the task for execution. |
| [`is_ended()`](../include/fast_task/task/task.hpp:136) | Returns `true` once the task has completed. |
| [`await_task()`](../include/fast_task/task/task.hpp:137) | Blocks the caller until the task ends. |
| [`await_task_until(tp)`](../include/fast_task/task/task.hpp:138) | Waits until a time point; returns `false` on timeout. |
| [`await_task_for(dur)`](../include/fast_task/task/task.hpp:224) | Convenience wrapper over `await_task_until`. |
| [`await_multiple(container)`](../include/fast_task/task/task.hpp:212) | Starts (optionally) and awaits every task in a container. |
| [`reset()`](../include/fast_task/task/task.hpp:121) | Releases the task object reference. |
| [`release()`](../include/fast_task/task/task.hpp:122) | Detaches the raw `task_object*`. |
| [`adopt(raw)`](../include/fast_task/task/task.hpp:123) | Wraps a raw `task_object*` in a `task`. |

## Cancellation

| Method | Description |
|--------|-------------|
| [`notify_cancel()`](../include/fast_task/task/task.hpp:140) | Requests cancellation of the task. |
| [`await_notify_cancel()`](../include/fast_task/task/task.hpp:141) | Requests cancellation and waits for it to take effect. |
| [`is_cancellation_requested()`](../include/fast_task/task/task.hpp:135) | Checks whether cancellation was requested. |

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
| [`set_timeout(tp)`](../include/fast_task/task/task.hpp:129) | Sets an absolute deadline. |
| [`get_timeout()`](../include/fast_task/task/task.hpp:133) | Returns the current deadline. |
| [`has_wait_timed_out()`](../include/fast_task/task/task.hpp:134) | Checks (and resets) the timed-out flag for timed waits. |
| [`reset_awake()`](../include/fast_task/task/task.hpp:142) | Resets the time-end and awake flags. |

## Worker Binding

Tasks can be pinned to a specific worker for thread affinity:

| Method | Description |
|--------|-------------|
| [`set_worker_id(id)`](../include/fast_task/task/task.hpp:127) | Binds the task to a worker. |
| [`set_auto_bind_worker(enable)`](../include/fast_task/task/task.hpp:126) | Enables automatic worker binding. |

Bound executors are created through the [scheduler API](scheduler.md#bound-executors).

## Callbacks

A task can register a continuation that runs when it completes:

```cpp
fast_task::task t = fast_task::task::create([] { /* work */ });
t.callback(fast_task::task::create([] { /* runs after t */ }));
```

- [`callback(task)`](../include/fast_task/task/task.hpp:139) — schedules `task` to
  run after this task completes.
- [`callback_dummy(...)`](../include/fast_task/task/task.hpp:220) — creates a task
  from raw callbacks (`on_start`, `on_await`, `on_cancel`, `on_destruct`).

## Introspection

| Method | Description |
|--------|-------------|
| [`get_id()`](../include/fast_task/task/task.hpp:144) | Returns the unique task id. |
| [`get_counter_interrupt()`](../include/fast_task/task/task.hpp:131) | Number of interrupts the task received. |
| [`get_counter_context_switch()`](../include/fast_task/task/task.hpp:132) | Number of context switches the task performed. |

## Static Configuration

| Member | Description |
|--------|-------------|
| [`max_running_tasks`](../include/fast_task/task/task.hpp:95) | Maximum number of concurrently running tasks. |
| [`enable_task_naming`](../include/fast_task/task/task.hpp:96) | Enables task naming (used by debuggers). |
| [`sbo_size`](../include/fast_task/task/task.hpp:97) | Inline storage size for the small-buffer optimization. |

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
- [Scheduler](scheduler.md) — starting tasks and managing executors.
- [Synchronization](synchronization.md) — primitives usable inside tasks.
