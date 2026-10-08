# Coroutines

Fast Task provides first-class support for C++20 stackless coroutines. Unlike
[stackful tasks](tasks.md), coroutines do not allocate a separate stack; they
suspend by saving state and resume directly on a scheduler worker thread. This
makes them ideal for massive concurrency (for example, millions of concurrent
network connections).

The coroutine API is exposed through
[`fast_task/coroutine.hpp`](../include/fast_task/coroutine.hpp:1), which pulls in
`core.hpp`, `helpers.hpp`, and `promise.hpp`.

## `task_coro<T>`

[`task_coro<T>`](../include/fast_task/coroutine/core.hpp:270) is the return type of
a stackless coroutine. It is `[[nodiscard]]` and move-only.

```cpp
fast_task::task_coro<int> compute() {
    co_return 42;
}
```

### Members

| Member | Description |
|--------|-------------|
| [`task_handle`](../include/fast_task/coroutine/core.hpp:329) | The underlying [`fast_task::task`](tasks.md). |
| [`operator->`](../include/fast_task/coroutine/core.hpp:339) | Access to the underlying task. |
| [`operator task()`](../include/fast_task/coroutine/core.hpp:343) | Implicit conversion to `fast_task::task`. |
| [`get_task()`](../include/fast_task/coroutine/core.hpp:347) | Returns the underlying task. |
| [`operator co_await()`](../include/fast_task/coroutine/core.hpp:351) | Awaits the coroutine and yields its result. |
| [`sync_get<U>()`](../include/fast_task/coroutine/core.hpp:356) | Blocks and returns the result synchronously. |

### Awaiting a coroutine

```cpp
fast_task::task_coro<void> example() {
    int value = co_await compute();
}
```

Awaiting a coroutine from a non-coroutine context (for example, a native thread)
is supported through a bridge task created internally.

## `task_auto_start_coro<T>`

[`task_auto_start_coro<T>`](../include/fast_task/coroutine/core.hpp:374) is a
`task_coro<T>` that starts itself immediately upon creation:

```cpp
fast_task::task_auto_start_coro<void> fire_and_forget() {
    // starts running as soon as it is created
    co_return;
}
```

## `task_promise` and `task_promise_base`

[`task_promise_base`](../include/fast_task/coroutine/promise.hpp:10) provides the
common promise behavior: it suspends initially
([`initial_suspend`](../include/fast_task/coroutine/promise.hpp:12)) and, on
completion, notifies the scheduler via
[`this_task::the_coroutine_ended`](../include/fast_task/coroutine/promise.hpp:26).

The typed [`task_promise<T>`](../include/fast_task/coroutine/core.hpp:59) stores the
result or a captured exception and exposes it through `result()`. Specializations
exist for `T&` and `void`.

## `task_generator<T>`

[`task_generator<T>`](../include/fast_task/coroutine/generator.hpp:18) is a
coroutine-based channel that produces a stream of values. It is `[[nodiscard]]` and
move-only.

```cpp
fast_task::task_generator<int> counter() {
    for (int i = 0; i < 10; ++i)
        co_yield i;
}

fast_task::task_coro<void> consume() {
    auto gen = counter();
    while (auto opt_val = co_await gen.next()) {
        int val = *opt_val;
    }
}
```

The generator buffers values internally and suspends the producer when the buffer
exceeds 40 items, resuming it as the consumer drains the queue. Exceptions thrown
by the producer are rethrown to the consumer on the next `next()` call.

## Coroutine Helpers

The [`fast_task::coroutine`](../include/fast_task/coroutine/helpers.hpp:13) namespace
provides parallel iteration utilities.

### `async_for_each`

```cpp
template <class T, class FN>
task_coro<void> async_for_each(T&& container, fast_task::queue& queue, FN&& fn);

template <class T, class FN>
task_coro<void> async_for_each(T&& container, FN&& fn);
```

Runs `fn` for each element concurrently as coroutines, then awaits all of them. If
any coroutine throws, the remaining ones are cancelled and the exception is
rethrown.

### `for_each`

```cpp
template <class T, class FN>
void for_each(T& container, fast_task::queue& queue, FN&& fn);

template <class T, class FN>
void for_each(T& container, FN&& fn);
```

The blocking variant of `async_for_each`: it starts the coroutines and waits for
them to finish before returning.

### `wait_all`

```cpp
template <class T>
task_auto_start_coro<void> wait_all(T&& coros);
```

Awaits every coroutine in a container.

### `wait_all_blocking`

```cpp
template <class T>
void wait_all_blocking(T& coros);
```

Starts and blocks on every coroutine in a container, cancelling the rest if one
throws.

## `this_task` Namespace

The [`this_task`](../include/fast_task/task/this_task.hpp:15) namespace provides
operations for the currently executing task or coroutine.

### Scheduling

| Function | Description |
|----------|-------------|
| [`get_id()`](../include/fast_task/task/this_task.hpp:16) | Returns the current task id. |
| [`yield()`](../include/fast_task/task/this_task.hpp:17) | Cooperatively yields to the scheduler. |
| [`sleep_until(tp)`](../include/fast_task/task/this_task.hpp:18) | Suspends until a time point. |
| [`sleep_for(dur)`](../include/fast_task/task/this_task.hpp:21) | Suspends for a duration. |

### Cancellation

| Function | Description |
|----------|-------------|
| [`check_cancellation()`](../include/fast_task/task/this_task.hpp:25) | Throws if cancellation was requested. |
| [`is_cancellation_requested()`](../include/fast_task/task/this_task.hpp:26) | Returns whether cancellation was requested. |
| [`self_cancel()`](../include/fast_task/task/this_task.hpp:27) | Requests cancellation of the current task. |

### Context

| Function | Description |
|----------|-------------|
| [`is_task()`](../include/fast_task/task/this_task.hpp:28) | Returns whether the caller is running as a task. |
| [`the_coroutine_ended(task)`](../include/fast_task/task/this_task.hpp:29) | Notifies the scheduler that a coroutine finished. |
| [`transfer_to(target)`](../include/fast_task/task/this_task.hpp:30) | Directly transfers execution to another task. |

### `this_task::the_coroutine_ended`

```cpp
void this_task::the_coroutine_ended(const task&) noexcept;
```

Should be called by the coroutine when it finishes its execution. It modifies the
task flags so the scheduler calls the required condition variables and callbacks,
and updates the scheduler's state.

It removes the `is_restartable` flag from the task and marks it completed.

Automatically called by the scheduler when the task is cancelled.

### `this_task::transfer_to`

```cpp
bool this_task::transfer_to(const task& target);
```

Directly transfers the scheduler's currently executing task to `target` after a
yield or completion.

Both the current task (`c`) and the target (`t`) must satisfy:

- `(c, t)` have the same worker binding.
- `(t)` The target can be scheduled (`is_restartable = true` or `started = false`).
- `(c)` The scheduler is executing the `on_start` callback (no exception).
- `(c)` No pending transfers.
- `(c)` The cooperative transfer limit has not been reached (if one is set).

Returns `true` if the transfer was accepted (now waiting for the return from
`on_start`), or `false` if the conditions were not met — in which case the caller
must fall back to the normal [`scheduler::start(target)`](scheduler.md#scheduling-tasks).

### Async awaiters

When compiling with C++20, `this_task` also provides awaiters:

| Awaiter | Description |
|---------|-------------|
| [`async_yield()`](../include/fast_task/task/this_task.hpp:38) | Yields cooperatively. |
| [`async_sleep_until(tp)`](../include/fast_task/task/this_task.hpp:56) | Suspends until a time point. |
| [`async_sleep_for(dur)`](../include/fast_task/task/this_task.hpp:76) | Suspends for a duration. |

## Related Pages

- [Tasks](tasks.md) — the stackful alternative.
- [Architecture](architecture.md#execution-contexts) — how coroutines run on the
  scheduler stack.
- [Synchronization](synchronization.md) — async lock awaiters.
