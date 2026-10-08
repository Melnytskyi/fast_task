# Exceptions

Fast Task defines a small exception hierarchy rooted at
[`fast_task::exception`](../include/fast_task/exceptions.hpp:13). All library
errors derive from it, so a single `catch (const fast_task::exception&)` can
handle every failure the runtime reports.

Header: [`fast_task/exceptions.hpp`](../include/fast_task/exceptions.hpp:1)
(included by [`fast_task.hpp`](../include/fast_task.hpp:1)).

---

## Hierarchy

```text
std::exception
└── fast_task::exception
    ├── invalid_switch
    ├── invalid_context
    │   ├── invalid_coroutine_context_arguments
    │   ├── invalid_coroutine_context
    │   └── invalid_native_context
    ├── no_assignable_workers
    ├── file_closed
    └── no_return_value
```

| Exception | Meaning |
|-----------|---------|
| [`exception`](../include/fast_task/exceptions.hpp:13) | Base class for all Fast Task errors. |
| [`invalid_switch`](../include/fast_task/exceptions.hpp:18) | A task switched context without scheduling itself or marking itself complete. **Should never be thrown by user code** — it indicates a broken primitive or a direct call to an internal scheduler function. |
| [`invalid_context`](../include/fast_task/exceptions.hpp:24) | A function was used in the wrong execution context. |
| [`invalid_coroutine_context_arguments`](../include/fast_task/exceptions.hpp:30) | A stackless-only function was called with arguments meant for a stackful context. |
| [`invalid_coroutine_context`](../include/fast_task/exceptions.hpp:36) | A function designed for a stackful context was called from a stackless coroutine. |
| [`invalid_native_context`](../include/fast_task/exceptions.hpp:42) | A native-thread-only function was called from inside a task. |
| [`no_assignable_workers`](../include/fast_task/exceptions.hpp:48) | A task was assigned to a bound executor that has no worker allowing implicit start. |
| [`file_closed`](../include/fast_task/exceptions.hpp:54) | An operation was attempted on a closed [`file_handle`](io.md#file_handle). |
| [`no_return_value`](../include/fast_task/exceptions.hpp:60) | A coroutine that was never started has no result to return. |

---

## `task_cancellation`

[`task_cancellation`](../include/fast_task/exceptions.hpp:67) is **not** part of
the `exception` hierarchy. It is a special control-flow signal used to unwind a
task when cancellation is requested. It is thrown by
[`this_task::check_cancellation()`](task/coroutines.md#cancellation) and by the
scheduler when a task is cancelled while suspended.

> **Do not catch `task_cancellation`.** It is an implementation detail of the
> cancellation mechanism. Catching it prevents the task from unwinding cleanly
> and can leave the scheduler in an inconsistent state. The class is
> intentionally not derived from `std::exception` so that generic
> `catch (const std::exception&)` handlers do not swallow it by accident.

---

## Where exceptions surface

| Source | Behaviour |
|--------|-----------|
| [`task::run`](tasks.md#creating-and-running-tasks) body throws | The exception is captured; it is rethrown by [`await_task()`](tasks.md#lifecycle-and-state) or delivered to the optional `ex_handler`. |
| [`future<T>::get()` / `take()`](futures.md#retrieving-the-result) | Rethrows the captured exception, or throws `std::runtime_error` if the task was cancelled. |
| `safe_async_*` I/O operations | Do **not** throw; errors are returned as [`polyfill::expected`](io.md#io-awaiters). |
| `async_*` I/O operations | Throw on error; use the `safe_` variants to avoid exceptions. |
| [`scheduler::request_stw`](scheduler.md#stop-the-world) from a task | Throws [`invalid_native_context`](../include/fast_task/exceptions.hpp:42). |
| [`debug::dump_program_state`](debugging.md#stop-the-world-snapshots) from a task | Throws [`invalid_native_context`](../include/fast_task/exceptions.hpp:42). |

---

## Related Pages

- [Tasks](tasks.md) — exception handling in task bodies
- [Futures](futures.md) — exception propagation through futures
- [Asynchronous I/O](io.md) — throwing vs. non-throwing I/O variants
- [Debugging](debugging.md) — native-context restrictions
