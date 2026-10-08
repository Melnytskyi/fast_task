# Troubleshooting & FAQ

This page collects the most common problems encountered when using Fast Task,
along with their causes and fixes.

---

## Deadlocks

### The program hangs when preemption is enabled

**Cause:** Code inside a task used a hidden OS lock (`malloc`, `new`,
`std::cout`, `std::mutex`, …) and was preempted while holding it.

**Fix:** Wrap the offending region in an
[`interrupt_unsafe_region`](interrupt.md):

```cpp
{
    fast_task::interrupt_unsafe_region region;
    std::cout << "safe now\n";
}
```

See [Interrupt Safety & Preemption](interrupt.md) for the full list of what is
and is not safe.

### A task never resumes after `await_task()`

**Cause:** The task was created with `is_on_scheduler = true` and then performed
a blocking operation. Tasks running on the scheduler stack are cooperative only
and must use the `enter_*` methods for synchronization; regular blocking calls
throw.

**Fix:** Either run the task on its own stack (the default,
`is_on_scheduler = false`), or replace blocking calls with the corresponding
`enter_*` / `async_*` variants. See
[Architecture — Execution Contexts](architecture.md#execution-contexts).

---

## Exceptions

### `invalid_native_context` is thrown

**Cause:** A native-thread-only function was called from inside a task. Common
examples are [`scheduler::request_stw`](scheduler.md#stop-the-world) and
[`debug::dump_program_state`](debugging.md#stop-the-world-snapshots).

**Fix:** Call these functions from a real OS thread (for example, `main` or a
[`native::thread`](native.md#nativethread)), not from a task or coroutine.

### `task_cancellation` escapes my `catch` block

**Cause:** `task_cancellation` is a control-flow signal, not a normal exception,
and is intentionally **not** derived from `std::exception`.

**Fix:** Do not catch it. Let it propagate so the task can unwind cleanly. See
[Exceptions](exceptions.md#task_cancellation).

### `no_assignable_workers` is thrown

**Cause:** A task was assigned to a bound executor that has no worker allowing
implicit start.

**Fix:** Create the bound executor with `allow_implicit_start = true`, or start
the task explicitly. See
[Scheduler — Bound executors](scheduler.md#bound-executors).

---

## Build & integration

### `liburing` is missing on Linux

**Cause:** Linux builds require `liburing`.

**Fix:** Install it via your package manager, for example
`sudo apt install liburing-dev`.

### The C++20 module target fails to build

**Cause:** `FAST_TASK_BUILD_MODULE=ON` requires CMake 3.28+, a compiler with
C++20 modules support (GCC 14+, Clang 16+, or MSVC 19.34+), and a generator with
module dependency scanning (Ninja or Visual Studio).

**Fix:** Use a supported toolchain, or leave the option `OFF` and use the
header-based API. See
[Getting Started — Optional C++20 Module Wrapper](getting-started.md#optional-c20-module-wrapper).

### Debug dumps are empty

**Cause:** The debug API is compiled out unless
`FAST_TASK_ENABLE_DEBUG_API=ON`.

**Fix:** Reconfigure with `-DFAST_TASK_ENABLE_DEBUG_API=ON`. See
[Debugging](debugging.md).

---

## Runtime behaviour

### `shut_down()` is never called and the process hangs on exit

**Cause:** Worker threads are still running when `main` returns.

**Fix:** Call [`scheduler::shut_down()`](scheduler.md#lifecycle-and-draining)
before returning from `main`.

### A coroutine's result is unavailable

**Cause:** The coroutine was never started, so it has no result.

**Fix:** Start the coroutine (or use
[`task_auto_start_coro`](task/coroutines.md)) before
awaiting it. Accessing the result of an unstarted coroutine throws
[`no_return_value`](exceptions.md).

### `std::mutex` works but is slow / blocks a worker

**Cause:** `std::mutex` is a blocking primitive; it does not yield the worker
thread.

**Fix:** Use the scheduler-aware [`fast_task::mutex`](synchronization.md#mutex)
inside tasks so the worker can run other work while waiting.

---

## Related Pages

- [Interrupt Safety & Preemption](interrupt.md) — hidden-lock deadlocks
- [Exceptions](exceptions.md) — the exception hierarchy
- [Architecture](architecture.md) — execution contexts and preemption
- [Getting Started](getting-started.md) — build options and dependencies
