# Fast Task Documentation

This folder contains the full documentation for **Fast Task**, a high-performance
C++ green thread and coroutine library. The top-level [`README.md`](../README.md)
provides a compact overview; the pages below cover each subsystem in depth.

## Contents

| Document | Description |
|----------|-------------|
| [Getting Started](getting-started.md) | Prerequisites, building, integration, CMake options, model comparison, and compatibility |
| [Architecture](architecture.md) | Work-stealing scheduler, timer management, preemption, and synchronization internals |
| [Tasks](tasks.md) | The stackful `fast_task::task` API, lifecycle, priorities, timeouts, and cancellation |
| [Coroutines](task/coroutines.md) | Stackless `task_coro`, generators, and coroutine helpers |
| [Synchronization](synchronization.md) | `mutex`, `recursive_mutex`, `rw_mutex`, `condition_variable`, `semaphore`, `limiter`, and `mutex_unify` |
| [Futex](futex.md) | The single-atomic futex layer that makes the primitives faster than Boost.Fiber |
| [Asynchronous I/O](io.md) | File and network I/O with `io_operation`, `io_handle`, and awaiters |
| [Futures](futures.md) | The `future<T>` API, chaining, callbacks, and `future_tool` |
| [Scheduler](scheduler.md) | Executors, queues, timers, and scheduler lifecycle |
| [Debugging](debugging.md) | Introspection API, program state dumps, and stack traces |
| [Allocator](allocator.md) | The `fast_task::allocator` and the `at` allocation tag |
| [Native Primitives](native.md) | OS-level `thread`, `mutex`, `condition_variable`, and `spin_lock` |
| [Interrupt Safety](interrupt.md) | `interrupt_unsafe_region` and preemption-safe coding |
| [Exceptions](exceptions.md) | The `fast_task::exception` hierarchy and `task_cancellation` |
| [Troubleshooting & FAQ](troubleshooting.md) | Common deadlocks, exceptions, and build issues |
| [Documentation Style Guide](CONTRIBUTING.md) | Conventions for writing and linking documentation |

## Concurrency Models at a Glance

Fast Task offers three interoperable ways to run concurrent work:

1. **Stackful tasks** ([`fast_task::task`](tasks.md)) — allocate their own stack and
   behave like native threads, but switch in user space. Best for deep call chains
   and code that must look synchronous.
2. **Stackless coroutines** ([`fast_task::task_coro`](task/coroutines.md)) — no separate
   stack; suspend by saving state. Best for massive concurrency (millions of
   connections).
3. **Native threads** ([`fast_task::native::thread`](native.md)) — real OS threads
   that can still wait on Fast Task synchronization primitives.

All three can share the same synchronization primitives, so you can mix and match
models within a single program.

## Header Map

The public API is exposed through the umbrella header
[`include/fast_task.hpp`](../include/fast_task.hpp:1). Individual headers:

| Header | Contents |
|--------|----------|
| [`fast_task/task/task.hpp`](../include/fast_task/task/task.hpp:1) | `task`, `task_priority`, `task_vtable` |
| [`fast_task/task/scheduler.hpp`](../include/fast_task/task/scheduler.hpp:1) | `scheduler` namespace |
| [`fast_task/task/this_task.hpp`](../include/fast_task/task/this_task.hpp:1) | `this_task` namespace |
| [`fast_task/task/mutex.hpp`](../include/fast_task/task/mutex.hpp:1) | `mutex`, `recursive_mutex`, `rw_mutex`, lock guards |
| [`fast_task/task/condition_variable.hpp`](../include/fast_task/task/condition_variable.hpp:1) | `condition_variable`, `condition_variable_any` |
| [`fast_task/task/semaphore.hpp`](../include/fast_task/task/semaphore.hpp:1) | `semaphore`, `limiter` |
| [`fast_task/task/mutex_unify.hpp`](../include/fast_task/task/mutex_unify.hpp:1) | `mutex_unify`, `multiply_mutex` |
| [`fast_task/task/future.hpp`](../include/fast_task/task/future.hpp:1) | `future<T>`, `future_tool` |
| [`fast_task/task/queue.hpp`](../include/fast_task/task/queue.hpp:1) | `queue` |
| [`fast_task/task/deadline_timer.hpp`](../include/fast_task/task/deadline_timer.hpp:1) | `deadline_timer` |
| [`fast_task/coroutine.hpp`](../include/fast_task/coroutine.hpp:1) | `task_coro`, `task_generator`, helpers |
| [`fast_task/file.hpp`](../include/fast_task/file.hpp:1) | `file_handle`, `io_operation`, I/O handles |
| [`fast_task/net.hpp`](../include/fast_task/net.hpp:1) | `address`, `tcp_socket`, `tcp_listener` |
| [`fast_task/debug.hpp`](../include/fast_task/debug.hpp:1) | `debug` namespace |
| [`fast_task/allocator.hpp`](../include/fast_task/allocator.hpp:1) | `allocator`, `allocate`, `free` |
| [`fast_task/native.hpp`](../include/fast_task/native.hpp:1) | `native` namespace |
| [`fast_task/shared.hpp`](../include/fast_task/shared.hpp:1) | Export macros (`FT_API`, `FT_API_LOCAL`) |
| [`fast_task/shared/primitives.hpp`](../include/fast_task/shared/primitives.hpp:1) | `lock_guard`, `unique_lock`, `shared_lock`, `relock_guard`, lock tags |
| [`fast_task/polyfill/expected.hpp`](../include/fast_task/polyfill/expected.hpp:1) | `polyfill::expected` (non-throwing result type) |
| [`fast_task/interrupt.hpp`](../include/fast_task/interrupt.hpp:1) | `interrupt_unsafe_region` |
| [`fast_task/exceptions.hpp`](../include/fast_task/exceptions.hpp:1) | Exception hierarchy |
