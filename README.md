[![Language](https://img.shields.io/badge/C%2B%2B-20%2B-blue.svg)](https://isocpp.org/)
[![License](https://img.shields.io/badge/License-BSL%201.0-orange.svg)](LICENSE)

![alt text](images/unnamed.png "Title")

# Fast Task: A High-Performance C++ Green Thread & Coroutine Library

**Fast Task** is a modern, high-performance tasking framework for C++ designed for
complex CPU-bound and I/O-bound workloads. It provides a lightweight, highly
scalable alternative to `std::thread` via [`fast_task::task`](include/fast_task/task/task.hpp:51).

Built on a lock-free work-stealing scheduler, Fast Task lets you write concurrent
code using stackful green threads, C++20 stackless coroutines
([`fast_task::task_coro`](include/fast_task/coroutine/core.hpp:270)), or asynchronous
I/O — all while keeping memory consumption and context-switching overhead minimal.

## Features

- **Universal synchronization (mix & match):** [`mutex`](include/fast_task/task/mutex.hpp:21),
  [`rw_mutex`](include/fast_task/task/mutex.hpp:115), and
  [`condition_variable`](include/fast_task/task/condition_variable.hpp:19) bridge
  execution contexts, so stackful tasks, stackless coroutines, and OS threads can
  wait on the same primitive without blocking scheduler workers.
- **C++20 stackless coroutines:** `co_await`-based tasks that consume a fraction of
  the memory of a thread.
- **Work-stealing scheduler:** M:N architecture with thread-local deques for cache
  locality and minimal lock contention.
- **Asynchronous I/O:** Non-blocking file and network operations (`io_uring` on
  Linux, IOCP on Windows).
- **Preemptive & cooperative scheduling:** Cooperative by default, with an optional
  time-sliced preemptive scheduler.
- **Task management:** Cancellation, timeouts, priorities, and bound executors.
- **Introspection & debugging:** Stop-the-world state dumps and stack traces.

## Why Fast Task?

| Aspect | `std::thread` | Boost.Fiber | **Fast Task** |
|--------|---------------|-------------|---------------|
| Scheduling | OS preemptive | Cooperative | Cooperative + optional preemptive |
| Context switch | Kernel syscall | User-space | User-space |
| Synchronization | OS locks | Spinlock + waiter list | Single-atomic [futex](documentation/futex.md) |
| Task-to-task handoff | Syscall | Spinlock + list walk | Scheduler context switch, no syscall |
| Stackless coroutines | — | — | Yes ([`task_coro`](documentation/task/coroutines.md)) |
| Async I/O | — | — | `io_uring` / IOCP |
| Mixing models | — | — | Tasks, coroutines, and native threads share primitives |

Fast Task's primitives keep their entire state in a single atomic word and park
task waiters directly on the scheduler, so a contended handoff between two tasks
is a context switch rather than a syscall. See the
[Futex](documentation/futex.md) page for the design and the
[benchmark results](benchmark/results/bench.md) for measured numbers.

## Quick Start

```cpp
#include <fast_task.hpp>

int main() {
    fast_task::task t = fast_task::task::run([] {
        // Runs on a scheduler worker thread.
    });
    t.await_task();

    fast_task::scheduler::shut_down();
}
```

Build and integrate:

```bash
cmake -B build -S .
cmake --build build
```

```cmake
add_subdirectory(fast_task)
target_link_libraries(YOUR_PROJECT_NAME PRIVATE fast_task)
```

## Documentation

Full documentation lives in the [`documentation/`](documentation/README.md) folder:

| Topic | Description |
|-------|-------------|
| [Getting Started](documentation/getting-started.md) | Prerequisites, building, integration, CMake options, model comparison |
| [Architecture](documentation/architecture.md) | Scheduler, timers, preemption, synchronization internals |
| [Tasks](documentation/tasks.md) | Stackful task API and lifecycle |
| [Coroutines](documentation/task/coroutines.md) | Stackless coroutine API, generators, helpers |
| [Synchronization](documentation/synchronization.md) | Mutexes, condition variables, semaphores, limiters |
| [Futex](documentation/futex.md) | The single-atomic futex layer behind the primitives |
| [Asynchronous I/O](documentation/io.md) | File and network operations |
| [Futures](documentation/futures.md) | `future<T>` API and chaining |
| [Scheduler](documentation/scheduler.md) | Executors, queues, timers, lifecycle |
| [Debugging](documentation/debugging.md) | Introspection and stop-the-world dumps |
| [Allocator](documentation/allocator.md) | Custom allocator and `at` tag |
| [Native Primitives](documentation/native.md) | OS-level threads, mutexes, condition variables |
| [Interrupt Safety](documentation/interrupt.md) | `interrupt_unsafe_region` and preemption-safe coding |
| [Exceptions](documentation/exceptions.md) | The exception hierarchy and `task_cancellation` |
| [Troubleshooting & FAQ](documentation/troubleshooting.md) | Common deadlocks, exceptions, and build issues |

## Contributing

Contributions are welcome — bug reports, optimizations, extended I/O support, and
documentation improvements. Open an issue or submit a pull request.

## SAST Tools

[PVS-Studio](https://pvs-studio.com/en/pvs-studio/?utm_source=website&utm_medium=github&utm_campaign=open_source) — a static analyzer for C, C++, C#, and Java code.
