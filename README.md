[![Language](https://img.shields.io/badge/C%2B%2B-20%2B-blue.svg)](https://isocpp.org/) 
[![License](https://img.shields.io/badge/License-BSL%201.0-orange.svg)](LICENSE)

![alt text](images/unnamed.png "Title")

# Fast Task: A High-Performance C++ Green Thread & Coroutine Library

**Fast Task** is a modern, high-performance tasking library for C++ designed for complex CPU-bound and I/O-bound workloads. It provides a lightweight, highly scalable alternative to `std::thread` via `fast_task::task`. 

Built on a lock-free work-stealing scheduler, Fast Task allows developers to seamlessly write concurrent code using stackful green threads, C++20 stackless coroutines (`fast_task::task_coro`), or asynchronous I/O, all while keeping memory consumption and context-switching overhead to an absolute minimum.

## Key Features

- **Universal Synchronization (Mix & Match):** Primitives like `task_mutex`, `task_rw_mutex`, and `task_condition_variable` are designed to bridge execution contexts. You can safely mix stackful tasks, stackless coroutines, and OS-level native threads—all waiting on the exact same synchronization primitive without blocking the underlying scheduler worker threads.
- **C++20 Stackless Coroutines:** Full support for modern `co_await` syntax to create ultra-lightweight, state-machine-based tasks that consume a fraction of the memory of standard threads.
- **Lock-Free Work-Stealing Scheduler:** An M:N scheduler architecture using thread-local deques to maximize CPU cache locality and eliminate lock contention during task dispatching.
- **Asynchronous I/O Multiplexing:** Built-in non-blocking file and network I/O operations (leveraging `io_uring` on Linux and IOCP on Windows) for highly responsive server applications.
- **Preemptive & Cooperative Scheduling:** Operates cooperatively by default for maximum throughput, but includes an optional time-sliced preemptive scheduler to prevent long-running tasks from monopolizing worker threads.
- **Advanced Task Management:** Support for graceful task cancellation, timeout handling, and bound executors for strict thread affinity.
- **Introspection & Debugging:** Features a "stop-the-world" API to inspect program state, alongside native thread naming and Windows guard pages for stack overflow protection.

## Core Concepts

### Stackful Tasks vs. Stackless Coroutines
Fast Task gives you the flexibility to choose the right concurrency model for your workload:
* **Stackful Tasks (`fast_task::task`):** Allocate their own execution stack. They behave exactly like native threads, allowing deep call chains and standard execution flow, but context switch in user-space much faster than OS threads.
* **Stackless Coroutines (`fast_task::task_coro`):** Do not allocate a separate stack. They execute directly on the scheduler's worker thread. Because they suspend by saving state rather than swapping stacks, they are perfect for massive concurrency (e.g., millions of concurrent network connections).

### Unified Execution & I/O Model
Rather than managing separate thread pools for CPU workloads and I/O polling, Fast Task unifies them. Whether a task is waiting on a file read, a network packet, or a synchronization primitive, it yields cooperatively to the scheduler without blocking the underlying OS thread. This allows you to write straight-line, synchronous-looking code that operates asynchronously under the hood, maximizing hardware utilization.

## Getting Started

### Prerequisites

- **Compiler:** C++20 compatible compiler (GCC, Clang, MSVC).
- **CMake:** Version 3.20 or later.
- **OS:** Windows or Linux.
- **Dependencies:** `cpptrace` (if the Introspection API is enabled). `liburing` (required for Linux builds).

### Building the Project

**Method 1: Using an IDE**
Clone the repository and open it in a modern IDE (Visual Studio, CLion, VS Code). The IDE will automatically detect the configurations from `CMakePresets.json` and configure the build environment.

**Method 2: Standard CMake**
1. Clone the repository:
   ```bash
   git clone https://github.com/Melnytskyi/fast_task.git ./fast_task
   cd fast_task
   ```
2. Build the project:
   ```bash
   cmake -B build -S .
   cmake --build build
   ```
*(Note: CMake will automatically download most dependencies. On Linux, you may need to install `liburing-dev` via your system package manager).*

**Method 3: Using vcpkg**
1. Clone and initialize:
   ```bash
   git clone https://github.com/Melnytskyi/fast_task.git ./fast_task
   cd fast_task
   git submodule update --init --recursive
   ./vcpkg/bootstrap-vcpkg.sh
   ./vcpkg/vcpkg install
   ```
2. Configure and build:
   ```bash
   cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=./vcpkg/scripts/buildsystems/vcpkg.cmake -DVCPKG_TARGET_TRIPLET=x64-linux-static
   cmake --build build
   ```

## Integration & Usage

Add `fast_task` to your project by including it as a subdirectory in your `CMakeLists.txt`:
```cmake
add_subdirectory(fast_task)
target_link_libraries(YOUR_PROJECT_NAME PRIVATE fast_task)
```

Alternatively, if installed globally, use `find_package`:

```cmake
find_package(fast_task CONFIG REQUIRED)
target_link_libraries(YOUR_PROJECT_NAME PRIVATE fast_task)
```

### CMake Configuration Options
Customize the library build using the following CMake flags:
- `FAST_TASK_STATIC`: Build `fast_task` as a static library.
- `FAST_TASK_ENABLE_DEBUG_API`: Enables debugging utilities found in `include/debug.hpp`.
- `FAST_TASK_ENABLE_PREEMPTIVE_SCHEDULER`: Enables time-sliced preemption for tasks.
- `FAST_TASK_ENABLE_ABORT_IF_ALREADY_STARTED`: Forces an abort if a task is started multiple times.
- `FAST_TASK_ENABLE_ABORT_IF_NEVER_STARTED`: Forces an abort if a task is destroyed before execution.
- `FAST_TASK_EXCEPTION_POLICY`: Defines context switch exception behavior (`NONE`, `CHECK`, or `PRESERVE`).

## Architecture Overview

**Work-Stealing Scheduler**
To minimize scheduling overhead and lock contention, Fast Task utilizes a multi-tiered queue system:
- `loc.local_tasks`: A lock-free, thread-local work-stealing deque. Prioritizes cache locality.
- `glob.tasks`: A global queue for hot tasks ready to be picked up by any available scheduler thread.
- `glob.cold_tasks`: A fallback queue for uninitialized tasks (e.g., stackful tasks waiting for stack allocation).

**Time and Awake Management**
Task timeouts and deadlines are handled by a dedicated `taskTimer` thread. To prevent race conditions and redundant wake-ups, each task maintains an `awake_check` counter. If a task is awakened via synchronization before its timer expires, this counter invalidates the pending timed event. 

**Scheduler-Aware Synchronization & Preemption Limits**
Fast Task's custom synchronization primitives (e.g., `task_mutex`) and its own native locks (`fast_task::mutex`) are scheduler-aware. When the preemptive scheduler is enabled, they automatically prevent context-switching while a lock is held. **Crucially, standard library features that rely on hidden internal OS locks—such as `malloc`, `new`, `std::cout`, and `std::mutex`—lack this awareness and are completely incompatible with preemption.** If the scheduler hijacks a thread while it holds an internal system lock, it can cause deadlocks. To safely use standard library allocations, I/O streams, or OS-level locks with preemption enabled, developers must explicitly wrap those operations within an `interrupt_unsafe_region`. Additionally, the library's primitives solve standard C++ spurious wakeups using dedicated condition variables with targeted per-thread flags.

**Preemption Mechanics**
If enabled, preemption runs outside the standard time controller. On Windows, an `interrupt_processor` intercepts expired timers and uses `insert_context` to hijack the execution flow. On Linux, a dedicated `PREEMPTION_SIGNAL` interrupts the thread. In both cases, the handler safely checks for lock-free boundaries before invoking `swapCtx` to forcibly yield the task.

## Contributing
Contributions are highly encouraged. Whether it's reporting bugs, optimizing algorithms, extending I/O support, or improving documentation, please feel free to open an issue or submit a pull request.

## SAST Tools
[PVS-Studio](https://pvs-studio.com/en/pvs-studio/?utm_source=website&utm_medium=github&utm_campaign=open_source) — a static analyzer for C, C++, C#, and Java code.