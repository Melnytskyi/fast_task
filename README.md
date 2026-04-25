[![Language](https://img.shields.io/badge/C%2B%2B-23-blue.svg)](https://isocpp.org/) 
[![License](https://img.shields.io/badge/License-BSL%201.0-orange.svg)](LICENSE)

# Fast Task: A High-Performance C++ Green Thread Library

**Fast Task** is a modern, tasking library for C++ designed to be a fast and powerful tool for handling I/O and CPU-bound tasks. It offers a lightweight alternative to `std::thread` as `fast_task::task`, focusing on high-performance asynchronous operations and efficient task management. An option to use stack-less coroutines, `fast_task::task_coro`, is also available to optimize memory consumption.

## Key Features

- **Lightweight Green Threads:** Utilizes stack-based green threads for efficient context switching, enabling high concurrency with minimal overhead.
- **Stack-less coroutines:** Integrated coroutines support to reduce memory consumption.
- **Asynchronous I/O:**
    - **File I/O:** Non-blocking file operations for reading and writing data.
    - **Network I/O:** Asynchronous networking capabilities for building responsive and scalable applications.
- **Advanced Synchronization:** Provides a rich set of synchronization primitives that work seamlessly with stackful/stackless tasks and native threads, including:
    - Mutexes (`task_mutex`, `task_recursive_mutex`, `task_rw_mutex`)
    - Condition Variables (`task_condition_variable`)
    - Semaphores (`task_semaphore`)
    - Utilities like `task_limiter` and `task_query` for managing concurrent access.
- **Preemptive Scheduler:** Includes a preemptive scheduler to prevent tasks from monopolizing execution time. This feature can be enabled if needed.
- **Task Cancellation:** Supports the cancellation of tasks, allowing for graceful termination of operations.
- **Improved Native Thread Implementation:** Offers an enhanced version of native threads for cases when a lock is used in a task with the preemptive scheduler enabled by avoiding context switching when a mutex is locked. It also utilizes modern APIs for Windows, reduces memory usage, and adds support for thread pausing and resuming.
- **Callback Support:** Facilitates the use of callbacks for handling asynchronous events or even adding support for custom coroutines.
- **Stack Protection:** Implements guard pages for stacks on Windows to protect against stack overflows.
- **Introspection API:** Allows for a "stop-the-world" operation to inspect the program state.

## Getting Started

### Prerequisites

- **C++23 Compiler:** A compiler that supports C++23 is required.
- **CMake:** Version 3.31 or later.
- **Operating System:** Windows or Linux.
- **vcpkg:** The vcpkg package manager is used for dependency management and is included as a submodule in the project root.
- **Dependencies:** If the introspection API is enabled, `cpptrace` is required. For Linux builds, `liburing` is required.

### Building the Project

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/Melnytskyi/fast_task.git
    cd fast_task
    git submodule update --init --recursive
    ```

2.  **Initialize vcpkg:**
    ```bash
    ./vcpkg/bootstrap-vcpkg.sh
    ```

3.  **Install Dependencies and Build:**
    ```bash
    ./vcpkg/vcpkg install
    cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=./vcpkg/scripts/buildsystems/vcpkg.cmake -DVCPKG_TARGET_TRIPLET=x64-windows-static
    cmake --build build
    ```
    Alternatively, you can use the CMake presets available in the `CMakePresets.json` file with an IDE like Visual Studio or CLion to configure and build the project.

### Project Structure

The repository is organized as follows:
-   `include/`: Public header files for the library.
-   `src/`: Source code, including implementation details for tasks, networking, and file operations.
-   `CMakeLists.txt`: The main CMake build script.
-   `vcpkg.json`: vcpkg manifest for dependencies (`boost-context`, `concurrentqueue`, `cpptrace`, `liburing`).
-   `LICENSE`: The Boost Software License under which the project is distributed.

## Usage

To integrate `fast_task` into your project, you can add it as a subdirectory in your `CMakeLists.txt`:

```cmake
add_subdirectory(fast_task)
target_link_libraries(YOUR_PROJECT_NAME PRIVATE fast_task)
```

If you have installed the library globally, you can use `find_package`:

```cmake
find_package(fast_task CONFIG REQUIRED)
target_link_libraries(YOUR_PROJECT_NAME PRIVATE fast_task)
```

There are also multiple CMake options to enable or disable features or checks:
 - `FAST_TASK_STATIC`: Enable static build for the fast_task library.
 - `FAST_TASK_ENABLE_DEBUG_API`: Enables the `include/debug.hpp` functionality.
 - `FAST_TASK_ENABLE_PREEMPTIVE_SCHEDULER`: Enables time-sliced preemption for tasks.
 - `FAST_TASK_ENABLE_ABORT_IF_ALREADY_STARTED`: Aborts if a task is started more than once.
 - `FAST_TASK_ENABLE_ABORT_IF_NEVER_STARTED`: Aborts if a task's destructor is called before the task was ever started.
 - `FAST_TASK_EXCEPTION_POLICY`: Changes behavior for context switches. Options are `NONE`, `CHECK`, or `PRESERVE`.

## Contributing

Contributions to `fast_task` are welcome. Whether it's bug fixes, new features, or documentation improvements, please feel free to open an issue or submit a pull request.

## Short Architecture Description

This library implements a lock-free work-stealing scheduler to minimize scheduling overhead. It utilizes multiple queues for tasks in varying states:
- `glob.cold_tasks`: A queue for tasks that do not yet have a stack allocated (in the stackful case).
- `glob.tasks`: A queue for the working set of tasks ready to be picked by any global scheduler thread.
- `loc.local_tasks`: A thread-local work-stealing queue to increase cache locality and reduce contention.

For bound executors, a similar structure, `binded_context`, is assigned to each.

Timing is implemented using a dedicated time controller thread (`taskTimer`). All task-related timing is managed by this thread. It uses an `awake_check` counter for each task; when a task is awakened for any reason, this counter is incremented, which can invalidate a pending timed wake-up and prevent redundant scheduling.

The synchronization primitives create their own condition variables with a flag for each awaiting native thread. This effectively solves the issue of spurious wakeups by allowing the thread to confirm it was intentionally notified.

The `task` class utilizes a unified callback architecture with manual type erasure and Small Buffer Optimization (SBO). This design efficiently stores task states (like capturing lambdas) without unnecessary heap allocations and ensures C++17 compatibility by avoiding standard library function wrappers. It provides the flexibility to set custom await, cancel, exception handling, or destruct operations. This architecture allows tasks to execute directly on worker threads without allocating separate stacks (stackless) or to run with separate stacks (stackful). It also allows tasks to be restartable, enabling yield-like behavior for both stackful and stackless tasks. This mechanism forms the foundation for implementing coroutines, network I/O, and file I/O.

Time-slicing interrupts are processed outside the main time controller. On Windows, when a timer expires, an `interrupt_processor` thread uses `fast_task::thread::insert_context` to execute the `interruptTask` function. On Linux, it uses a custom signal (`PREEMPTION_SIGNAL`) for the same purpose. On both platforms, `interruptTask` checks if preemption is safe and then uses `swapCtx` to switch back to the scheduler. Stackless tasks do not support preemption as they execute directly on the scheduler's thread.

## License

This project is licensed under the **Boost Software License - Version 1.0**. For more details, please see the [LICENSE](https://github.com/Melnytskyi/fast_task/blob/main/LICENSE) file.

## SAST Tools

[PVS-Studio](https://pvs-studio.com/en/pvs-studio/?utm_source=website&utm_medium=github&utm_campaign=open_source) - static analyzer for C, C++, C#, and Java code.