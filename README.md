[![Language](https://img.shields.io/badge/C%2B%2B-20-blue.svg)](https://isocpp.org/) 
[![License](https://img.shields.io/badge/License-BSL%201.0-orange.svg)](LICENSE)

# Fast Task: A High-Performance C++ Green Thread Library

**Fast task** is a modern, stack-based green thread implementation for C++ designed to be a simple, fast, and powerful tool for concurrent programming. It offers a lightweight alternative to `std::thread`, focusing on high-performance asynchronous operations and efficient task management.

_the library technically could be used by client code with C++23 for the coroutines support_

## Core Features

- **Lightweight Green Threads:** Utilizes stack-based green threads for efficient context switching, enabling high concurrency with minimal overhead.
- **Asynchronous I/O:**
    - **File I/O:** Non-blocking file operations for reading and writing data.
    - **Network I/O:** Asynchronous networking capabilities for building responsive and scalable applications.
- **Advanced Synchronization:** Provides a rich set of synchronization primitives that work seamlessly with both tasks and native threads, including:
    - Mutexes (`task_mutex`, `task_recursive_mutex`, `task_rw_mutex`)
    - Condition Variables (`task_condition_variable`)
    - Semaphores (`task_semaphore`)
    - Utilities like `task_limiter` and `task_query` for managing concurrent access.
- **Preemptive Scheduler:** Includes a preemptive scheduler (currently in testing for Windows, with incomplete Linux support) to prevent tasks from monopolizing execution time. This feature can be disabled if not needed.
- **Task Cancellation:** Supports cancellation of tasks, allowing for graceful termination of operations. 
- **Improved Native Thread Implementation:** Offers an enhanced version of native threads that prevents deadlocks when used with the preemptive scheduler by avoiding context switching when a mutex is locked.  It also utilizes modern APIs for Windows, reduces memory usage, and adds support for thread pausing and resuming.
- **Callback Support:** Facilitates the use of callbacks for handling asynchronous events.
- **Stack Protection:** Implements guard pages for stacks on Windows to protect against stack overflows.

## Getting Started

### Prerequisites

- **C++20 Compiler:** A compiler that supports C++20 is required.
- **CMake:** Version 3.31 or later. 
- **Operating System:** Windows or Linux.
- **vcpkg:** The vcpkg package manager is used for dependency management and included as a submodule in the project root.
- **dependencies** If the introspection api enabled the cpptrace is required and for linux builds the liburing is required

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
-   `vcpkg.json`: vcpkg manifest for dependencies (`boost-context`, `boost-lockfree`, `cpptrace`, `liburing`).
-   `LICENSE`: The Boost Software License under which the project is distributed. 

## Usage

To integrate `fast_task` into your project, you can add it as a subdirectory in your `CMakeLists.txt`:

```cmake
add_subdirectory(fast_task)
target_link_libraries(YOUR_PROJECT_NAME PRIVATE fast_task)
````

If you have installed the library globally, you can use `find_package`:

```cmake
find_package(fast_task CONFIG REQUIRED)
target_link_libraries(YOUR_PROJECT_NAME PRIVATE fast_task)
```

## Contributing

Contributions to `fast_task` are welcome. Whether it's bug fixes, new features, or documentation improvements, please feel free to open an issue or submit a pull request. 

## License

This project is licensed under the **Boost Software License - Version 1.0**. For more details, please see the [LICENSE](https://github.com/Melnytskyi/fast_task/blob/main/LICENSE) file. 

## SAST Tools

[PVS-Studio](https://pvs-studio.com/en/pvs-studio/?utm_source=website&utm_medium=github&utm_campaign=open_source) - static analyzer for C, C++, C#, and Java code.