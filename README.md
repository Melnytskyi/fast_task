# Fast task

is stack based green threads implementation for C++

this library aims to be simple, fast and powerful tool for concurrent programming in C++
it could simply replaced with std::thread, the only difference is the tasks do not implement joining or detaching

# Features
- guard pages for stacks(Windows)
- asynchronous file I/O
- asynchronous network I/O
- universal synchronization primitives for tasks and native threads
- task cancellation
- callbacks support
- preemptive scheduler (testing in Windows, Linux is incomplete)
    this feature could be disabled by setting tasks_enable_preemptive_scheduler_preview macro to false
- improved native threads implementation
    if application still using std::thread, this should be used when preemptive scheduler is enabled
    it prevents context switching by scheduler when mutex is locked to avoid deadlocks
    also it used more latest api for windows and reduces memory usage
    adds thread pausing and resuming support for windows and linux(linux is untested)

# Getting started

Prerequisites:
- C++20 compiler
- CMake 3.31 or later
- Windows or Linux
- vcpkg package manager (included in project as submodule)

Building:

1. Clone the repository:
   ```bash
   git clone https://github.com/Melnytskyi/fast_task.git
   git submodules update --init --recursive
   ```

2. Initialize vcpkg:
   ```bash
   cd fast_task
   ./vcpkg/bootstrap-vcpkg.sh
   ```
3. Build the project:
   ```bash
   ./vcpkg/vcpkg install
   cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=./vcpkg/scripts/buildsystems/vcpkg.cmake -DVCPKG_TARGET_TRIPLET=x64-windows-static 
   cmake --build build
   ```

Or your could use cmake presets in your IDE (e.g., Visual Studio, CLion) to configure and build the project.

# Usage

Add library to your project:
```cmake
add_subdirectory(fast_task)
target_link_libraries(PROJECT_NAME PRIVATE fast_task)
```
You can also use `find_package(fast_task CONFIG REQUIRED)` if you have installed the library globally.


# Contributing
Contributions are welcome! Please open issues or pull requests for bug fixes, features, or documentation improvements.

# License
This project is licensed under the Boost Software License - V1.0. See the LICENSE file for details.