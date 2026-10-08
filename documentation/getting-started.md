# Getting Started

This page covers prerequisites, building Fast Task, integrating it into your
project, and the available CMake configuration options.

## Prerequisites

- **Compiler:** A C++20-compatible compiler (GCC, Clang, or MSVC).
- **CMake:** Version 3.20 or later.
- **OS:** Windows or Linux.
- **Dependencies:**
  - `cpptrace` — required only when the introspection API is enabled
    (`FAST_TASK_ENABLE_DEBUG_API`).
  - `liburing` — required for Linux builds.

## Building the Project

### Method 1: Using an IDE

Clone the repository and open it in a modern IDE (Visual Studio, CLion, VS Code).
The IDE detects the configurations from [`CMakePresets.json`](../CMakePresets.json:1)
and configures the build environment automatically.

### Method 2: Standard CMake

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

   > CMake automatically downloads most dependencies. On Linux you may need to
   > install `liburing-dev` via your system package manager.

### Method 3: Using vcpkg

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

Add `fast_task` as a subdirectory in your `CMakeLists.txt`:

```cmake
add_subdirectory(fast_task)
target_link_libraries(YOUR_PROJECT_NAME PRIVATE fast_task)
```

Alternatively, if installed globally, use `find_package`:

```cmake
find_package(fast_task CONFIG REQUIRED)
target_link_libraries(YOUR_PROJECT_NAME PRIVATE fast_task)
```

Then include the umbrella header:

```cpp
#include <fast_task.hpp>
```

## Optional C++20 Module Wrapper

Fast Task can optionally be consumed as a C++20 module instead of through
`#include` directives. Enable the wrapper with `FAST_TASK_BUILD_MODULE`:

```bash
cmake -B build -S . -DFAST_TASK_BUILD_MODULE=ON
cmake --build build
```

This builds the `fast_task::module` target, which exposes the entire public API
through a single module interface unit
([`include/fast_task.cppm`](../include/fast_task.cppm:1)). Consumers link against
`fast_task::module` and use `import`:

```cmake
add_subdirectory(fast_task)
target_link_libraries(YOUR_PROJECT_NAME PRIVATE fast_task::module)
```

```cpp
import fast_task;

int main() {
    fast_task::task t = fast_task::task::run([] { /* ... */ });
    t.await_task();

    fast_task::scheduler::shut_down();
}
```

The module is a thin facade: it includes the public headers inside a global module
fragment and re-exports the public names, so the header-based and module-based APIs
are always in sync. Both can be used side by side in the same project.

**Requirements:** CMake 3.28+, a compiler with C++20 modules support (GCC 14+,
Clang 16+, or MSVC 19.34+), and a generator with module dependency scanning (Ninja
or Visual Studio). The option is `OFF` by default, so existing header-based
consumers are unaffected.

## CMake Configuration Options

The following options are defined in [`cmake/Options.cmake`](../cmake/Options.cmake:1).

### Feature toggles

| Option | Default | Description |
|--------|---------|-------------|
| `FAST_TASK_STATIC` | `ON` | Build `fast_task` as a static library. |
| `FAST_TASK_BUILD_TESTS` | `OFF` | Build the test suite. |
| `FAST_TASK_BUILD_BENCHMARKS` | `OFF` | Build the benchmark suite. |
| `FAST_TASK_BUILD_MODULE` | `OFF` | Build the optional C++20 module wrapper (`import fast_task;`). |
| `FAST_TASK_DISABLE_IO_TESTS` | `ON` | Disable I/O tests. |
| `FAST_TASK_ENABLE_DEBUG_API` | `OFF` | Enable the debugging and introspection API ([`debug.hpp`](../include/fast_task/debug.hpp:1)). |
| `FAST_TASK_ENABLE_ABORT_IF_ALREADY_STARTED` | `OFF` | Abort if a task is started more than once. |
| `FAST_TASK_ENABLE_ABORT_IF_NEVER_STARTED` | `OFF` | Abort if a task's destructor runs before it ever started. |
| `FAST_TASK_ENABLE_PREEMPTIVE_SCHEDULER` | `OFF` | Enable time-sliced preemption. Tasks must use [`interrupt_unsafe_region`](synchronization.md#interrupt-unsafe-regions) around regions where preemption must be disabled. |
| `FAST_TASK_INCLUDE_THREAD_INTERRUPT_CODE` | `ON` | Allow stopping a thread and running a custom function on top of its stack. No effect when the preemptive scheduler is enabled. |
| `FAST_TASK_WARNINGS_AS_ERRORS` | `OFF` | Treat compiler warnings as errors. |

### Tuning parameters

| Option | Default | Description |
|--------|---------|-------------|
| `FAST_TASK_GUARD_PAGE_COUNT` | `1` | Number of `PROT_NONE` (Linux) / `PAGE_GUARD` (Windows) pages at the bottom of each task stack. `0` disables guard pages. |
| `FAST_TASK_TASK_TRANSFERS_LIMIT` | `8` | Maximum number of cooperative task transfers without a context switch. `0` means no limit. |
| `FAST_TASK_MAX_EXECUTORS` | `1024` | Maximum number of work-stealing entries. |
| `FAST_TASK_BINDED_MAX_SLOTS` | `64` | Maximum threads per bound pool. |
| `FAST_TASK_MAX_STEAL_ATTEMPTS` | `3` | Number of steal attempts from a random worker. |
| `FAST_TASK_TIMER_PRECISION` | `1ms` | Timer wheel precision: `1us`, `1ms`, or `10ms`. |
| `FAST_TASK_EXCEPTION_POLICY` | `NONE` | Context-switch exception policy: `NONE`, `CHECK`, or `PRESERVE`. |

### Preemption quantum tuning

When the preemptive scheduler is enabled, each priority level has a basic and a
maximum time slice (in nanoseconds). These are advanced settings:

| Priority | Basic quantum | Max quantum |
|----------|---------------|-------------|
| `background` | 15 ms | 30 ms |
| `low` | 30 ms | 60 ms |
| `lower` | 40 ms | 80 ms |
| `normal` | 80 ms | 160 ms |
| `higher` | 90 ms | 180 ms |
| `high` | 120 ms | 240 ms |

The corresponding cache variables are `FAST_TASK_PREEMPT_<PRIORITY>_BASIC_QUANTUM_NS`
and `FAST_TASK_PREEMPT_<PRIORITY>_MAX_QUANTUM_NS`.

### Exception policy details

`FAST_TASK_EXCEPTION_POLICY` controls what happens when a context switch occurs
while an exception is in flight:

- **`NONE`** — No checks. Fastest.
- **`CHECK`** — Abort if a context switch occurs inside a `catch` block or another
  exception-handling stage. Has a performance cost.
- **`PRESERVE`** — Preserve the exception across the context switch and rethrow it
  when switched back. Has a performance cost.

## Choosing a Concurrency Model

Fast Task offers three interoperable execution models. All three can share the
same [synchronization primitives](synchronization.md), so you can mix them in a
single program.

| Model | Stack | Memory per unit | Switch cost | Best for |
|-------|-------|-----------------|-------------|----------|
| [`task`](tasks.md) (stackful) | Own stack | High (tens of KB+) | User-space context switch | Deep call chains, synchronous-looking code, blocking-style APIs |
| [`task_coro`](task/coroutines.md) (stackless) | None | Very low (state only) | Function resume | Massive concurrency (millions of connections), `co_await`-style code |
| [`native::thread`](native.md#nativethread) | OS stack | Highest | OS thread switch (syscall) | Bridging to OS APIs, CPU-bound work outside the scheduler |

**Guidance:**

- Start with **stackful tasks** for general work — they behave like threads and
  can use every primitive.
- Switch to **stackless coroutines** when memory or scale is the bottleneck.
- Use **native threads** only when you must interact with OS-level APIs or code
  that cannot run on the scheduler.

See [Architecture — Execution Contexts](architecture.md#execution-contexts) for
how stackful and stackless tasks differ internally.

## Compatibility

| Requirement | Minimum |
|-------------|---------|
| C++ standard | C++20 |
| CMake | 3.20 (3.28+ for the C++20 module wrapper) |
| GCC | 11+ (14+ for the module wrapper) |
| Clang | 14+ (16+ for the module wrapper) |
| MSVC | 19.30+ (19.34+ for the module wrapper) |
| Platforms | Linux (with `liburing`), Windows |
| Generators | Any (Ninja or Visual Studio required for the module wrapper) |

The optional C++20 module wrapper additionally requires a generator with module
dependency scanning. See
[Optional C++20 Module Wrapper](#optional-c20-module-wrapper).

## Next Steps

- Read the [Architecture](architecture.md) overview to understand the scheduler.
- Learn the [Tasks](tasks.md) API for stackful concurrency.
- Explore [Coroutines](task/coroutines.md) for stackless concurrency.
- Check [Troubleshooting & FAQ](troubleshooting.md) for common pitfalls.
