# Contributing to `fast_task`

Thank you for contributing to `fast_task`!

## Prerequisites

- **C++20 compiler** (GCC 11+, Clang 14+, or MSVC 2022+; GCC 14+ / Clang 16+ for C++20 module builds)
- **CMake 3.20+** (3.28+ for `FAST_TASK_BUILD_MODULE=ON`) and **Ninja**
- **Linux dependencies:** `liburing-dev`, `libc-ares-dev`, `libboost-context-dev`, `pkg-config`

## Building & Running Tests

```bash
# Standard Debug test build (including I/O and network tests)
cmake -B out/build/Linux-Test -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DFAST_TASK_BUILD_TESTS=ON \
  -DFAST_TASK_DISABLE_IO_TESTS=OFF
cmake --build out/build/Linux-Test --parallel
ctest --test-dir out/build/Linux-Test --output-on-failure

# Preemptive scheduler test build
cmake -B out/build/Linux-Test-Preempt -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DFAST_TASK_BUILD_TESTS=ON \
  -DFAST_TASK_ENABLE_PREEMPTIVE_SCHEDULER=ON
cmake --build out/build/Linux-Test-Preempt --parallel
ctest --test-dir out/build/Linux-Test-Preempt --output-on-failure
```

## Benchmarks

```bash
cmake -B out/build/Linux-Release -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DFAST_TASK_BUILD_BENCHMARKS=ON
cmake --build out/build/Linux-Release --target benchmark_runner --parallel
./out/build/Linux-Release/benchmark/benchmark_runner
```

To run a single benchmark case:

```bash
./out/build/Linux-Release/benchmark/benchmark_runner --_run_child task_spawn_run_and_await
```

## Architecture & Style Checks

1. **Scheduler layer boundaries:** Run `bash scripts/check_layers.sh` before opening a PR to verify include direction across `src/tasks/core/` (`base -> pool -> notify -> runtime -> execution`).
2. **Formatting:** Follow `.clang-format` and `.editorconfig`.
3. **Documentation:** See [documentation/CONTRIBUTING.md](documentation/CONTRIBUTING.md) for documentation style conventions.
4. **Sanitizers:** When changing lock-free, futex, pool, or I/O code, test under Clang ASan+UBSan and TSan where possible.
