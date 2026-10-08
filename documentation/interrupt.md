# Interrupt Safety & Preemption

When the preemptive scheduler is enabled
(`FAST_TASK_ENABLE_PREEMPTIVE_SCHEDULER=ON`), the scheduler can forcibly yield a
running task at any time. This is safe for Fast Task's own primitives, which are
scheduler-aware, but it is **not** safe for code that relies on hidden OS-level
locks. This page explains the problem and the
[`interrupt_unsafe_region`](../include/fast_task/interrupt.hpp:14) tool that
solves it.

Header: [`fast_task/interrupt.hpp`](../include/fast_task/interrupt.hpp:1)
(included by [`fast_task.hpp`](../include/fast_task.hpp:1)).

---

## The problem

Standard library facilities such as `malloc`, `new`, `std::cout`, and
`std::mutex` use internal OS locks that Fast Task cannot see. If the scheduler
preempts a task while it holds one of those locks, another task on the same
worker may try to acquire the same lock and deadlock — the first task cannot run
to release it until the scheduler resumes it, but the scheduler is busy running
the second task.

> **Rule of thumb:** any operation that may take a hidden OS lock must be wrapped
> in an `interrupt_unsafe_region` when preemption is enabled.

See [Architecture](architecture.md#scheduler-aware-synchronization--preemption-limits)
for the full explanation.

---

## `interrupt_unsafe_region`

[`interrupt_unsafe_region`](../include/fast_task/interrupt.hpp:14) is an RAII
guard that disables preemption for its scope:

```cpp
{
    fast_task::interrupt_unsafe_region region;
    // Preemption is disabled here.
    std::cout << "safe to use std::cout\n";
    auto* p = new int(42);
    delete p;
} // Preemption is re-enabled here.
```

The region is **nestable** and **per-thread**: entering it increments a counter,
leaving it decrements the counter, and preemption is only re-enabled when the
counter reaches zero.

### Members

| Member | Description |
|--------|-------------|
| [`interrupt_unsafe_region()`](../include/fast_task/interrupt.hpp:15) | Disables preemption for the scope. |
| [`~interrupt_unsafe_region()`](../include/fast_task/interrupt.hpp:16) | Re-enables preemption. |
| [`lock()`](../include/fast_task/interrupt.hpp:17) | Manually disables preemption (static). |
| [`unlock()`](../include/fast_task/interrupt.hpp:18) | Manually re-enables preemption (static). |
| [`lock_swap(state)`](../include/fast_task/interrupt.hpp:19) | Swaps the current state with `state` and returns the previous state (static). |

### Manual control

The static methods allow manual, non-RAII control — useful when the region
spans a callback boundary:

```cpp
std::size_t saved = fast_task::interrupt_unsafe_region::lock_swap(0);
// ... preemption disabled ...
fast_task::interrupt_unsafe_region::lock_swap(saved);
// ... previous state restored ...
```

---

## What is already safe

The following are scheduler-aware and do **not** need a region:

- Fast Task [synchronization primitives](synchronization.md) — `mutex`,
  `rw_mutex`, `condition_variable`, `semaphore`, `limiter`.
- [Native primitives](native.md) — `native::mutex`, `native::rw_mutex`,
  `native::condition_variable`, `native::spin_lock`.
- [`fast_task::allocate` / `fast_task::free`](allocator.md) — already wrapped in
  an interrupt-unsafe region internally.

## What needs a region

- `malloc` / `free` / `new` / `delete` (the raw C++ allocator).
- `std::cout`, `std::cerr`, `printf`, and other stdio facilities.
- `std::mutex`, `std::condition_variable`, and other standard-library locks.
- Any third-party library that uses hidden OS locks internally.

---

## When preemption is disabled

If `FAST_TASK_ENABLE_PREEMPTIVE_SCHEDULER` is `OFF` (the default), tasks are
cooperative and never preempted, so `interrupt_unsafe_region` is a no-op. It is
still safe to use unconditionally — the guard simply does nothing.

---

## Related Pages

- [Architecture](architecture.md#scheduler-aware-synchronization--preemption-limits) — why preemption and hidden locks conflict
- [Synchronization](synchronization.md#interrupt-unsafe-regions) — usage alongside the primitives
- [Allocator](allocator.md) — the allocator that already uses this guard
- [Getting Started](getting-started.md#feature-toggles) — the preemption build option
