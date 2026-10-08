# Debugging & Introspection

Fast Task can expose a consistent snapshot of its entire runtime state — tasks,
mutexes, condition variables, semaphores, queues, and timers — for debugging,
profiling, or tooling. The API lives in the
[`fast_task::debug`](../include/fast_task/debug.hpp:18) namespace.

Header: [`fast_task/debug.hpp`](../include/fast_task/debug.hpp).

> **Build requirement:** the full debug API is only available when the library
> is built with `FAST_TASK_ENABLE_DEBUG_API`. Without it, dumps are empty and
> initialization stack traces are never captured. See
> [Getting Started](getting-started.md) for the option.

---

## Stop-the-world snapshots

All snapshot functions briefly pause the scheduler (a *stop-the-world* pause) to
capture a consistent view. They may only be called from a **native thread** —
calling them from a task throws `invalid_native_context`.

| Function | Description |
|----------|-------------|
| [`dump_program_state()`](../include/fast_task/debug.hpp:36) | Returns a [`program_state_dump`](../include/fast_task/debug.hpp:386) of the whole runtime |
| [`save_program_state_dump(path)`](../include/fast_task/debug.hpp:39) | Writes a dump to a file |
| [`iterate_task_objects(callback, data)`](../include/fast_task/debug.hpp:53) | Iterates every live task object |

`dump_program_state` captures only *raw* data (IDs, states, ownership, raw stack
frames). Expensive work such as symbol resolution is deferred until you ask for
it, keeping the pause short.

```cpp
fast_task::debug::program_state_dump dump = fast_task::debug::dump_program_state();
for (auto& t : dump.tasks) {
    // inspect t.status, t.priority, t.call_stack, ...
}
```

`iterate_task_objects` differs from `dump_program_state`: it walks the task
object allocator directly, so it still works even when debug tracking is
disabled.

---

## Stack traces

| Function | Description |
|----------|-------------|
| [`request_task_stack_trace(task)`](../include/fast_task/debug.hpp:67) | Captures a task's current stack trace |
| [`request_task_init_stack_trace(task)`](../include/fast_task/debug.hpp:80) | Returns the stack trace captured when the task was created |
| [`enable_init_stack_trace(enable)`](../include/fast_task/debug.hpp:81) | Enables or disables init-trace capture |
| [`is_debug_enabled()`](../include/fast_task/debug.hpp:82) | Whether the debug API is compiled in |

A [`raw_stack_trace`](../include/fast_task/debug.hpp:189) holds an
[`array`](../include/fast_task/debug.hpp:86) of
[`entry`](../include/fast_task/debug.hpp:190) objects. Each entry resolves
lazily:

| Member | Description |
|--------|-------------|
| [`symbol()`](../include/fast_task/debug.hpp:205) | Symbol name (empty if unavailable) |
| [`file()`](../include/fast_task/debug.hpp:206) | Source file (empty if unavailable) |
| [`line()`](../include/fast_task/debug.hpp:207) | Line number (`-1` if unavailable) |
| [`column()`](../include/fast_task/debug.hpp:208) | Column number (`-1` if unavailable) |
| [`is_inline()`](../include/fast_task/debug.hpp:209) | Whether the frame is inlined |

```cpp
if (auto trace = fast_task::debug::request_task_stack_trace(some_task)) {
    for (auto& frame : trace->entries)
        std::cout << frame.symbol() << " @ " << frame.file() << ':' << frame.line() << '\n';
}
```

---

## Dump structures

[`program_state_dump`](../include/fast_task/debug.hpp:386) aggregates arrays of
per-object records, each carrying a `created_by_id` / `created_by_is_native`
pair identifying the creator, plus an optional `init_call_stack`.

| Field | Record type | Contents |
|-------|-------------|----------|
| `tasks` | [`raw_task_info`](../include/fast_task/debug.hpp:220) | Task ID, status, flags, priority, bind worker, counters, call stack |
| `mutexes` | [`raw_mutex_info`](../include/fast_task/debug.hpp:267) | Owner, waiters |
| `rec_mutexes` | [`raw_recursive_mutex_info`](../include/fast_task/debug.hpp:281) | Recursion count, internal mutex |
| `rw_mutexes` | [`raw_rw_mutex_info`](../include/fast_task/debug.hpp:294) | Writer, readers, waiters with reader/writer keys |
| `condition_variables` | [`raw_condition_info`](../include/fast_task/debug.hpp:313) | Waiters |
| `semaphores` | [`raw_semaphore_info`](../include/fast_task/debug.hpp:325) | Thresholds, waiters |
| `limiters` | [`raw_limiter_info`](../include/fast_task/debug.hpp:339) | Thresholds, locked flag, waiters |
| `queries` | [`raw_queue_info`](../include/fast_task/debug.hpp:354) | In-run count, max concurrency, enabled flag |
| `deadlines` | [`raw_deadline_timer_info`](../include/fast_task/debug.hpp:370) | Timestamp, scheduled/canceled tasks |

### Task status

[`raw_task_info::status_e`](../include/fast_task/debug.hpp:222) is one of
`created`, `scheduled`, `running`, `suspending`, `suspended`, or `ended`.

### Waiters

[`awake_item`](../include/fast_task/debug.hpp:183) describes a task waiting on an
object: its `id`, an `awake_check` generation counter, and whether the waiter is
a native thread. The `awake_check` value guards against stale wakeups — if it
does not match the scheduler's current value, the wakeup is ignored.

---

## The `array` helper

[`debug::array<T>`](../include/fast_task/debug.hpp:86) is a move-only,
allocator-backed dynamic array used throughout the dump structures. It exists so
that dumps can cross shared-library boundaries safely. It supports
`operator[]`, `begin()`/`end()`, and move construction/assignment.

---

## Related Pages

- [Architecture](architecture.md) — stop-the-world and scheduler internals
- [Allocator](allocator.md) — the allocator backing `debug::array`
- [Synchronization](synchronization.md) — the objects reported in dumps
