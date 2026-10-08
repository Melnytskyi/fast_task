# Synchronization

Fast Task's synchronization primitives are **scheduler-aware**: when a task waits
on them, it yields cooperatively instead of blocking the underlying worker thread.
The same primitives can be used by stackful tasks, stackless coroutines, and native
threads, so you can mix execution models freely.

All of them are built on a shared [futex](futex.md) layer that keeps each
primitive's state mostly in a single atomic variable and parks task waiters on the
scheduler without any syscall.

All primitives are declared in
[`fast_task/task/mutex.hpp`](../include/fast_task/task/mutex.hpp:1),
[`condition_variable.hpp`](../include/fast_task/task/condition_variable.hpp:1),
[`semaphore.hpp`](../include/fast_task/task/semaphore.hpp:1), and
[`mutex_unify.hpp`](../include/fast_task/task/mutex_unify.hpp:1).

## Lock Guards

Fast Task provides its own lock guards in
[`fast_task/shared/primitives.hpp`](../include/fast_task/shared/primitives.hpp:1):

| Guard | Description |
|-------|-------------|
| [`lock_guard<Mutex>`](../include/fast_task/shared/primitives.hpp:18) | Locks on construction, unlocks on destruction. |
| [`unique_lock<Mutex>`](../include/fast_task/shared/primitives.hpp:48) | Movable, supports deferred locking and manual `lock`/`unlock`. |
| [`shared_lock<Mutex>`](../include/fast_task/shared/primitives.hpp:126) | Shared (reader) ownership for `rw_mutex`. |
| [`relock_guard<Mutex>`](../include/fast_task/shared/primitives.hpp:204) | Unlocks on construction, relocks on destruction. |

Tag types [`adopt_lock`](../include/fast_task/shared/primitives.hpp:13),
[`defer_lock`](../include/fast_task/shared/primitives.hpp:14), and
[`defer_unlock`](../include/fast_task/shared/primitives.hpp:15) are provided.

## `mutex`

[`mutex`](../include/fast_task/task/mutex.hpp:21) is a scheduler-aware mutual
exclusion lock. `timed_mutex` is an alias for `mutex`.

| Method | Description |
|--------|-------------|
| [`lock()`](../include/fast_task/task/mutex.hpp:37) | Acquires the lock, yielding if necessary. |
| [`try_lock()`](../include/fast_task/task/mutex.hpp:38) | Non-blocking acquisition attempt. |
| [`try_lock_until(tp)`](../include/fast_task/task/mutex.hpp:39) | Acquires with a deadline. |
| [`try_lock_for(dur)`](../include/fast_task/task/mutex.hpp:50) | Acquires with a timeout. |
| [`unlock()`](../include/fast_task/task/mutex.hpp:40) | Releases the lock. |
| [`is_locked()`](../include/fast_task/task/mutex.hpp:41) | Returns whether the lock is held. |
| [`is_own()`](../include/fast_task/task/mutex.hpp:43) | Returns whether the current task owns the lock. |
| [`lifecycle_lock(task&&)`](../include/fast_task/task/mutex.hpp:42) | Transfers lock ownership to a task. |

### Async locking (C++20)

```cpp
co_await mutex.async_lock();
co_await mutex.async_try_lock_for(std::chrono::milliseconds(100));
```

| Awaiter | Description |
|---------|-------------|
| [`async_lock()`](../include/fast_task/task/mutex.hpp:55) | Awaits lock acquisition. |
| [`async_try_lock_until(tp)`](../include/fast_task/task/mutex.hpp:59) | Awaits acquisition with a deadline. |
| [`async_try_lock_for(dur)`](../include/fast_task/task/mutex.hpp:64) | Awaits acquisition with a timeout. |

## `recursive_mutex`

[`recursive_mutex`](../include/fast_task/task/mutex.hpp:72) allows the same task to
acquire the lock multiple times. It exposes the same interface as `mutex`
(`lock`, `try_lock`, `try_lock_until`, `try_lock_for`, `unlock`, `is_locked`,
`is_own`, `lifecycle_lock`, and the async awaiters).

## `rw_mutex`

[`rw_mutex`](../include/fast_task/task/mutex.hpp:115) is a reader-writer lock. It
also provides the standard-library-compatible aliases `lock`/`unlock` (write),
`lock_shared`/`unlock_shared` (read), and `try_lock`/`try_lock_shared`.

### Writer operations

| Method | Description |
|--------|-------------|
| [`write_lock()`](../include/fast_task/task/mutex.hpp:164) | Acquires the write lock. |
| [`try_write_lock()`](../include/fast_task/task/mutex.hpp:165) | Non-blocking write attempt. |
| [`try_write_lock_until(tp)`](../include/fast_task/task/mutex.hpp:166) | Write lock with a deadline. |
| [`try_write_lock_for(dur)`](../include/fast_task/task/mutex.hpp:210) | Write lock with a timeout. |
| [`write_unlock()`](../include/fast_task/task/mutex.hpp:167) | Releases the write lock. |
| [`is_write_locked()`](../include/fast_task/task/mutex.hpp:168) | Returns whether the write lock is held. |

### Reader operations

| Method | Description |
|--------|-------------|
| [`read_lock()`](../include/fast_task/task/mutex.hpp:157) | Acquires the read lock. |
| [`try_read_lock()`](../include/fast_task/task/mutex.hpp:158) | Non-blocking read attempt. |
| [`try_read_lock_until(tp)`](../include/fast_task/task/mutex.hpp:159) | Read lock with a deadline. |
| [`try_read_lock_for(dur)`](../include/fast_task/task/mutex.hpp:205) | Read lock with a timeout. |
| [`read_unlock()`](../include/fast_task/task/mutex.hpp:160) | Releases the read lock. |
| [`is_read_locked()`](../include/fast_task/task/mutex.hpp:161) | Returns whether the read lock is held. |

### Async awaiters

`async_read_lock`, `async_write_lock`, `async_try_read_lock_until`,
`async_try_write_lock_until`, and their `_for` variants are available under C++20.

### RAII helpers

[`read_lock`](../include/fast_task/task/mutex.hpp:329) and
[`write_lock`](../include/fast_task/task/mutex.hpp:343) are RAII wrappers that
acquire the corresponding lock on construction and release it on destruction.

### `protected_value<T>`

[`protected_value<T, mutex_t>`](../include/fast_task/task/mutex.hpp:359) wraps a
value with an internal `rw_mutex` (configurable via `mutex_t`). Access is mediated
by accessor callbacks:

```cpp
fast_task::protected_value<int> value{0};

value.set([](int& v) { v = 42; });
int read = value.get([](const int& v) { return v; });
```

> `protected_value` is intended for stackful or native tasks only.

## `condition_variable`

[`condition_variable`](../include/fast_task/task/condition_variable.hpp:19) supports
both Fast Task locks and standard-library locks.

| Method | Description |
|--------|-------------|
| [`wait(unique_lock<mutex>&)`](../include/fast_task/task/condition_variable.hpp:26) | Waits, releasing and reacquiring the lock. |
| [`wait_until(lock, tp)`](../include/fast_task/task/condition_variable.hpp:27) | Waits with a deadline; returns `false` on timeout. |
| [`wait_for(lock, dur)`](../include/fast_task/task/condition_variable.hpp:41) | Waits with a timeout. |
| [`notify_one()`](../include/fast_task/task/condition_variable.hpp:30) | Wakes one waiter. |
| [`notify_all()`](../include/fast_task/task/condition_variable.hpp:31) | Wakes all waiters. |
| [`has_waiters()`](../include/fast_task/task/condition_variable.hpp:32) | Returns whether any task is waiting. |
| [`callback(lock, task)`](../include/fast_task/task/condition_variable.hpp:34) | Registers a task to run on notification. |

Overloads accepting `std::unique_lock<mutex>` are also provided. Async awaiters
(`async_wait`, `async_wait_until`, `async_wait_for`) are available under C++20.

### `condition_variable_any`

[`condition_variable_any`](../include/fast_task/task/condition_variable.hpp:173)
works with any lock type via an internal mutex and a relock guard. It provides
`wait`, `wait_for`, `wait_until`, `notify_one`, `notify_all`, and `has_waiters`.

## `semaphore`

[`semaphore`](../include/fast_task/task/semaphore.hpp:22) is a counting semaphore.

| Method | Description |
|--------|-------------|
| [`lock()`](../include/fast_task/task/semaphore.hpp:35) | Acquires a permit. |
| [`try_lock()`](../include/fast_task/task/semaphore.hpp:36) | Non-blocking acquisition. |
| [`try_lock_until(tp)`](../include/fast_task/task/semaphore.hpp:37) | Acquisition with a deadline. |
| [`try_lock_for(dur)`](../include/fast_task/task/semaphore.hpp:46) | Acquisition with a timeout. |
| [`release()`](../include/fast_task/task/semaphore.hpp:38) | Releases one permit. |
| [`release_all()`](../include/fast_task/task/semaphore.hpp:39) | Releases all permits. |
| [`set_max_threshold(n)`](../include/fast_task/task/semaphore.hpp:34) | Sets the maximum permit count. |
| [`is_locked()`](../include/fast_task/task/semaphore.hpp:40) | Returns whether permits are exhausted. |

## `limiter`

[`limiter`](../include/fast_task/task/semaphore.hpp:67) behaves like a semaphore but
performs deadlock checks on lock acquisition. It provides `lock`, `try_lock`,
`try_lock_until`, `try_lock_for`, `unlock`, `is_locked`, and `set_max_threshold`,
plus async awaiters under C++20.

## `mutex_unify`

[`mutex_unify`](../include/fast_task/task/mutex_unify.hpp:27) is a type-erased lock
handle that can hold a reference to any supported lock type. It is used by
[`deadline_timer`](scheduler.md#deadline_timer) and allows generic code to operate
on different lock kinds.

Supported lock types include `std::mutex`, `std::timed_mutex`,
`std::recursive_mutex`, [`fast_task::native::mutex`](native.md#nativemutex),
[`fast_task::native::timed_mutex`](native.md#nativetimed_mutex),
[`fast_task::native::rw_mutex`](native.md#nativerw_mutex),
[`fast_task::native::recursive_mutex`](native.md#nativerecursive_mutex),
[`fast_task::native::spin_lock`](native.md#nativespin_lock),
[`mutex`](#mutex), [`rw_mutex`](#rw_mutex), [`recursive_mutex`](#recursive_mutex),
[`multiply_mutex`](#multiply_mutex), [`semaphore`](#semaphore), and
[`limiter`](#limiter).

Key members:

| Member | Description |
|--------|-------------|
| [`get_type()`](../include/fast_task/task/mutex_unify.hpp:95) | Returns the held lock type. |
| [`get_mutex()`](../include/fast_task/task/mutex_unify.hpp:99) | Returns a raw pointer to the held lock. |
| [`lock()`](../include/fast_task/task/mutex_unify.hpp:135) / [`unlock()`](../include/fast_task/task/mutex_unify.hpp:138) | Lock/unlock the held lock. |
| [`try_lock()`](../include/fast_task/task/mutex_unify.hpp:136) / [`try_lock_until(tp)`](../include/fast_task/task/mutex_unify.hpp:137) | Non-blocking / timed acquisition. |
| [`relock_start()`](../include/fast_task/task/mutex_unify.hpp:140) / [`relock_end()`](../include/fast_task/task/mutex_unify.hpp:141) | Save/restore recursive lock state. |

For unsupported locks such as `std::mutex`, `enter_wait` locks the mutex directly
and returns `true`.

## `multiply_mutex`

[`multiply_mutex`](../include/fast_task/task/mutex_unify.hpp:169) locks several
`mutex_unify` handles atomically:

```cpp
fast_task::multiply_mutex mm{mutex_a, mutex_b};
mm.lock();
// ...
mm.unlock();
```

It provides `lock`, `try_lock`, `try_lock_until`, `try_lock_for`, `unlock`, and
async awaiters under C++20.

## Interrupt-Unsafe Regions

[`interrupt_unsafe_region`](../include/fast_task/interrupt.hpp:14) disables
preemption for a scope. Use it around operations that rely on hidden OS locks —
`malloc`, `new`, `std::cout`, `std::mutex`, and similar — when the preemptive
scheduler is enabled.

```cpp
{
    fast_task::interrupt_unsafe_region region;
    // preemption is disabled here
}
```

Static methods [`lock()`](../include/fast_task/interrupt.hpp:17),
[`unlock()`](../include/fast_task/interrupt.hpp:18), and
[`lock_swap(state)`](../include/fast_task/interrupt.hpp:19) allow manual control.

See [Architecture](architecture.md#scheduler-aware-synchronization--preemption-limits)
for why this is necessary.

## Related Pages

- [Architecture](architecture.md#scheduler-aware-synchronization--preemption-limits) —
  preemption and lock awareness.
- [Coroutines](task/coroutines.md) — async lock awaiters.
- [Native Primitives](native.md) — OS-level locks.
