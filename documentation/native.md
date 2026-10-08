# Native Primitives

The `fast_task::native` namespace provides OS-level threading and
synchronization primitives. They are the building blocks the scheduler uses
internally, and they are exposed publicly for code that must interact with real
threads — for example, bridging a native thread into the runtime or protecting
data shared between native threads and tasks.

Header: [`fast_task/native.hpp`](../include/fast_task/native.hpp), which
aggregates:

- [`native/thread.hpp`](../include/fast_task/native/thread.hpp)
- [`native/mutex.hpp`](../include/fast_task/native/mutex.hpp)
- [`native/condition_variable.hpp`](../include/fast_task/native/condition_variable.hpp)
- [`native/spin_lock.hpp`](../include/fast_task/native/spin_lock.hpp)

> These are **blocking** primitives. Inside a task, prefer the
> [scheduler-aware primitives](synchronization.md), which yield cooperatively
> instead of blocking a worker thread.

---

## `native::thread`

[`thread`](../include/fast_task/native/thread.hpp:18) is a native OS thread with
extra control over stack allocation and suspension.

### Construction

| Constructor | Description |
|-------------|-------------|
| [`thread(f, args...)`](../include/fast_task/native/thread.hpp:85) | Starts a thread with a default stack |
| [`thread(stack_size(n), f, args...)`](../include/fast_task/native/thread.hpp:75) | Starts a thread with an explicit stack size |
| [`thread(reserved_stack_size(n), f, args...)`](../include/fast_task/native/thread.hpp:80) | Starts a thread with a reserved stack |

The [`stack_size`](../include/fast_task/native/thread.hpp:60) and
[`reserved_stack_size`](../include/fast_task/native/thread.hpp:67) tag types
select the allocation strategy.

### Lifetime and identity

| Member | Description |
|--------|-------------|
| [`join()`](../include/fast_task/native/thread.hpp:123) | Waits for the thread to finish |
| [`detach()`](../include/fast_task/native/thread.hpp:124) | Detaches the thread |
| [`joinable()`](../include/fast_task/native/thread.hpp:125) | Whether the thread can be joined |
| [`get_id()`](../include/fast_task/native/thread.hpp:115) | Returns the [`thread::id`](../include/fast_task/native/thread.hpp:142) |
| [`native_handle()`](../include/fast_task/native/thread.hpp:117) | Returns the OS handle |
| [`hardware_concurrency()`](../include/fast_task/native/thread.hpp:121) | Number of hardware threads |

### Suspension and context injection

Unlike `std::thread`, a `native::thread` can be suspended and resumed, and code
can be injected to run on it:

| Member | Description |
|--------|-------------|
| [`suspend()`](../include/fast_task/native/thread.hpp:127) / [`resume()`](../include/fast_task/native/thread.hpp:128) | Suspend or resume this thread |
| [`suspend(id)`](../include/fast_task/native/thread.hpp:130) / [`resume(id)`](../include/fast_task/native/thread.hpp:131) | Static forms by ID |
| [`insert_context(fn, arg)`](../include/fast_task/native/thread.hpp:129) | Runs `fn(arg)` on the thread |
| [`insert_context(id, fn, arg)`](../include/fast_task/native/thread.hpp:132) | Static form by ID |

### `this_thread`

| Function | Description |
|----------|-------------|
| [`this_thread::get_id()`](../include/fast_task/native/thread.hpp:136) | ID of the calling thread |
| [`this_thread::yield()`](../include/fast_task/native/thread.hpp:137) | Yields the CPU |
| [`this_thread::sleep_for(ms)`](../include/fast_task/native/thread.hpp:138) | Sleeps for a duration |
| [`this_thread::sleep_until(tp)`](../include/fast_task/native/thread.hpp:139) | Sleeps until a time point |

[`thread::id`](../include/fast_task/native/thread.hpp:142) is comparable,
convertible to `size_t`, and hashable via
[`std::hash`](../include/fast_task/native/thread.hpp:170).

---

## `native::mutex`

[`mutex`](../include/fast_task/native/mutex.hpp:19) is a non-recursive,
non-copyable, non-movable mutual-exclusion lock.

| Member | Description |
|--------|-------------|
| [`lock()`](../include/fast_task/native/mutex.hpp:33) | Acquires the lock |
| [`unlock()`](../include/fast_task/native/mutex.hpp:34) | Releases the lock |
| [`try_lock()`](../include/fast_task/native/mutex.hpp:35) | Attempts to acquire without blocking |

---

## `native::rw_mutex`

[`rw_mutex`](../include/fast_task/native/mutex.hpp:38) is a reader/writer lock.

| Member | Description |
|--------|-------------|
| [`lock()`](../include/fast_task/native/mutex.hpp:53) / [`unlock()`](../include/fast_task/native/mutex.hpp:54) | Exclusive (writer) lock |
| [`try_lock()`](../include/fast_task/native/mutex.hpp:55) | Non-blocking writer lock |
| [`lock_shared()`](../include/fast_task/native/mutex.hpp:57) / [`unlock_shared()`](../include/fast_task/native/mutex.hpp:58) | Shared (reader) lock |
| [`try_lock_shared()`](../include/fast_task/native/mutex.hpp:59) | Non-blocking reader lock |

---

## `native::recursive_mutex`

[`recursive_mutex`](../include/fast_task/native/mutex.hpp:62) may be locked
multiple times by the same thread. It also supports saving and restoring the
full lock state, which is used by condition variables:

| Member | Description |
|--------|-------------|
| [`lock()`](../include/fast_task/native/mutex.hpp:78) / [`unlock()`](../include/fast_task/native/mutex.hpp:79) / [`try_lock()`](../include/fast_task/native/mutex.hpp:80) | Standard lock operations |
| [`relock_begin()`](../include/fast_task/native/mutex.hpp:82) | Captures the current recursion state |
| [`relock_end(state)`](../include/fast_task/native/mutex.hpp:83) | Restores a captured state |

---

## `native::timed_mutex`

[`timed_mutex`](../include/fast_task/native/mutex.hpp:86) adds timed acquisition:

| Member | Description |
|--------|-------------|
| [`lock()`](../include/fast_task/native/mutex.hpp:102) / [`unlock()`](../include/fast_task/native/mutex.hpp:103) / [`try_lock()`](../include/fast_task/native/mutex.hpp:104) | Standard lock operations |
| [`try_lock_for(ms)`](../include/fast_task/native/mutex.hpp:105) | Tries to lock for a duration |
| [`try_lock_until(tp)`](../include/fast_task/native/mutex.hpp:106) | Tries to lock until a time point |

---

## `native::spin_lock`

[`spin_lock`](../include/fast_task/native/spin_lock.hpp:15) is a lightweight
atomic spin lock built on `std::atomic_flag`. It is non-copyable and
non-movable.

| Member | Description |
|--------|-------------|
| [`lock()`](../include/fast_task/native/spin_lock.hpp:34) | Spins until acquired |
| [`try_lock()`](../include/fast_task/native/spin_lock.hpp:35) | Attempts to acquire once |
| [`unlock()`](../include/fast_task/native/spin_lock.hpp:36) | Releases the lock |

---

## `native::condition_variable`

[`condition_variable`](../include/fast_task/native/condition_variable.hpp:65)
works with `mutex` and `recursive_mutex`.

| Member | Description |
|--------|-------------|
| [`notify_one()`](../include/fast_task/native/condition_variable.hpp:78) | Wakes one waiter |
| [`notify_all()`](../include/fast_task/native/condition_variable.hpp:79) | Wakes all waiters |
| [`wait(mtx)`](../include/fast_task/native/condition_variable.hpp:80) | Waits, releasing `mtx` |
| [`wait_for(mtx, ms)`](../include/fast_task/native/condition_variable.hpp:81) | Timed wait |
| [`wait_until(mtx, tp)`](../include/fast_task/native/condition_variable.hpp:82) | Waits until a time point |

Overloads accept `mutex`, `recursive_mutex`, and the corresponding
[`unique_lock`](../include/fast_task/shared/primitives.hpp:48) wrappers.

[`condition_variable_any`](../include/fast_task/native/condition_variable.hpp:113)
works with any lockable type. It internally uses a `mutex` plus a
[`full_state_relock_guard`](../include/fast_task/native/condition_variable.hpp:17)
to release and restore the caller's lock — including the full recursion state of
a `recursive_mutex`.

| Member | Description |
|--------|-------------|
| [`notify_one()`](../include/fast_task/native/condition_variable.hpp:119) / [`notify_all()`](../include/fast_task/native/condition_variable.hpp:120) | Wake waiters |
| [`wait(mtx)`](../include/fast_task/native/condition_variable.hpp:123) | Waits on any lockable |
| [`wait_for(mtx, ms)`](../include/fast_task/native/condition_variable.hpp:131) | Timed wait |
| [`wait_until(mtx, tp)`](../include/fast_task/native/condition_variable.hpp:136) | Waits until a time point |

---

## Related Pages

- [Synchronization](synchronization.md) — scheduler-aware equivalents
- [Architecture](architecture.md) — how native threads back the scheduler
- [Tasks](tasks.md) — running work on the scheduler instead of native threads
