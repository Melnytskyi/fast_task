# Futex

Fast Task's synchronization primitives are built on a custom **futex** layer
instead of the classic *spinlock + waiter list* design used by Boost.Fiber and
similar libraries. The result is a smaller, faster primitive: a mutex that is
just **one atomic variable** in the uncontended case, with no per-primitive
heap allocation and no per-primitive lock.

The key property of the Fast Task futex is that it is **dual-path**:

| Caller | Wait | Wake | Syscalls |
|--------|------|------|----------|
| Stackful task / stackless coroutine | Park on the scheduler | Resume in userspace | **None** |
| Native thread (outside the scheduler) | `SYS_futex` / `WaitOnAddress` | `SYS_futex` / `WakeByAddressSingle` | Yes |

In other words, **native futex syscalls are used only for native threads**.
Stackful and stackless tasks never enter the kernel to block or wake — they are
parked on the scheduler and resumed directly in userspace. This is what makes
Fast Task primitives faster than a Boost.Fiber mutex: a task-to-task handoff is
a context switch, not a syscall, and the primitive itself is a single atomic.

## Why one atomic instead of spinlock + list

A Boost.Fiber-style mutex typically looks like:

```text
struct mutex {
    spinlock lock;          // protects the state
    waiter_list waiters;    // heap-allocated nodes
    bool locked;
};
```

Every lock/unlock touches the spinlock, and every blocked waiter allocates a
list node. Fast Task instead keeps the *entire* state of a primitive in one
atomic word (for example a `mutex` is a single `std::atomic<uint32_t>` holding
the owner id / reader count). The slow path — when a task actually has to block
— is delegated to the shared futex layer, which parks the task on the scheduler
and records it in a global hash table. There is no per-primitive lock and no
per-primitive list.

This is also a lot faster because it **reduces cache-invalidation noise**. A
spinlock + list design makes every waiter touch the same lock word and the same
list head, so each lock/unlock invalidates those cache lines on every core that
has them. With a single atomic word, the uncontended fast path touches only that
one word, and the contended path spreads waiters across 4096 independent,
cache-line-padded buckets — so unrelated primitives stop bouncing the same cache
lines between cores.

## The task wait table

When a **task** blocks, it is recorded in a global, cache-line-aligned hash
table. The table is split into **4096 buckets**, each padded to a cache line so
unrelated addresses rarely contend. Each bucket holds a two-level list: a list of
**addresses**, and under each address a FIFO list of **waiters**. The address is
hashed with a bit-mixing function to spread addresses evenly across buckets.

A waiter node carries:

- links in the per-bucket address list,
- links in the per-address FIFO,
- the address being waited on,
- the kind of wait (`wait`, `unlock_and_wait`, or `enter_wait_and_lock`),
- the task to resume (null for a native thread),
- a 6-bit key (see below).

The bucket lock is held only for the short bookkeeping window; it is released
before the task is parked.

## The dual-path wait/wake

The two paths meet in the wait primitive:

```cpp
void wait_on_address(void* address, bool (*check_callback)(void*), node_data data) {
    bucket_t& bucket = glob.futex_global.get_bucket(address);
    std::unique_lock guard(bucket.lock);

    if (check_callback(address))   // lost-wakeup guard
        return;

    wait_node_t me;
    /* ... fill me, link into bucket ... */
    make_wait(bucket, &me);

    auto& loc = get_loc();
    if (loc.is_task_thread && loc.curr_task) {
        me.waiter = loc.curr_task;
        swapCtxUnlock(*guard.release());   // TASK: park, no syscall
    } else {
        guard.unlock();
        uint32_t expected = 0;
        while (me.native_wake.load(std::memory_order_acquire) == 0)
            native_futex_wait(&me.native_wake, expected);  // NATIVE: syscall
    }
}
```

and symmetrically in the wake primitive:

```cpp
void wake_item(wait_node_t* item) {
    if (item->waiter) {
        /* ... */
        transfer_task(std::move(item->waiter), reinterpret_cast<enter_state*>(item)); // TASK
    } else {
        auto* wake_addr = &item->native_wake;
        wake_addr->store(1, std::memory_order_release);
        native_futex_wake(wake_addr, 1);   // NATIVE: syscall
    }
}
```

So:

- **Task waiters** are parked with a context switch that releases the bucket
  lock and resumed with a userspace task transfer — no kernel involvement.
- **Native waiters** spin on the wake word and block in the kernel only when the
  spin fails.

The `check_callback` is evaluated while holding the bucket lock, before parking,
so a wake that races with the wait cannot be lost.

## Timed waits

The timed wait adds a deadline:

- **Task path**: the task is parked with a pending timer. If the scheduler wakes
  it because the deadline expired, the task removes itself from the bucket and
  reports a timeout. A generation counter guards against a stale wake that
  arrives after the timeout.
- **Native path**: loops on the timed native wait; on timeout it removes itself
  from the bucket (or, if a wake raced in, drains the wake word) and reports a
  timeout.

## `unlock_and_wait`

`unlock_and_wait` atomically releases one lock and parks on another address. It
is the primitive behind condition variables: the caller unlocks the mutex and
waits on the condition's address in one step, so no wakeup can slip between the
unlock and the wait. It locks the two buckets in address order, avoiding
deadlock.

## Requeue and select

- `wake_and_requeue_on_address` wakes some waiters and moves the rest to a
  different address — used to hand off a lock without a thundering herd.
- `wake_and_requeue_on_address_select` wakes only waiters matching a predicate.
  This is how `rw_mutex`, `semaphore`, and `limiter` pick the right waiter (for
  example, a reader vs. a writer).

## Keys (`node_data`)

A `node_data` is a 6-bit key attached to a waiter. Multiple waiters can share one
address but be distinguished by key. `rw_mutex` uses this to keep readers and
writers on the same address while waking only the appropriate class.

## Introspection

The futex layer exposes read-only helpers used by the debug API:

- `has_waiters` — is anyone waiting on this address?
- `iterate_waiters` — enumerate waiters, yielding `waiter_info` (`task_id`,
  `key`, `is_native`).

## How primitives use the futex

| Primitive | Address | Notes |
|-----------|---------|-------|
| `mutex` | the mutex's atomic word | one atomic; slow path parks on the futex |
| `recursive_mutex` | the mutex's atomic word | owner id + recursion count in one word |
| `rw_mutex` | the mutex's atomic word | reader/writer classes separated by `node_data` keys |
| `condition_variable` | the condition's atomic word | `unlock_and_wait` releases the mutex and parks atomically |
| `semaphore` | the counter's atomic word | select-based wake releases the right count |
| `limiter` | the counter's atomic word | same select-based wake |
| `queue` | the queue's atomic word | producers/consumers park and are woken in userspace |

Because the task path never enters the kernel, a contended mutex handoff between
two tasks is a scheduler context switch — cheaper than a Boost.Fiber mutex, which
must take a spinlock and walk a heap-allocated waiter list.

## Related Pages

- [Synchronization](synchronization.md) — the user-facing primitives built on the futex.
- [Architecture](architecture.md) — the scheduler that parks and resumes task waiters.
- [Native Primitives](native.md) — the native-thread side of the dual path.
- [Debugging](debugging.md) — waiter introspection.
