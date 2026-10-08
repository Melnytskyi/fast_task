# Futures

Futures provide a value-oriented, composable interface to asynchronous work.
Unlike a raw [`task`](tasks.md), a future owns a result slot and lets you wait
for, chain, and aggregate results without managing task handles directly.

Header: [`fast_task/task/future.hpp`](../include/fast_task/task/future.hpp)
(included by [`fast_task.hpp`](../include/fast_task.hpp)).

---

## `future<T>`

[`future<T>`](../include/fast_task/task/future.hpp:21) is a reference-counted
handle to a value that will be produced by a task. It derives from
`std::enable_shared_from_this`, so it is always used through a
[`future_ptr<T>`](../include/fast_task/task/future.hpp:327)
(`std::shared_ptr<future<T>>`).

### Creating futures

| Factory | Description |
|---------|-------------|
| [`start(fn, bind_id)`](../include/fast_task/task/future.hpp:31) | Runs `fn` on the scheduler; returns a future for its result |
| [`start(queue, fn, bind_id)`](../include/fast_task/task/future.hpp:53) | Runs `fn` on a specific [`queue`](scheduler.md) |
| [`make_ready(value)`](../include/fast_task/task/future.hpp:80) | Returns an already-completed future |

`fn` must return exactly `T`. The optional `bind_id` pins the work to a
specific worker thread.

```cpp
future_ptr<int> f = future<int>::start([] {
    return 6 * 7;
});
```

### Retrieving the result

| Member | Description |
|--------|-------------|
| [`get()`](../include/fast_task/task/future.hpp:96) | Waits, then returns a copy of the result |
| [`take()`](../include/fast_task/task/future.hpp:106) | Waits, then moves the result out |
| [`wait()`](../include/fast_task/task/future.hpp:148) | Waits and rethrows any stored exception |
| [`wait_for()`](../include/fast_task/task/future.hpp:158) / [`wait_until()`](../include/fast_task/task/future.hpp:162) | Timed wait; returns `false` on timeout |
| [`wait_no_except()`](../include/fast_task/task/future.hpp:173) | Waits without rethrowing |
| [`wait_for_no_except()`](../include/fast_task/task/future.hpp:179) / [`wait_until_no_except()`](../include/fast_task/task/future.hpp:183) | Timed, non-throwing wait |

`get()` and `take()` rethrow the exception captured by the producing task, and
throw `std::runtime_error` if the task was canceled.

### State inspection

| Member | Description |
|--------|-------------|
| [`is_ready()`](../include/fast_task/task/future.hpp:144) | Whether the result is available |
| [`has_exception()`](../include/fast_task/task/future.hpp:190) | Whether the task failed |
| [`is_canceled()`](../include/fast_task/task/future.hpp:194) | Whether cancellation was requested |

### Callbacks

| Member | Description |
|--------|-------------|
| [`when_ready(fn)`](../include/fast_task/task/future.hpp:117) | Invokes `fn` when ready; overloads accept `fn(future&)` or `fn()` |
| [`callback(task)`](../include/fast_task/task/future.hpp:140) | Schedules a task to run on completion |
| [`cancel()`](../include/fast_task/task/future.hpp:198) | Requests cancellation of the producing task |

### Chaining

[`chain(fn)`](../include/fast_task/task/future.hpp:75) produces a new future
whose result is `fn(previous_result)`. The `&` overload passes the previous
result by reference (`get()`); the `&&` overload consumes it (`take()`).

```cpp
future_ptr<int> squared = future<int>::start([]{ return 7; })
    ->chain([](int v) { return v * v; });

int result = squared->get(); // 49
```

### Awaiting from a coroutine

When compiled as C++20, a `future<T>` can be `co_await`ed directly. The
implementation bridges the future into the coroutine via a temporary task, so
`co_await fut` yields the result value.

```cpp
task_coro<void> use_future() {
    future_ptr<int> f = future<int>::start([]{ return 42; });
    int value = co_await f;
}
```

### Stackful waiting

For stackful tasks, `enter_wait` and `enter_wait_until`
([`future.hpp:202`](../include/fast_task/task/future.hpp:202)) integrate with
[`enter_state`](../include/fast_task/task/enter_state.hpp:7) so a task can
suspend on a future without blocking its worker.

---

## `future<void>`

[`future<void>`](../include/fast_task/task/future.hpp:212) is the
specialization for operations with no result. It offers the same factories,
waiting, callback, and cancellation API, minus `get()`/`take()` value returns.
Use it for fire-and-forget work that still needs completion tracking.

```cpp
future_ptr<void> f = future<void>::start([]{ do_work(); });
f->wait();
```

---

## `future_tool`

The [`future_tool`](../include/fast_task/task/future.hpp:385) namespace provides
parallel algorithms over containers and collections of futures.

### Iteration

| Function | Description |
|----------|-------------|
| [`for_each(container, fn)`](../include/fast_task/task/future.hpp:408) | Runs `fn(item)` for each item in parallel |
| [`for_each(container, queue, fn)`](../include/fast_task/task/future.hpp:387) | Same, on a specific queue |
| [`for_each_move(container, fn)`](../include/fast_task/task/future.hpp:429) | Moves each item into `fn` |
| [`for_each_move(container, queue, fn)`](../include/fast_task/task/future.hpp:452) | Same, on a specific queue |
| [`for_each_wait(container, fn)`](../include/fast_task/task/future.hpp:494) | Blocking variant |
| [`for_each_wait(container, queue, fn)`](../include/fast_task/task/future.hpp:475) | Blocking variant on a queue |

If any item throws, the remaining futures are canceled and the exception
propagates.

### Mapping

| Function | Description |
|----------|-------------|
| [`process<Result>(container, fn)`](../include/fast_task/task/future.hpp:513) | Maps each item through `fn`, returning `std::vector<Result>` |
| [`process<Result>(container, queue, fn)`](../include/fast_task/task/future.hpp:536) | Same, on a specific queue |

### Aggregation

| Function | Description |
|----------|-------------|
| [`accumulate(futures)`](../include/fast_task/task/future.hpp:559) | Waits for all futures, returns `future_ptr<std::vector<Ret>>` |
| [`accumulate(queue, futures)`](../include/fast_task/task/future.hpp:574) | Same, on a specific queue |
| [`accumulate(std::move(futures))`](../include/fast_task/task/future.hpp:589) | Move overload |
| [`accumulate(queue, std::move(futures))`](../include/fast_task/task/future.hpp:604) | Move overload on a queue |
| [`wait_all(futures)`](../include/fast_task/task/future.hpp:661) | Waits for every future in the range |

```cpp
std::vector<int> input = {1, 2, 3, 4};
future_ptr<void> done = future_tool::for_each(input, [](int& v) {
    v *= 2;
});
done->wait();
```

---

## Related Pages

- [Tasks](tasks.md) — the underlying execution primitive
- [Coroutines](task/coroutines.md) — `co_await` on futures
- [Scheduler](scheduler.md) — queues and worker binding
- [Asynchronous I/O](io.md) — `fut_*` file operations
