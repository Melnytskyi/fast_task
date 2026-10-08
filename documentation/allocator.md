# Allocator

Fast Task exposes a small allocation API used internally for task objects and
shared with the runtime so that data crossing library boundaries uses the same
allocation path. It is a thin wrapper around `malloc`/`free`, wrapped in an
[`interrupt_unsafe_region`](../include/fast_task/interrupt.hpp:13) so that
allocation is not interrupted by the preemptive scheduler.

Header: [`fast_task/allocator.hpp`](../include/fast_task/allocator.hpp).

---

## Raw allocation

| Function | Description |
|----------|-------------|
| [`allocate(bytes)`](../include/fast_task/allocator.hpp:18) | Allocates `bytes`; returns `nullptr` on failure |
| [`free(p)`](../include/fast_task/allocator.hpp:19) | Releases memory obtained from `allocate` |

Both are simple wrappers over the C allocator, executed inside an
interrupt-unsafe region so a task cannot be preempted mid-allocation.

```cpp
void* p = fast_task::allocate(1024);
// ... use p ...
fast_task::free(p);
```

---

## `allocator<T>`

[`allocator<T>`](../include/fast_task/allocator.hpp:22) is a standard-conforming
allocator that routes through `fast_task::allocate` / `fast_task::free`. It is
stateless and always equal to any other instantiation, so it can be used with
standard containers.

```cpp
std::vector<int, fast_task::allocator<int>> values;
values.push_back(42);
```

| Member | Description |
|--------|-------------|
| [`allocate(n)`](../include/fast_task/allocator.hpp:36) | Allocates storage for `n` objects |
| [`deallocate(p, n)`](../include/fast_task/allocator.hpp:40) | Releases storage |

Equality operators are provided
([`operator==`](../include/fast_task/allocator.hpp:48),
[`operator!=`](../include/fast_task/allocator.hpp:53)) and always report all
instances as interchangeable.

---

## Placement `new` with the `at` tag

The [`at`](../include/fast_task/allocator.hpp:16) tag selects the fast_task
allocator for placement `new`/`delete`:

```cpp
auto* obj = new (fast_task::at) MyType(args...);
// ...
operator delete(obj, fast_task::at);
```

| Operator | Description |
|----------|-------------|
| [`operator new(size, at)`](../include/fast_task/allocator.hpp:57) | Allocates via the fast_task allocator |
| [`operator delete(p, at)`](../include/fast_task/allocator.hpp:58) | Frees via the fast_task allocator |
| [`operator new[](size, at)`](../include/fast_task/allocator.hpp:59) | Array form |
| [`operator delete[](p, at)`](../include/fast_task/allocator.hpp:60) | Array form |

---

## Related Pages

- [Debugging](debugging.md) — `debug::array` uses this allocator
- [Synchronization](synchronization.md) — interrupt-unsafe regions
- [Architecture](architecture.md) — internal task-object allocation
