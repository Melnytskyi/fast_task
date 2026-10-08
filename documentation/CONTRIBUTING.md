# Documentation Style Guide

This guide describes the conventions used across the Fast Task documentation so
that new pages stay consistent and links keep working.

---

## File layout

- One topic per file, named in lowercase with hyphens (`getting-started.md`).
- Subsystem pages that belong to a group live in a subdirectory, for example
  [`task/coroutines.md`](task/coroutines.md).
- Every page starts with a single `# Title` heading.
- Every page ends with a `## Related Pages` section linking to adjacent topics.

---

## Linking

### Relative paths

All links are **relative to the file that contains them**.

- To link a sibling page: `[Tasks](tasks.md)`.
- To link a page in a subdirectory: `[Coroutines](task/coroutines.md)`.
- To link a source header from a page in `documentation/`:
  `[`task.hpp`](../include/fast_task/task/task.hpp:51)`.

> **Common mistake:** linking to `coroutines.md` when the file is actually at
> `task/coroutines.md`. Always double-check the directory.

### Line anchors

When linking to a symbol in a header, include a line anchor:

```markdown
[`task::run`](../include/fast_task/task/task.hpp:162)
```

Line anchors are a maintenance burden — they drift as the source changes. When
you edit a header, grep the documentation for the file name and update any
anchors that moved.

### Anchor links within a page

GitHub slugifies headings by lowercasing, removing punctuation, and replacing
spaces with hyphens. For example, `` ## `this_task` Namespace `` becomes
`#this_task-namespace`, and `` ### `this_task::transfer_to` `` becomes
`#this_tasktransfer_to` (the backticks and `::` are stripped).

---

## Code examples

- Use `cpp` for C++ code blocks, `bash` for shell, `cmake` for CMake, and
  `text` for plain diagrams.
- Keep examples minimal and compilable against the current API.
- Prefer the umbrella header `#include <fast_task.hpp>` in examples unless the
  point is to show a specific header.
- Use `fast_task::` qualification on first use; subsequent uses in the same
  snippet may omit it only if the snippet is self-contained.

---

## Terminology

Use these terms consistently:

| Term | Meaning |
|------|---------|
| **stackful task** | A [`fast_task::task`](tasks.md) with its own stack. |
| **stackless coroutine** | A [`task_coro`](task/coroutines.md). |
| **native thread** | A [`fast_task::native::thread`](native.md#nativethread) or an OS thread. |
| **scheduler-aware** | A primitive that yields cooperatively instead of blocking a worker. |
| **worker** | A scheduler thread that runs tasks. |
| **executor** | A worker pool, possibly bound to an ID. |

Avoid "green thread" in body text except when introducing the concept; prefer
"stackful task".

---

## Tables

Use tables for API surfaces (members, parameters, options). Keep the first
column a link to the symbol where possible:

```markdown
| Member | Description |
|--------|-------------|
| [`lock()`](../include/fast_task/task/mutex.hpp:37) | Acquires the lock. |
```

---

## Adding a new page

1. Create the file with a `# Title` and a short intro paragraph.
2. Add it to the contents table in [`README.md`](README.md).
3. Add it to the documentation table in the top-level
   [`README.md`](../README.md).
4. Add a `## Related Pages` section.
5. Verify every link resolves (relative path + anchor).

---

## Related Pages

- [Documentation Index](README.md) — the full contents table
- [Getting Started](getting-started.md) — build and integration
