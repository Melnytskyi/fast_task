# Asynchronous I/O

Fast Task provides fully asynchronous file and network I/O. All operations are
driven by the platform's native completion mechanism — `io_uring` on Linux and
IOCP on Windows — so a task that performs I/O cooperatively yields its worker
thread instead of blocking it.

Two headers expose the API:

| Header | Namespace | Contents |
|--------|-----------|----------|
| [`fast_task/file.hpp`](../include/fast_task/file.hpp) | `fast_task::file` | Files, streams, I/O awaiters |
| [`fast_task/net.hpp`](../include/fast_task/net.hpp) | `fast_task::net` | Addresses, TCP, UDP |

Both are included by the umbrella header [`fast_task.hpp`](../include/fast_task.hpp).

---

## I/O Awaiters

Every asynchronous operation returns an *awaiter* that must be awaited or
explicitly canceled. There are four families, differing in two axes:

- **`io_handle` vs `safe_io_handle`** — the `safe_` variants return
  [`polyfill::expected`](../include/fast_task/polyfill/expected.hpp) instead of
  throwing on error.
- **plain vs `_until`** — the `_until` variants accept a deadline and can time
  out.

| Type | Result on success | Result on error |
|------|-------------------|-----------------|
| [`detail::io_handle<T>`](../include/fast_task/file.hpp:162) | `T` | throws |
| [`detail::io_handle_until<T>`](../include/fast_task/file.hpp:282) | `std::optional<T>` | throws / `nullopt` on timeout |
| [`detail::safe_io_handle<T>`](../include/fast_task/file.hpp:410) | `polyfill::expected<T, io_errors>` | error in expected |
| [`detail::safe_io_handle_until<T>`](../include/fast_task/file.hpp:534) | `std::optional<T>` | error in expected |

All four are `[[nodiscard]]` — an un-awaited handle is a compile-time warning
because the underlying operation would leak.

### Cancellation

Each awaiter exposes a `cancel()` member returning a `cancel_awaiter`. Awaiting
it aborts the pending operation:

```cpp
auto op = file.async_read(1024);
// ... later, from another task:
co_await op.cancel();
```

---

## Files

### Enumerations

| Type | Values |
|------|--------|
| [`open_mode`](../include/fast_task/file.hpp:26) | `read`, `write`, `read_write`, `append` |
| [`on_open_action`](../include/fast_task/file.hpp:74) | `open`, `always_new`, `create_new`, `open_exists`, `truncate_exists` |
| [`pointer`](../include/fast_task/file.hpp:60) | `read`, `write` |
| [`pointer_offset`](../include/fast_task/file.hpp:64) | `begin`, `current`, `end` |
| [`pointer_mode`](../include/fast_task/file.hpp:69) | `separated`, `combined` |
| [`io_errors`](../include/fast_task/file.hpp:93) | `no_error`, `eof`, `no_enough_memory`, `invalid_user_buffer`, `no_enough_quota`, `unknown_error`, `operation_canceled` |

[`share_mode`](../include/fast_task/file.hpp:33) (Windows-only) controls
concurrent read/write/delete access. [`file_flags`](../include/fast_task/file.hpp:82)
carries cache-manager hints such as `random_access`, `sequential_scan`,
`no_buffering`, `write_through`, `delete_on_close`, `posix_semantics`,
`at_end`, and `use_lock`.

### `file_handle`

[`file_handle`](../include/fast_task/file.hpp:662) is a move-only RAII wrapper
around an OS file object.

```cpp
using namespace fast_task::file;

file_handle f = file_handle::open_throws(
    "data.bin",
    open_mode::read_write,
    on_open_action::open_exists
);
```

#### Opening and lifetime

| Member | Description |
|--------|-------------|
| [`open()`](../include/fast_task/file.hpp:666) | Opens a file; returns an invalid handle on failure |
| [`open_throws()`](../include/fast_task/file.hpp:667) | Opens a file; throws on failure |
| [`is_open()`](../include/fast_task/file.hpp:676) | Whether the handle refers to an open file |
| [`close()`](../include/fast_task/file.hpp:677) | Closes the file |
| [`get_path()`](../include/fast_task/file.hpp:724) | Resolves the full path from the handle |
| [`internal_get_handle()`](../include/fast_task/file.hpp:721) | Native handle (`int` on POSIX, `void*` on Windows) |

#### Synchronous operations

These block the calling thread, or suspend a stackful task. They can also be used without the scheduler running.

| Member | Description |
|--------|-------------|
| [`read()`](../include/fast_task/file.hpp:679) / [`read_at()`](../include/fast_task/file.hpp:680) | Read into a buffer, optionally at an offset |
| [`read_fixed()`](../include/fast_task/file.hpp:681) / [`read_fixed_at()`](../include/fast_task/file.hpp:682) | Read exactly `size` bytes |
| [`write()`](../include/fast_task/file.hpp:684) / [`write_at()`](../include/fast_task/file.hpp:685) | Write a buffer, optionally at an offset |
| [`append()`](../include/fast_task/file.hpp:686) | Append to the end of the file |
| [`seek_pos()`](../include/fast_task/file.hpp:689) | Move the read or write pointer |
| [`tell_pos()`](../include/fast_task/file.hpp:691) | Query the current pointer |
| [`flush()`](../include/fast_task/file.hpp:693) | Flush buffered writes |
| [`size()`](../include/fast_task/file.hpp:695) | File size in bytes |

#### Future-based operations

The `fut_*` family returns a [`future_ptr`](futures.md) that can be awaited or
combined with other futures:

```cpp
future_ptr<std::vector<uint8_t>> header = f.fut_read(64);
future_ptr<void> body = f.fut_write(payload, payload_size);
```

| Member | Returns |
|--------|---------|
| [`fut_read()`](../include/fast_task/file.hpp:697) / [`fut_read_at()`](../include/fast_task/file.hpp:698) | `future_ptr<std::vector<uint8_t>>` |
| [`fut_read_fixed()`](../include/fast_task/file.hpp:699) / [`fut_read_fixed_at()`](../include/fast_task/file.hpp:700) | `future_ptr<std::vector<uint8_t>>` |
| [`fut_write()`](../include/fast_task/file.hpp:701) / [`fut_write_at()`](../include/fast_task/file.hpp:702) | `future_ptr<void>` |
| [`fut_append()`](../include/fast_task/file.hpp:703) | `future_ptr<void>` |

#### Low-level operations

The `make_*` family returns an [`io_operation<T>`](../include/fast_task/file.hpp:104)
that can be awaited from a stackful task via `enter_wait` /
`enter_wait_until`, or canceled via `enter_cancel`:

| Member | Returns |
|--------|---------|
| [`make_read()`](../include/fast_task/file.hpp:706) / [`make_read_at()`](../include/fast_task/file.hpp:707) | `io_operation<std::vector<uint8_t>>` |
| [`make_read_fixed()`](../include/fast_task/file.hpp:708) / [`make_read_fixed_at()`](../include/fast_task/file.hpp:709) | `io_operation<std::vector<uint8_t>>` |
| [`make_write()`](../include/fast_task/file.hpp:711) / [`make_write_at()`](../include/fast_task/file.hpp:712) | `io_operation<void>` |
| [`make_append()`](../include/fast_task/file.hpp:713) | `io_operation<void>` |

#### Coroutine operations

The `async_*` family returns an awaiter usable with `co_await`:

```cpp
task_coro<void> copy(file_handle& src, file_handle& dst) {
    std::vector<uint8_t> chunk = co_await src.async_read(4096);
    co_await dst.async_append(chunk.data(), (uint32_t)chunk.size());
}
```

| Member | Awaiter |
|--------|---------|
| [`async_read()`](../include/fast_task/file.hpp:726), [`async_read_at()`](../include/fast_task/file.hpp:730), [`async_read_fixed()`](../include/fast_task/file.hpp:734), [`async_read_fixed_at()`](../include/fast_task/file.hpp:738) | `io_handle<std::vector<uint8_t>>` |
| [`async_write()`](../include/fast_task/file.hpp:742), [`async_write_at()`](../include/fast_task/file.hpp:746), [`async_append()`](../include/fast_task/file.hpp:750) | `io_handle<void>` |
| [`async_*_until()`](../include/fast_task/file.hpp:754) | `io_handle_until<...>` with a deadline |
| [`async_*_for()`](../include/fast_task/file.hpp:782) | `io_handle_until<...>` with a duration |

The `safe_async_*` variants ([`safe_async_read()`](../include/fast_task/file.hpp:817)
and friends) return `safe_io_handle` / `safe_io_handle_until` instead, so errors
surface as `polyfill::expected` values rather than exceptions.

### Streams

Two `std::iostream` adapters let existing stream code run asynchronously:

- [`async_iofstream`](../include/fast_task/file.hpp:1112) — a full input/output
  stream backed by an [`async_filebuf`](../include/fast_task/file.hpp:991). It can
  be constructed from a path plus open mode, or from an existing `file_handle`.
- [`atomic_async_ofstream`](../include/fast_task/file.hpp:1185) — an output
  stream that writes to a temporary file and atomically renames it into place on
  destruction, guaranteeing readers never observe a partially written file.

```cpp
async_iofstream in("input.txt", std::ios::in);
async_iofstream out("output.txt", std::ios::out);

std::string line;
while (std::getline(in, line))
    out << line << '\n';
```

---

## Networking

### Initialization

The network stack must be initialized before use and torn down afterwards:

```cpp
fast_task::net::init_networking();
// ... use sockets ...
fast_task::net::deinit_networking();
```

| Function | Description |
|----------|-------------|
| [`init_networking()`](../include/fast_task/net.hpp) | Initializes the platform network stack |
| [`deinit_networking()`](../include/fast_task/net.hpp) | Releases network resources |
| [`ipv6_supported()`](../include/fast_task/net.hpp) | Whether IPv6 is available on this host |

### `address`

[`address`](../include/fast_task/net.hpp:167) is a resolved IP endpoint
(IPv4 or IPv6). It is hashable via
[`std::hash<address>`](../include/fast_task/net.hpp:751), so it can be used as a
key in unordered containers.

| Member | Description |
|--------|-------------|
| [`async_resolve()`](../include/fast_task/net.hpp:220) | Resolve a host/service to a single address |
| [`async_resolve_multiple()`](../include/fast_task/net.hpp:236) | Resolve to all matching addresses |
| [`safe_async_resolve()`](../include/fast_task/net.hpp:252) | Non-throwing resolve |
| [`safe_async_resolve_multiple()`](../include/fast_task/net.hpp:268) | Non-throwing multi-resolve |

The [`family`](../include/fast_task/net.hpp:187) enum selects `ipv4`, `ipv6`, or
`none` (let the resolver decide).

```cpp
auto addr = co_await net::address::async_resolve("example.com", "https");
```

### TCP

[`tcp_socket`](../include/fast_task/net.hpp) is a connected stream socket.
[`tcp_listener`](../include/fast_task/net.hpp) accepts incoming connections.

| Operation | `tcp_socket` | `tcp_listener` |
|-----------|--------------|----------------|
| Connect / accept | [`async_connect()`](../include/fast_task/net.hpp:339) | [`async_accept()`](../include/fast_task/net.hpp:500) |
| Receive | [`async_recv()`](../include/fast_task/net.hpp:355), [`async_recvv()`](../include/fast_task/net.hpp:363) | — |
| Send | [`async_send()`](../include/fast_task/net.hpp:371), [`async_sendv()`](../include/fast_task/net.hpp:379) | — |
| Send file | [`async_send_file()`](../include/fast_task/net.hpp:387), [`async_sendv_file()`](../include/fast_task/net.hpp:403) | — |
| Shutdown / close | [`async_shutdown()`](../include/fast_task/net.hpp:419), [`async_close()`](../include/fast_task/net.hpp:435) | [`async_close()`](../include/fast_task/net.hpp:508) |

`async_send_file` and `async_sendv_file` transmit a file directly from disk
(zero-copy where the platform supports it), optionally with prefix/postfix
buffers. The `safe_async_*` variants return `polyfill::expected` results.

[`tcp_configuration`](../include/fast_task/net.hpp:24) tunes socket behavior,
and [`shutdown_mode`](../include/fast_task/net.hpp:56) selects `receive`,
`send`, or `both`.

```cpp
net::tcp_listener listener;
listener.bind(addr);
while (true) {
    net::tcp_socket client = co_await listener.async_accept();
    co_await client.async_send(payload, payload_size);
    co_await client.async_close();
}
```

### UDP

[`udp_socket`](../include/fast_task/net.hpp) is an unconnected datagram socket;
[`udp_peer`](../include/fast_task/net.hpp) is a connected peer.

| Operation | `udp_socket` | `udp_peer` |
|-----------|--------------|------------|
| Receive | [`async_recv()`](../include/fast_task/net.hpp:566), [`async_recvv()`](../include/fast_task/net.hpp:582) | [`async_recv()`](../include/fast_task/net.hpp:670) |
| Send | [`async_send()`](../include/fast_task/net.hpp:574), [`async_sendv()`](../include/fast_task/net.hpp:590) | [`async_send()`](../include/fast_task/net.hpp:678) |
| Close | [`async_close()`](../include/fast_task/net.hpp:598) | [`async_close()`](../include/fast_task/net.hpp:702) |

`udp_socket` also supports multicast via `join_multicast_group` /
`leave_multicast_group`, and its receive operations report the sender address.
[`udp_configuration`](../include/fast_task/net.hpp) controls socket options.

### Errors

[`tcp_error`](../include/fast_task/net.hpp:46) enumerates TCP failure modes.
The `safe_async_*` operations report errors as
`polyfill::expected<T, std::error_code>`.

---

## Related Pages

- [Tasks](tasks.md) — stackful tasks that drive I/O
- [Coroutines](task/coroutines.md) — `co_await` on I/O awaiters
- [Futures](futures.md) — `fut_*` operations and `future_ptr`
- [Architecture](architecture.md) — how the scheduler integrates with I/O completion
