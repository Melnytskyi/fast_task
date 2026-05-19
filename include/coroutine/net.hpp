// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef INCLUDE_COROUTINE_NET
#define INCLUDE_COROUTINE_NET
#include "../net.hpp"
#include "core.hpp"

namespace fast_task {
    // co_await-able wrappers around tcp_network_stream / tcp_network_blocking
    // / tcp_network_server make_* methods.

    [[nodiscard]] inline auto async_read(networking::tcp_network_stream& stream, uint32_t len) {
        return stream.make_read(len);
    }

    [[nodiscard]] inline auto async_write(networking::tcp_network_stream& stream, const char* data, uint32_t len) {
        return stream.make_write(data, len);
    }

    [[nodiscard]] inline auto async_read(networking::tcp_network_blocking& conn, uint32_t len) {
        return conn.make_read(len);
    }

    [[nodiscard]] inline auto async_write(networking::tcp_network_blocking& conn, const char* data, uint32_t len) {
        return conn.make_write(data, len);
    }

    // Returns a future<tcp_network_blocking*>; the caller takes ownership of
    // the returned pointer.
    [[nodiscard]] inline auto async_accept(networking::tcp_network_server& server, bool ignore_acceptors = false) {
        return server.make_accept(ignore_acceptors);
    }
}

#endif /* INCLUDE_COROUTINE_NET */
