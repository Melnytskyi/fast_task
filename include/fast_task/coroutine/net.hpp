// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_INCLUDE_COROUTINE_NET
#define FAST_TASK_INCLUDE_COROUTINE_NET
#include "../net.hpp"
#include "../polyfill/expected.hpp"
#include "core.hpp"
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <vector>

namespace fast_task::net {
    namespace detail {
        // Awaiter that drives a network "enter_*" operation which produces a value.
        // The operation is started lazily on suspension, so an unawaited awaiter is a no-op.
        template <class Result, class Starter>
        struct [[nodiscard("network operations must be awaited")]] value_awaiter {
            Starter start;
            opaque_network_state state{};
            Result result{};

            bool await_ready() const noexcept {
                return false;
            }

            bool await_suspend(base_coro_handle h) {
                return !start(h.promise->task_object, state, result);
            }

            Result await_resume() {
                return std::move(result);
            }
        };

        template <class Result, class Starter>
        struct [[nodiscard("network operations must be awaited")]] safe_value_awaiter {
            Starter start;
            opaque_network_state state{};
            Result result{};

            bool await_ready() const noexcept {
                return false;
            }

            bool await_suspend(base_coro_handle h) {
                return !start(h.promise->task_object, state, result);
            }

            polyfill::expected<Result, std::error_code> await_resume() {
                if (auto ec = state.get_error_code())
                    return polyfill::unexpected(ec);
                return std::move(result);
            }
        };

        // Awaiter for "enter_*" operations without a meaningful return value.
        template <class Starter>
        struct [[nodiscard("network operations must be awaited")]] void_awaiter {
            Starter start;
            opaque_network_state state{};

            bool await_ready() const noexcept {
                return false;
            }

            bool await_suspend(base_coro_handle h) {
                return !start(h.promise->task_object, state);
            }

            void await_resume() {}
        };

        template <class Result, class Starter>
        value_awaiter<Result, std::decay_t<Starter>> make_value_awaiter(Starter&& s) {
            return value_awaiter<Result, std::decay_t<Starter>>{std::forward<Starter>(s)};
        }

        template <class Result, class Starter>
        safe_value_awaiter<Result, std::decay_t<Starter>> make_safe_value_awaiter(Starter&& s) {
            return safe_value_awaiter<Result, std::decay_t<Starter>>{std::forward<Starter>(s)};
        }

        template <class Starter>
        void_awaiter<std::decay_t<Starter>> make_void_awaiter(Starter&& s) {
            return void_awaiter<std::decay_t<Starter>>{std::forward<Starter>(s)};
        }
    }

    // ---------------------------------------------------------------------
    // address resolution
    // ---------------------------------------------------------------------

    inline auto async_resolve(std::string_view host, std::string_view service, address::family preferred_family = address::family::none) {
        return detail::make_value_awaiter<address>(
            [host, service, preferred_family](const task& t, opaque_network_state& st, address& r) {
                return address::enter_resolve(t, st, r, host, service, preferred_family);
            }
        );
    }

    inline auto async_resolve(std::string_view host, std::string_view service, uint16_t port, address::family preferred_family = address::family::none) {
        return detail::make_value_awaiter<address>(
            [host, service, port, preferred_family](const task& t, opaque_network_state& st, address& r) {
                return address::enter_resolve(t, st, r, host, service, port, preferred_family);
            }
        );
    }

    inline auto async_resolve_multiple(std::string_view host, std::string_view service, address::family preferred_family = address::family::none) {
        return detail::make_value_awaiter<std::vector<address>>(
            [host, service, preferred_family](const task& t, opaque_network_state& st, std::vector<address>& r) {
                return address::enter_resolve_multiple(t, st, r, host, service, preferred_family);
            }
        );
    }

    inline auto async_resolve_multiple(std::string_view host, std::string_view service, uint16_t port, address::family preferred_family = address::family::none) {
        return detail::make_value_awaiter<std::vector<address>>(
            [host, service, port, preferred_family](const task& t, opaque_network_state& st, std::vector<address>& r) {
                return address::enter_resolve_multiple(t, st, r, host, service, port, preferred_family);
            }
        );
    }

    inline auto safe_async_resolve(std::string_view host, std::string_view service, address::family preferred_family = address::family::none) {
        return detail::make_safe_value_awaiter<address>(
            [host, service, preferred_family](const task& t, opaque_network_state& st, address& r) {
                return address::enter_resolve(t, st, r, host, service, preferred_family);
            }
        );
    }

    inline auto safe_async_resolve(std::string_view host, std::string_view service, uint16_t port, address::family preferred_family = address::family::none) {
        return detail::make_safe_value_awaiter<address>(
            [host, service, port, preferred_family](const task& t, opaque_network_state& st, address& r) {
                return address::enter_resolve(t, st, r, host, service, port, preferred_family);
            }
        );
    }

    inline auto safe_async_resolve_multiple(std::string_view host, std::string_view service, address::family preferred_family = address::family::none) {
        return detail::make_safe_value_awaiter<std::vector<address>>(
            [host, service, preferred_family](const task& t, opaque_network_state& st, std::vector<address>& r) {
                return address::enter_resolve_multiple(t, st, r, host, service, preferred_family);
            }
        );
    }

    inline auto safe_async_resolve_multiple(std::string_view host, std::string_view service, uint16_t port, address::family preferred_family = address::family::none) {
        return detail::make_safe_value_awaiter<std::vector<address>>(
            [host, service, port, preferred_family](const task& t, opaque_network_state& st, std::vector<address>& r) {
                return address::enter_resolve_multiple(t, st, r, host, service, port, preferred_family);
            }
        );
    }

    // ---------------------------------------------------------------------
    // tcp_socket
    // ---------------------------------------------------------------------

    inline auto async_connect(const address& ip_port, const tcp_configuration& config = {}) {
        return detail::make_value_awaiter<std::optional<tcp_socket>>(
            [ip_port, config](const task& t, opaque_network_state& st, std::optional<tcp_socket>& r) {
                return tcp_socket::enter_connect(t, st, r, ip_port, config);
            }
        );
    }

    inline auto async_connect(const address& ip_port, uint8_t* data, int32_t& size, const tcp_configuration& config = {}) {
        return detail::make_value_awaiter<std::optional<tcp_socket>>(
            [ip_port, data, &size, config](const task& t, opaque_network_state& st, std::optional<tcp_socket>& r) {
                return tcp_socket::enter_connect(t, st, r, ip_port, data, size, config);
            }
        );
    }

    inline auto async_recv(tcp_socket& sock, std::span<uint8_t> data) {
        return detail::make_value_awaiter<int32_t>(
            [&sock, data](const task& t, opaque_network_state& st, int32_t& r) {
                return sock.enter_recv(t, st, r, data);
            }
        );
    }

    inline auto async_recvv(tcp_socket& sock, std::span<std::span<uint8_t>> data) {
        return detail::make_value_awaiter<int32_t>(
            [&sock, data](const task& t, opaque_network_state& st, int32_t& r) {
                return sock.enter_recvv(t, st, r, data);
            }
        );
    }

    inline auto async_send(tcp_socket& sock, std::span<const uint8_t> data) {
        return detail::make_value_awaiter<int32_t>(
            [&sock, data](const task& t, opaque_network_state& st, int32_t& r) {
                return sock.enter_send(t, st, r, data);
            }
        );
    }

    inline auto async_sendv(tcp_socket& sock, std::span<const std::span<const uint8_t>> data) {
        return detail::make_value_awaiter<int32_t>(
            [&sock, data](const task& t, opaque_network_state& st, int32_t& r) {
                return sock.enter_sendv(t, st, r, data);
            }
        );
    }

    inline auto async_send_file(tcp_socket& sock, const char* file_path, size_t file_path_len, uint32_t data_len, uint64_t offset, uint32_t chunks_size) {
        return detail::make_value_awaiter<int32_t>(
            [&sock, file_path, file_path_len, data_len, offset, chunks_size](const task& t, opaque_network_state& st, int32_t& r) {
                return sock.enter_send_file(t, st, r, file_path, file_path_len, data_len, offset, chunks_size);
            }
        );
    }

    inline auto async_send_file(tcp_socket& sock, file::file_handle& file, uint32_t data_len, uint64_t offset, uint32_t chunks_size) {
        return detail::make_value_awaiter<int32_t>(
            [&sock, &file, data_len, offset, chunks_size](const task& t, opaque_network_state& st, int32_t& r) {
                return sock.enter_send_file(t, st, r, file, data_len, offset, chunks_size);
            }
        );
    }

    inline auto async_sendv_file(tcp_socket& sock, std::span<const uint8_t> prefix, std::span<const uint8_t> postfix, const char* file_path, size_t file_path_len, uint32_t data_len, uint64_t offset, uint32_t chunks_size) {
        return detail::make_value_awaiter<int32_t>(
            [&sock, prefix, postfix, file_path, file_path_len, data_len, offset, chunks_size](const task& t, opaque_network_state& st, int32_t& r) {
                return sock.enter_sendv_file(t, st, r, prefix, postfix, file_path, file_path_len, data_len, offset, chunks_size);
            }
        );
    }

    inline auto async_sendv_file(tcp_socket& sock, std::span<const uint8_t> prefix, std::span<const uint8_t> postfix, file::file_handle& file, uint32_t data_len, uint64_t offset, uint32_t chunks_size) {
        return detail::make_value_awaiter<int32_t>(
            [&sock, prefix, postfix, &file, data_len, offset, chunks_size](const task& t, opaque_network_state& st, int32_t& r) {
                return sock.enter_sendv_file(t, st, r, prefix, postfix, file, data_len, offset, chunks_size);
            }
        );
    }

    inline auto async_shutdown(tcp_socket& sock, shutdown_mode mode) {
        return detail::make_void_awaiter(
            [&sock, mode](const task& t, opaque_network_state& st) {
                return sock.enter_shutdown(t, st, mode);
            }
        );
    }

    inline auto async_reset(tcp_socket& sock) {
        return detail::make_void_awaiter(
            [&sock](const task& t, opaque_network_state& st) {
                return sock.enter_reset(t, st);
            }
        );
    }

    inline auto async_close(tcp_socket& sock) {
        return detail::make_void_awaiter(
            [&sock](const task& t, opaque_network_state& st) {
                return sock.enter_close(t, st);
            }
        );
    }

    inline auto safe_async_recv(tcp_socket& sock, std::span<uint8_t> data) {
        return detail::make_safe_value_awaiter<int32_t>(
            [&sock, data](const task& t, opaque_network_state& st, int32_t& r) {
                return sock.enter_recv(t, st, r, data);
            }
        );
    }

    inline auto safe_async_recvv(tcp_socket& sock, std::span<std::span<uint8_t>> data) {
        return detail::make_safe_value_awaiter<int32_t>(
            [&sock, data](const task& t, opaque_network_state& st, int32_t& r) {
                return sock.enter_recvv(t, st, r, data);
            }
        );
    }

    inline auto safe_async_send(tcp_socket& sock, std::span<const uint8_t> data) {
        return detail::make_safe_value_awaiter<int32_t>(
            [&sock, data](const task& t, opaque_network_state& st, int32_t& r) {
                return sock.enter_send(t, st, r, data);
            }
        );
    }

    inline auto safe_async_sendv(tcp_socket& sock, std::span<const std::span<const uint8_t>> data) {
        return detail::make_safe_value_awaiter<int32_t>(
            [&sock, data](const task& t, opaque_network_state& st, int32_t& r) {
                return sock.enter_sendv(t, st, r, data);
            }
        );
    }

    // ---------------------------------------------------------------------
    // tcp_listener
    // ---------------------------------------------------------------------

    inline auto async_accept(tcp_listener& listener) {
        return detail::make_value_awaiter<std::optional<tcp_socket>>(
            [&listener](const task& t, opaque_network_state& st, std::optional<tcp_socket>& r) {
                return listener.enter_accept(t, st, r);
            }
        );
    }

    inline auto async_close(tcp_listener& listener) {
        return detail::make_void_awaiter(
            [&listener](const task& t, opaque_network_state& st) {
                return listener.enter_close(t, st);
            }
        );
    }

    // ---------------------------------------------------------------------
    // udp_socket
    // ---------------------------------------------------------------------

    inline auto async_recv(udp_socket& sock, std::span<uint8_t> data, address& sender) {
        return detail::make_value_awaiter<uint32_t>(
            [&sock, data, &sender](const task& t, opaque_network_state& st, uint32_t& r) {
                return sock.enter_recv(t, st, r, data, sender);
            }
        );
    }

    inline auto async_send(udp_socket& sock, std::span<const uint8_t> data, const address& to) {
        return detail::make_value_awaiter<uint32_t>(
            [&sock, data, to](const task& t, opaque_network_state& st, uint32_t& r) {
                return sock.enter_send(t, st, r, data, to);
            }
        );
    }

    inline auto async_recvv(udp_socket& sock, std::span<std::span<uint8_t>> buffers, address& sender) {
        return detail::make_value_awaiter<uint32_t>(
            [&sock, buffers, &sender](const task& t, opaque_network_state& st, uint32_t& r) {
                return sock.enter_recvv(t, st, r, buffers, sender);
            }
        );
    }

    inline auto async_sendv(udp_socket& sock, std::span<const std::span<const uint8_t>> data, const address& to) {
        return detail::make_value_awaiter<uint32_t>(
            [&sock, data, to](const task& t, opaque_network_state& st, uint32_t& r) {
                return sock.enter_sendv(t, st, r, data, to);
            }
        );
    }

    inline auto async_close(udp_socket& sock) {
        return detail::make_void_awaiter(
            [&sock](const task& t, opaque_network_state& st) {
                return sock.enter_close(t, st);
            }
        );
    }

    inline auto safe_async_recv(udp_socket& sock, std::span<uint8_t> data, address& sender) {
        return detail::make_safe_value_awaiter<uint32_t>(
            [&sock, data, &sender](const task& t, opaque_network_state& st, uint32_t& r) {
                return sock.enter_recv(t, st, r, data, sender);
            }
        );
    }

    inline auto safe_async_send(udp_socket& sock, std::span<const uint8_t> data, const address& to) {
        return detail::make_safe_value_awaiter<uint32_t>(
            [&sock, data, to](const task& t, opaque_network_state& st, uint32_t& r) {
                return sock.enter_send(t, st, r, data, to);
            }
        );
    }

    inline auto safe_async_recvv(udp_socket& sock, std::span<std::span<uint8_t>> buffers, address& sender) {
        return detail::make_safe_value_awaiter<uint32_t>(
            [&sock, buffers, &sender](const task& t, opaque_network_state& st, uint32_t& r) {
                return sock.enter_recvv(t, st, r, buffers, sender);
            }
        );
    }

    inline auto safe_async_sendv(udp_socket& sock, std::span<const std::span<const uint8_t>> data, const address& to) {
        return detail::make_safe_value_awaiter<uint32_t>(
            [&sock, data, to](const task& t, opaque_network_state& st, uint32_t& r) {
                return sock.enter_sendv(t, st, r, data, to);
            }
        );
    }

    // ---------------------------------------------------------------------
    // udp_peer
    // ---------------------------------------------------------------------

    inline auto async_recv(udp_peer& peer, std::span<uint8_t> data) {
        return detail::make_value_awaiter<uint32_t>(
            [&peer, data](const task& t, opaque_network_state& st, uint32_t& r) {
                return peer.enter_recv(t, st, r, data);
            }
        );
    }

    inline auto async_send(udp_peer& peer, std::span<const uint8_t> data) {
        return detail::make_value_awaiter<uint32_t>(
            [&peer, data](const task& t, opaque_network_state& st, uint32_t& r) {
                return peer.enter_send(t, st, r, data);
            }
        );
    }

    inline auto async_recvv(udp_peer& peer, std::span<std::span<uint8_t>> buffers) {
        return detail::make_value_awaiter<uint32_t>(
            [&peer, buffers](const task& t, opaque_network_state& st, uint32_t& r) {
                return peer.enter_recvv(t, st, r, buffers);
            }
        );
    }

    inline auto async_sendv(udp_peer& peer, std::span<const std::span<const uint8_t>> data) {
        return detail::make_value_awaiter<uint32_t>(
            [&peer, data](const task& t, opaque_network_state& st, uint32_t& r) {
                return peer.enter_sendv(t, st, r, data);
            }
        );
    }

    inline auto async_close(udp_peer& peer) {
        return detail::make_void_awaiter(
            [&peer](const task& t, opaque_network_state& st) {
                return peer.enter_close(t, st);
            }
        );
    }

    inline auto safe_async_recv(udp_peer& peer, std::span<uint8_t> data) {
        return detail::make_safe_value_awaiter<uint32_t>(
            [&peer, data](const task& t, opaque_network_state& st, uint32_t& r) {
                return peer.enter_recv(t, st, r, data);
            }
        );
    }

    inline auto safe_async_send(udp_peer& peer, std::span<const uint8_t> data) {
        return detail::make_safe_value_awaiter<uint32_t>(
            [&peer, data](const task& t, opaque_network_state& st, uint32_t& r) {
                return peer.enter_send(t, st, r, data);
            }
        );
    }

    inline auto safe_async_recvv(udp_peer& peer, std::span<std::span<uint8_t>> buffers) {
        return detail::make_safe_value_awaiter<uint32_t>(
            [&peer, buffers](const task& t, opaque_network_state& st, uint32_t& r) {
                return peer.enter_recvv(t, st, r, buffers);
            }
        );
    }

    inline auto safe_async_sendv(udp_peer& peer, std::span<const std::span<const uint8_t>> data) {
        return detail::make_safe_value_awaiter<uint32_t>(
            [&peer, data](const task& t, opaque_network_state& st, uint32_t& r) {
                return peer.enter_sendv(t, st, r, data);
            }
        );
    }
}

#endif /* FAST_TASK_INCLUDE_COROUTINE_NET */
