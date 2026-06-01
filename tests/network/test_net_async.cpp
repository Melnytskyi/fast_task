// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <coroutine/net.hpp>
#include <helpers.hpp>

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

using namespace fast_task::net;
namespace ft = fast_task;

namespace {
    std::span<const uint8_t> as_bytes(const std::string& s) {
        return std::span<const uint8_t>{reinterpret_cast<const uint8_t*>(s.data()), s.size()};
    }
}

class NetAsyncTest : public SchedulerFixture {};

// ---------------------------------------------------------------------------
// TCP: connect / send / recv driven entirely through coroutine awaiters
// ---------------------------------------------------------------------------

TEST_F(NetAsyncTest, TcpAsyncConnectSendRecv) {
    run_task([&] {
        auto listener = tcp_listener::bind(address("127.0.0.1", 0));
        ASSERT_TRUE(listener.has_value());
        uint16_t port = listener->local_address().port();

        const std::string msg = "hello async tcp";

        auto server = [&]() -> ft::task_coro<std::string> {
            auto conn = co_await async_accept(*listener);
            if (!conn.has_value())
                co_return std::string{};

            std::vector<uint8_t> buf(64, 0);
            int32_t n = co_await async_recv(*conn, std::span(buf));
            std::string out;
            if (n > 0)
                out.assign(buf.begin(), buf.begin() + n);

            co_await async_close(*conn);
            co_return out;
        };

        auto client = [&]() -> ft::task_coro<bool> {
            auto sock = co_await async_connect(address("127.0.0.1", port));
            if (!sock.has_value())
                co_return false;

            int32_t sent = co_await async_send(*sock, as_bytes(msg));
            co_await async_close(*sock);
            co_return sent == static_cast<int32_t>(msg.size());
        };

        auto server_coro = server();
        auto client_coro = client();
        ft::scheduler::start(server_coro.get_task());
        ft::scheduler::start(client_coro.get_task());

        server_coro->await_task();
        client_coro->await_task();

        EXPECT_TRUE(get_coro_result(client_coro));
        EXPECT_EQ(get_coro_result(server_coro), msg);

        listener->close();
    });
}

// ---------------------------------------------------------------------------
// TCP: vectored send / recv
// ---------------------------------------------------------------------------

TEST_F(NetAsyncTest, TcpAsyncVectored) {
    run_task([&] {
        auto listener = tcp_listener::bind(address("127.0.0.1", 0));
        ASSERT_TRUE(listener.has_value());
        uint16_t port = listener->local_address().port();

        auto server = [&]() -> ft::task_coro<std::vector<uint8_t>> {
            auto conn = co_await async_accept(*listener);
            if (!conn.has_value())
                co_return std::vector<uint8_t>{};

            std::array<uint8_t, 3> r1{};
            std::array<uint8_t, 2> r2{};
            std::array<std::span<uint8_t>, 2> rbufs{std::span<uint8_t>(r1), std::span<uint8_t>(r2)};

            std::vector<uint8_t> out;
            int32_t received = 0;
            while (received < 5) {
                int32_t n = co_await async_recvv(*conn, std::span(rbufs));
                if (n <= 0)
                    break;
                received += n;
            }
            out.insert(out.end(), r1.begin(), r1.end());
            out.insert(out.end(), r2.begin(), r2.end());

            co_await async_close(*conn);
            co_return out;
        };

        auto client = [&]() -> ft::task_coro<void> {
            auto sock = co_await async_connect(address("127.0.0.1", port));
            if (sock.has_value()) {
                const uint8_t a[] = {1, 2, 3};
                const uint8_t b[] = {4, 5};
                std::array<std::span<const uint8_t>, 2> sbufs{std::span<const uint8_t>(a, 3),
                                                              std::span<const uint8_t>(b, 2)};
                co_await async_sendv(*sock, std::span(sbufs));
                co_await async_close(*sock);
            }
            co_return;
        };

        auto server_coro = server();
        auto client_coro = client();
        ft::scheduler::start(server_coro.get_task());
        ft::scheduler::start(client_coro.get_task());

        server_coro->await_task();
        client_coro->await_task();

        auto data = get_coro_result(server_coro);
        ASSERT_EQ(data.size(), 5u);
        EXPECT_EQ(data[0], 1);
        EXPECT_EQ(data[1], 2);
        EXPECT_EQ(data[2], 3);
        EXPECT_EQ(data[3], 4);
        EXPECT_EQ(data[4], 5);

        listener->close();
    });
}

// ---------------------------------------------------------------------------
// TCP: safe_* variants expose errors through expected<>
// ---------------------------------------------------------------------------

TEST_F(NetAsyncTest, TcpSafeSendRecv) {
    run_task([&] {
        auto listener = tcp_listener::bind(address("127.0.0.1", 0));
        ASSERT_TRUE(listener.has_value());
        uint16_t port = listener->local_address().port();

        const std::string msg = "safe payload";

        auto server = [&]() -> ft::task_coro<std::string> {
            auto conn = co_await async_accept(*listener);
            if (!conn.has_value())
                co_return std::string{};

            std::vector<uint8_t> buf(64, 0);
            auto res = co_await safe_async_recv(*conn, std::span(buf));
            std::string out;
            if (res.has_value() && *res > 0)
                out.assign(buf.begin(), buf.begin() + *res);

            co_await async_close(*conn);
            co_return out;
        };

        auto client = [&]() -> ft::task_coro<bool> {
            auto sock = co_await async_connect(address("127.0.0.1", port));
            if (!sock.has_value())
                co_return false;

            auto res = co_await safe_async_send(*sock, as_bytes(msg));
            co_await async_close(*sock);
            co_return res.has_value() && *res == static_cast<int32_t>(msg.size());
        };

        auto server_coro = server();
        auto client_coro = client();
        ft::scheduler::start(server_coro.get_task());
        ft::scheduler::start(client_coro.get_task());

        server_coro->await_task();
        client_coro->await_task();

        EXPECT_TRUE(get_coro_result(client_coro));
        EXPECT_EQ(get_coro_result(server_coro), msg);

        listener->close();
    });
}

// ---------------------------------------------------------------------------
// UDP: async send / recv on loopback
// ---------------------------------------------------------------------------

TEST_F(NetAsyncTest, UdpAsyncSendRecv) {
    run_task([&] {
        auto server = udp_socket::bind(address("127.0.0.1", 0));
        ASSERT_TRUE(server.has_value());
        uint16_t server_port = server->local_address().port();

        auto client = udp_socket::bind(address("127.0.0.1", 0));
        ASSERT_TRUE(client.has_value());
        uint16_t client_port = client->local_address().port();

        const std::string msg = "async udp";

        auto recv_side = [&]() -> ft::task_coro<std::string> {
            std::array<uint8_t, 64> buf{};
            address from;
            uint32_t n = co_await async_recv(*server, std::span(buf), from);
            std::string out(reinterpret_cast<char*>(buf.data()), static_cast<size_t>(n));
            EXPECT_EQ(from.port(), client_port);
            co_return out;
        };

        auto send_side = [&]() -> ft::task_coro<uint32_t> {
            co_return co_await async_send(*client, as_bytes(msg), address("127.0.0.1", server_port));
        };

        auto recv_coro = recv_side();
        auto send_coro = send_side();
        ft::scheduler::start(recv_coro.get_task());
        ft::scheduler::start(send_coro.get_task());

        recv_coro->await_task();
        send_coro->await_task();

        EXPECT_EQ(get_coro_result(send_coro), static_cast<uint32_t>(msg.size()));
        EXPECT_EQ(get_coro_result(recv_coro), msg);

        client->close();
        server->close();
    });
}

// ---------------------------------------------------------------------------
// UDP peer: connected async send / recv
// ---------------------------------------------------------------------------

TEST_F(NetAsyncTest, UdpPeerAsyncSendRecv) {
    run_task([&] {
        auto server = udp_socket::bind(address("127.0.0.1", 0));
        ASSERT_TRUE(server.has_value());
        uint16_t server_port = server->local_address().port();

        auto peer = udp_peer::connect(address("127.0.0.1", server_port));
        ASSERT_TRUE(peer.has_value());

        const std::string msg = "peer ping";

        auto recv_side = [&]() -> ft::task_coro<std::string> {
            std::array<uint8_t, 64> buf{};
            address from;
            uint32_t n = co_await async_recv(*server, std::span(buf), from);
            co_return std::string(reinterpret_cast<char*>(buf.data()), static_cast<size_t>(n));
        };

        auto send_side = [&]() -> ft::task_coro<uint32_t> {
            co_return co_await async_send(*peer, as_bytes(msg));
        };

        auto recv_coro = recv_side();
        auto send_coro = send_side();
        ft::scheduler::start(recv_coro.get_task());
        ft::scheduler::start(send_coro.get_task());

        recv_coro->await_task();
        send_coro->await_task();

        EXPECT_EQ(get_coro_result(send_coro), static_cast<uint32_t>(msg.size()));
        EXPECT_EQ(get_coro_result(recv_coro), msg);

        peer->close();
        server->close();
    });
}

// ---------------------------------------------------------------------------
// Address resolution through the coroutine awaiter
// ---------------------------------------------------------------------------

TEST_F(NetAsyncTest, AsyncResolveLoopback) {
    auto resolver = [&]() -> ft::task_coro<bool> {
        auto addr = co_await async_resolve("127.0.0.1", "0");
        co_return addr.is_loopback();
    };

    auto coro = resolver();
    ft::scheduler::start(coro.get_task());
    coro->await_task();

    EXPECT_TRUE(get_coro_result(coro));
}

TEST_F(NetAsyncTest, SafeAsyncResolveLoopback) {
    auto resolver = [&]() -> ft::task_coro<bool> {
        auto res = co_await safe_async_resolve("127.0.0.1", "0");
        co_return res.has_value() && res->is_loopback();
    };

    auto coro = resolver();
    ft::scheduler::start(coro.get_task());
    coro->await_task();

    EXPECT_TRUE(get_coro_result(coro));
}
