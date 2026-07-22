// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>
#include <net.hpp>

#include <array>
#include <atomic>
#include <cstring>
#include <string>
#include <vector>

using namespace fast_task::net;
namespace ft = fast_task;

class TcpTest : public SchedulerFixture {};

// ---------------------------------------------------------------------------
// Basic connect / send / recv
// ---------------------------------------------------------------------------

TEST_F(TcpTest, ConnectSendRecv) {
    run_task([] {
        auto listener = tcp_listener::bind(address("127.0.0.1", 0));
        ASSERT_TRUE(listener.has_value());
        uint16_t port = listener->local_address().port();

        const std::string msg = "hello tcp";

        auto client = ft::task::create([&] {
            auto sock = tcp_socket::connect(address("127.0.0.1", port));
            ASSERT_TRUE(sock.has_value());
            int32_t sent = sock->send(
                std::span<const uint8_t>{reinterpret_cast<const uint8_t*>(msg.data()), msg.size()});
            EXPECT_EQ(sent, static_cast<int32_t>(msg.size()));
            sock->close();
        });
        ft::scheduler::start(client);

        auto conn = listener->accept();
        ASSERT_TRUE(conn.has_value());

        std::vector<uint8_t> buf(64, 0);
        int32_t n = conn->recv(std::span(buf));
        EXPECT_EQ(n, static_cast<int32_t>(msg.size()));
        EXPECT_EQ(std::string(buf.begin(), buf.begin() + n), msg);

        conn->close();
        listener->close();
        client.await_task();
    });
}

// ---------------------------------------------------------------------------
// Large transfer (exercises buffered sends/recvs)
// ---------------------------------------------------------------------------

TEST_F(TcpTest, LargeTransfer) {
    constexpr size_t DATA_SIZE = 128 * 1024;
    std::vector<uint8_t> send_data(DATA_SIZE);
    for (size_t i = 0; i < DATA_SIZE; ++i)
        send_data[i] = static_cast<uint8_t>(i & 0xFF);

    run_task([&] {
        auto listener = tcp_listener::bind(address("127.0.0.1", 0));
        ASSERT_TRUE(listener.has_value());
        uint16_t port = listener->local_address().port();

        auto sender = ft::task::create([&] {
            auto sock = tcp_socket::connect(address("127.0.0.1", port));
            ASSERT_TRUE(sock.has_value());
            size_t sent_total = 0;
            while (sent_total < DATA_SIZE) {
                int32_t n = sock->send(std::span<const uint8_t>{send_data.data() + sent_total,
                                                                 DATA_SIZE - sent_total});
                ASSERT_GT(n, 0);
                sent_total += static_cast<size_t>(n);
            }
            sock->shutdown(shutdown_mode::write);
        });
        ft::scheduler::start(sender);

        auto conn = listener->accept();
        ASSERT_TRUE(conn.has_value());
        listener->close();

        std::vector<uint8_t> recv_data;
        recv_data.reserve(DATA_SIZE);
        std::array<uint8_t, 8192> tmp{};
        while (true) {
            int32_t n = conn->recv(std::span(tmp));
            if (n <= 0)
                break;
            recv_data.insert(recv_data.end(), tmp.begin(), tmp.begin() + n);
        }
        conn->close();
        sender.await_task();

        ASSERT_EQ(recv_data.size(), DATA_SIZE);
        EXPECT_EQ(recv_data, send_data);
    });
}

// ---------------------------------------------------------------------------
// Vectored send / recv
// ---------------------------------------------------------------------------

TEST_F(TcpTest, VectoredSendRecv) {
    run_task([] {
        auto listener = tcp_listener::bind(address("127.0.0.1", 0));
        ASSERT_TRUE(listener.has_value());
        uint16_t port = listener->local_address().port();

        auto client = ft::task::create([&] {
            auto sock = tcp_socket::connect(address("127.0.0.1", port));
            ASSERT_TRUE(sock.has_value());

            const uint8_t a[] = {'A', 'B'};
            const uint8_t b[] = {'C', 'D', 'E'};
            std::array<std::span<const uint8_t>, 2> bufs{std::span<const uint8_t>(a, 2),
                                                          std::span<const uint8_t>(b, 3)};
            int32_t sent = sock->sendv(std::span(bufs));
            EXPECT_EQ(sent, 5);
            sock->close();
        });
        ft::scheduler::start(client);

        auto conn = listener->accept();
        ASSERT_TRUE(conn.has_value());

        std::array<uint8_t, 2> r1{};
        std::array<uint8_t, 3> r2{};
        std::array<std::span<uint8_t>, 2> rbufs{std::span<uint8_t>(r1), std::span<uint8_t>(r2)};
        int32_t n = conn->recvv(std::span(rbufs));
        EXPECT_EQ(n, 5);
        EXPECT_EQ(r1[0], 'A');
        EXPECT_EQ(r1[1], 'B');
        EXPECT_EQ(r2[0], 'C');
        EXPECT_EQ(r2[1], 'D');
        EXPECT_EQ(r2[2], 'E');

        conn->close();
        listener->close();
        client.await_task();
    });
}

// ---------------------------------------------------------------------------
// Multiple sequential accepts
// ---------------------------------------------------------------------------

TEST_F(TcpTest, MultipleAccepts) {
    run_task([] {
        auto listener = tcp_listener::bind(address("127.0.0.1", 0));
        ASSERT_TRUE(listener.has_value());
        uint16_t port = listener->local_address().port();

        constexpr int N = 4;
        std::vector<ft::task> clients;
        clients.reserve(N);

        for (int i = 0; i < N; ++i) {
            auto t = ft::task::create([&, i] {
                auto sock = tcp_socket::connect(address("127.0.0.1", port));
                ASSERT_TRUE(sock.has_value());
                auto val = static_cast<uint8_t>(i + 1);
                sock->send(std::span<const uint8_t>(&val, 1));
                sock->close();
            });
            ft::scheduler::start(t);
            clients.push_back(std::move(t));
        }

        int total = 0;
        for (int i = 0; i < N; ++i) {
            auto conn = listener->accept();
            ASSERT_TRUE(conn.has_value());
            uint8_t buf{};
            conn->recv(std::span<uint8_t>(&buf, 1));
            total += buf;
            conn->close();
        }
        listener->close();

        for (auto& t : clients)
            t.await_task();

        EXPECT_EQ(total, 1 + 2 + 3 + 4);
    });
}

// ---------------------------------------------------------------------------
// Shutdown write half then read remaining data
// ---------------------------------------------------------------------------

TEST_F(TcpTest, ShutdownWrite) {
    run_task([] {
        auto listener = tcp_listener::bind(address("127.0.0.1", 0));
        ASSERT_TRUE(listener.has_value());
        uint16_t port = listener->local_address().port();

        auto client = ft::task::create([&] {
            auto sock = tcp_socket::connect(address("127.0.0.1", port));
            ASSERT_TRUE(sock.has_value());
            const uint8_t data[] = {'X', 'Y', 'Z'};
            sock->send(std::span<const uint8_t>(data, 3));
            sock->shutdown(shutdown_mode::write); // signal EOF to server
        });
        ft::scheduler::start(client);

        auto conn = listener->accept();
        ASSERT_TRUE(conn.has_value());

        std::vector<uint8_t> all;
        std::array<uint8_t, 16> tmp{};
        while (true) {
            int32_t n = conn->recv(std::span(tmp));
            if (n <= 0)
                break;
            all.insert(all.end(), tmp.begin(), tmp.begin() + n);
        }
        conn->close();
        listener->close();
        client.await_task();

        ASSERT_EQ(all.size(), 3u);
        EXPECT_EQ(all[0], 'X');
        EXPECT_EQ(all[1], 'Y');
        EXPECT_EQ(all[2], 'Z');
    });
}

// ---------------------------------------------------------------------------
// local_address / remote_address
// ---------------------------------------------------------------------------

TEST_F(TcpTest, LocalAndRemoteAddress) {
    run_task([] {
        auto listener = tcp_listener::bind(address("127.0.0.1", 0));
        ASSERT_TRUE(listener.has_value());
        uint16_t listen_port = listener->local_address().port();
        EXPECT_GT(listen_port, 0u);

        std::atomic<uint16_t> client_local_port{0};
        auto client = ft::task::create([&] {
            auto sock = tcp_socket::connect(address("127.0.0.1", listen_port));
            ASSERT_TRUE(sock.has_value());
            client_local_port = sock->local_address().port();
            EXPECT_EQ(sock->remote_address().port(), listen_port);
            sock->close();
        });
        ft::scheduler::start(client);

        auto conn = listener->accept();
        ASSERT_TRUE(conn.has_value());
        EXPECT_EQ(conn->local_address().port(), listen_port);

        conn->close();
        listener->close();
        client.await_task();
        EXPECT_GT(client_local_port.load(), 0u);
    });
}
