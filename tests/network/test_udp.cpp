// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>
#include <net.hpp>

#include <array>
#include <cstring>
#include <string>
#include <vector>

using namespace fast_task::net;
namespace ft = fast_task;

class UdpTest : public SchedulerFixture {};
class UdpPeerTest : public SchedulerFixture {};

// ---------------------------------------------------------------------------
// Basic loopback send/recv
// ---------------------------------------------------------------------------

TEST_F(UdpTest, SendRecvLoopback) {
    run_task([] {
        auto server = udp_socket::bind(address("127.0.0.1", 0));
        ASSERT_TRUE(server.has_value());
        uint16_t server_port = server->local_address().port();

        auto client = udp_socket::bind(address("127.0.0.1", 0));
        ASSERT_TRUE(client.has_value());

        const std::string msg = "hello udp";
        int32_t sent = client->send(
            std::span<const uint8_t>{reinterpret_cast<const uint8_t*>(msg.data()), msg.size()},
            address("127.0.0.1", server_port));
        EXPECT_EQ(sent, static_cast<int32_t>(msg.size()));

        std::array<uint8_t, 64> buf{};
        address from;
        int32_t n = server->recv(std::span(buf), from);
        EXPECT_EQ(n, static_cast<int32_t>(msg.size()));
        EXPECT_EQ(std::string(reinterpret_cast<char*>(buf.data()), static_cast<size_t>(n)), msg);
        EXPECT_EQ(from.port(), client->local_address().port());

        client->close();
        server->close();
    });
}

// ---------------------------------------------------------------------------
// Vectored send/recv
// ---------------------------------------------------------------------------

TEST_F(UdpTest, VectoredSendRecv) {
    run_task([] {
        auto server = udp_socket::bind(address("127.0.0.1", 0));
        ASSERT_TRUE(server.has_value());
        uint16_t server_port = server->local_address().port();

        auto client = udp_socket::bind(address("127.0.0.1", 0));
        ASSERT_TRUE(client.has_value());

        const uint8_t p1[] = {1, 2, 3};
        const uint8_t p2[] = {4, 5};
        std::array<std::span<const uint8_t>, 2> sbufs{std::span<const uint8_t>(p1, 3),
                                                        std::span<const uint8_t>(p2, 2)};
        int32_t sent = client->sendv(std::span(sbufs), address("127.0.0.1", server_port));
        EXPECT_EQ(sent, 5);

        std::array<uint8_t, 3> r1{};
        std::array<uint8_t, 2> r2{};
        std::array<std::span<uint8_t>, 2> rbufs{std::span<uint8_t>(r1), std::span<uint8_t>(r2)};
        address from;
        int32_t n = server->recvv(std::span(rbufs), from);
        EXPECT_EQ(n, 5);
        EXPECT_EQ(r1[0], 1);
        EXPECT_EQ(r1[1], 2);
        EXPECT_EQ(r1[2], 3);
        EXPECT_EQ(r2[0], 4);
        EXPECT_EQ(r2[1], 5);

        client->close();
        server->close();
    });
}

// ---------------------------------------------------------------------------
// Multiple datagrams in sequence
// ---------------------------------------------------------------------------

TEST_F(UdpTest, MultipleDatagrams) {
    constexpr int N = 8;
    run_task([&] {
        auto server = udp_socket::bind(address("127.0.0.1", 0));
        ASSERT_TRUE(server.has_value());
        uint16_t server_port = server->local_address().port();

        auto client = udp_socket::bind(address("127.0.0.1", 0));
        ASSERT_TRUE(client.has_value());

        for (int i = 0; i < N; ++i) {
            auto b = static_cast<uint8_t>(i);
            client->send(std::span<const uint8_t>(&b, 1), address("127.0.0.1", server_port));
        }

        int sum = 0;
        for (int i = 0; i < N; ++i) {
            uint8_t b{};
            address from;
            server->recv(std::span<uint8_t>(&b, 1), from);
            sum += b;
        }
        EXPECT_EQ(sum, 0 + 1 + 2 + 3 + 4 + 5 + 6 + 7);

        client->close();
        server->close();
    });
}

// ---------------------------------------------------------------------------
// udp_peer – connected send/recv
// ---------------------------------------------------------------------------

TEST_F(UdpPeerTest, ConnectedSendRecv) {
    run_task([] {
        // Raw server socket for the other side
        auto server = udp_socket::bind(address("127.0.0.1", 0));
        ASSERT_TRUE(server.has_value());
        uint16_t server_port = server->local_address().port();

        // Peer connects to server
        auto peer = udp_peer::connect(address("127.0.0.1", server_port));
        ASSERT_TRUE(peer.has_value());
        uint16_t peer_port = peer->local_address().port();

        // Peer sends to server
        const std::string msg = "hello from peer";
        peer->send(
            std::span<const uint8_t>{reinterpret_cast<const uint8_t*>(msg.data()), msg.size()});

        std::array<uint8_t, 64> buf{};
        address from;
        int32_t n = server->recv(std::span(buf), from);
        EXPECT_EQ(n, static_cast<int32_t>(msg.size()));
        EXPECT_EQ(std::string(reinterpret_cast<char*>(buf.data()), static_cast<size_t>(n)), msg);
        EXPECT_EQ(from.port(), peer_port);

        // Server replies
        const std::string reply = "ack";
        server->send(
            std::span<const uint8_t>{reinterpret_cast<const uint8_t*>(reply.data()), reply.size()},
            from);

        std::array<uint8_t, 16> rbuf{};
        int32_t rn = peer->recv(std::span(rbuf));
        EXPECT_EQ(rn, static_cast<int32_t>(reply.size()));
        EXPECT_EQ(std::string(reinterpret_cast<char*>(rbuf.data()), static_cast<size_t>(rn)), reply);

        peer->close();
        server->close();
    });
}

TEST_F(UdpPeerTest, VectoredSendRecv) {
    run_task([] {
        auto server = udp_socket::bind(address("127.0.0.1", 0));
        ASSERT_TRUE(server.has_value());
        uint16_t server_port = server->local_address().port();

        auto peer = udp_peer::connect(address("127.0.0.1", server_port));
        ASSERT_TRUE(peer.has_value());

        const uint8_t a[] = {0xAA, 0xBB};
        const uint8_t b[] = {0xCC};
        std::array<std::span<const uint8_t>, 2> sbufs{std::span<const uint8_t>(a, 2),
                                                        std::span<const uint8_t>(b, 1)};
        peer->sendv(std::span(sbufs));

        std::array<uint8_t, 2> r1{};
        std::array<uint8_t, 1> r2{};
        std::array<std::span<uint8_t>, 2> rbufs{std::span<uint8_t>(r1), std::span<uint8_t>(r2)};
        address from;
        int32_t n = server->recvv(std::span(rbufs), from);
        EXPECT_EQ(n, 3);
        EXPECT_EQ(r1[0], 0xAA);
        EXPECT_EQ(r1[1], 0xBB);
        EXPECT_EQ(r2[0], 0xCC);

        peer->close();
        server->close();
    });
}

TEST_F(UdpPeerTest, PeerVectoredRecv) {
    run_task([] {
        auto server = udp_socket::bind(address("127.0.0.1", 0));
        ASSERT_TRUE(server.has_value());
        uint16_t server_port = server->local_address().port();

        auto peer = udp_peer::connect(address("127.0.0.1", server_port));
        ASSERT_TRUE(peer.has_value());
        uint16_t peer_port = peer->local_address().port();

        // Send from server → peer using scatter payload
        const uint8_t payload[] = {1, 2, 3, 4};
        server->send(std::span<const uint8_t>(payload, 4), address("127.0.0.1", peer_port));

        std::array<uint8_t, 2> r1{};
        std::array<uint8_t, 2> r2{};
        std::array<std::span<uint8_t>, 2> rbufs{std::span<uint8_t>(r1), std::span<uint8_t>(r2)};
        int32_t n = peer->recvv(std::span(rbufs));
        EXPECT_EQ(n, 4);
        EXPECT_EQ(r1[0], 1);
        EXPECT_EQ(r1[1], 2);
        EXPECT_EQ(r2[0], 3);
        EXPECT_EQ(r2[1], 4);

        peer->close();
        server->close();
    });
}
