// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>
#include <net.hpp>

#include <string>

using namespace fast_task::net;

// ---------------------------------------------------------------------------
// AddressTest – pure IP-string parsing, no scheduler required
// ---------------------------------------------------------------------------

class AddressTest : public ::testing::Test {};

TEST_F(AddressTest, DefaultIsEmpty) {
    address a;
    EXPECT_EQ(a.get_family(), address::family::none);
}

TEST_F(AddressTest, IPv4Loopback) {
    address a("127.0.0.1", 8080);
    EXPECT_EQ(a.get_family(), address::family::ipv4);
    EXPECT_EQ(a.port(), 8080u);
    EXPECT_TRUE(a.is_loopback());
}

TEST_F(AddressTest, IPv4Arbitrary) {
    address a("192.168.1.1", 443);
    EXPECT_EQ(a.get_family(), address::family::ipv4);
    EXPECT_EQ(a.port(), 443u);
    EXPECT_FALSE(a.is_loopback());
}

TEST_F(AddressTest, IPv6Loopback) {
    address a("::1", 9090);
    EXPECT_EQ(a.get_family(), address::family::ipv6);
    EXPECT_EQ(a.port(), 9090u);
    EXPECT_TRUE(a.is_loopback());
}

TEST_F(AddressTest, CombinedIPv4String) {
    address a("127.0.0.1:1234");
    EXPECT_EQ(a.get_family(), address::family::ipv4);
    EXPECT_EQ(a.port(), 1234u);
}

TEST_F(AddressTest, AnyWithPort) {
    address a = address::any(80);
    EXPECT_EQ(a.port(), 80u);
    EXPECT_FALSE(a.is_loopback());
}

TEST_F(AddressTest, CopyConstructor) {
    address a("127.0.0.1", 1234);
    address b(a);
    EXPECT_EQ(b.get_family(), address::family::ipv4);
    EXPECT_EQ(b.port(), 1234u);
    EXPECT_EQ(a, b);
}

TEST_F(AddressTest, MoveConstructor) {
    address a("127.0.0.1", 1234);
    address b(std::move(a));
    EXPECT_EQ(b.get_family(), address::family::ipv4);
    EXPECT_EQ(b.port(), 1234u);
}

TEST_F(AddressTest, EqualityOperator) {
    address a("127.0.0.1", 8080);
    address b("127.0.0.1", 8080);
    address c("127.0.0.1", 9090);
    EXPECT_EQ(a, b);
    EXPECT_NE(a, c);
}

TEST_F(AddressTest, ToString) {
    address a("127.0.0.1", 80);
    std::string s = a.to_string();
    EXPECT_FALSE(s.empty());
    EXPECT_NE(s.find("127.0.0.1"), std::string::npos);
}

TEST_F(AddressTest, DataSize) {
    EXPECT_GT(address::data_size(), 0u);
}

// ---------------------------------------------------------------------------
// DnsTest – requires scheduler + c-ares
// ---------------------------------------------------------------------------

class DnsTest : public SchedulerFixture {
public:
    static void SetUpTestSuite() {
        SchedulerFixture::SetUpTestSuite();
        init_networking();
    }

    static void TearDownTestSuite() {
        deinit_networking();
        SchedulerFixture::TearDownTestSuite();
    }
};

TEST_F(DnsTest, ResolveNumericIPv4) {
    // Numeric IPs: c-ares resolves synchronously, no real DNS query
    address a = address::resolve("127.0.0.1", "80");
    EXPECT_EQ(a.get_family(), address::family::ipv4);
    EXPECT_EQ(a.port(), 80u);
}

TEST_F(DnsTest, ResolveNumericIPv4WithPortOverride) {
    address a = address::resolve("127.0.0.1", "", 9090);
    EXPECT_EQ(a.get_family(), address::family::ipv4);
    EXPECT_EQ(a.port(), 9090u);
}

TEST_F(DnsTest, ResolveLocalhost) {
    // "localhost" is in /etc/hosts on all standard Linux systems
    address a = address::resolve("localhost", "80");
    EXPECT_NE(a.get_family(), address::family::none);
    EXPECT_EQ(a.port(), 80u);
    EXPECT_TRUE(a.is_loopback());
}

TEST_F(DnsTest, ResolveLocalhostPreferIPv4) {
    address a = address::resolve("localhost", "443", address::family::ipv4);
    EXPECT_EQ(a.get_family(), address::family::ipv4);
    EXPECT_EQ(a.port(), 443u);
}

TEST_F(DnsTest, ResolveMultipleLocalhost) {
    auto addrs = address::resolve_multiple("localhost", "80");
    EXPECT_FALSE(addrs.empty());
    for (const auto& a : addrs) {
        EXPECT_NE(a.get_family(), address::family::none);
        EXPECT_EQ(a.port(), 80u);
        EXPECT_TRUE(a.is_loopback());
    }
}

TEST_F(DnsTest, ResolveMultipleWithPortOverride) {
    auto addrs = address::resolve_multiple("127.0.0.1", "", 7777);
    ASSERT_FALSE(addrs.empty());
    EXPECT_EQ(addrs[0].get_family(), address::family::ipv4);
    EXPECT_EQ(addrs[0].port(), 7777u);
}

TEST_F(DnsTest, ResolveFromInsideTask) {
    run_task([] {
        address a = address::resolve("127.0.0.1", "8080");
        EXPECT_EQ(a.get_family(), address::family::ipv4);
        EXPECT_EQ(a.port(), 8080u);
    });
}

TEST_F(DnsTest, ResolveMultipleFromInsideTask) {
    run_task([] {
        auto addrs = address::resolve_multiple("localhost", "53");
        EXPECT_FALSE(addrs.empty());
        for (const auto& a : addrs)
            EXPECT_TRUE(a.is_loopback());
    });
}
