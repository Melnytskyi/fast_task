// Copyright Danyil Melnytskyi 2022-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)
#ifndef SRC_NET_SHARED
#define SRC_NET_SHARED
#if _WIN64
    #define _WINSOCKAPI_
    #define WIN32_LEAN_AND_MEAN
    #define NOMINMAX
    #include <winsock2.h>

    #include <ws2tcpip.h>

    #include <mswsock.h>

    #include <stdio.h>
    #pragma comment(lib, "Ws2_32.lib")
#else
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <netinet/tcp.h>
    #include <sys/ioctl.h>
    #include <sys/mman.h>
    #include <sys/socket.h>
    #include <sys/types.h>
#endif

#include <condition_variable>
#include <filesystem>
#include <functional>
#include <string>
#include <variant>

namespace fast_task::net {

    extern bool inited;
    uint8_t init_networking();
    using universal_address = ::sockaddr_storage;

    void internal_makeIP4(universal_address& addr_storage, const char* ip, uint16_t port) {
        init_networking();
        sockaddr_in6 addr6;
        memset(&addr6, 0, sizeof(addr6));
        addr6.sin6_family = AF_INET6;
        addr6.sin6_port = htons(port);
        addr6.sin6_addr.s6_addr[10] = 0xFF;
        addr6.sin6_addr.s6_addr[11] = 0xFF;
        if (inet_pton(AF_INET, ip, &addr6.sin6_addr.s6_addr[12]) != 1)
            throw std::invalid_argument("Invalid ip4 address");

        memset(&addr_storage, 0, sizeof(addr_storage));
        memcpy(&addr_storage, &addr6, sizeof(addr6));
    }

    void internal_makeIP6(universal_address& addr_storage, const char* ip, uint16_t port) {
        init_networking();
        sockaddr_in6 addr6;
        memset(&addr6, 0, sizeof(addr6));
        addr6.sin6_family = AF_INET6;
        addr6.sin6_port = htons(port);
        if (inet_pton(AF_INET6, ip, &addr6.sin6_addr) != 1)
            throw std::invalid_argument("Invalid ip6 address");

        memset(&addr_storage, 0, sizeof(addr_storage));
        memcpy(&addr_storage, &addr6, sizeof(addr6));
    }

    void internal_makeIP(universal_address& addr_storage, const char* ip, uint16_t port) {
        init_networking();
        sockaddr_in6 addr6;
        memset(&addr6, 0, sizeof(addr6));
        addr6.sin6_family = AF_INET6;
        addr6.sin6_port = htons(port);
        addr6.sin6_addr.s6_addr[10] = 0xFF;
        addr6.sin6_addr.s6_addr[11] = 0xFF;
        if (inet_pton(AF_INET, ip, &addr6.sin6_addr + 12) == 1)
            ;
        else if (inet_pton(AF_INET6, ip, &addr6.sin6_addr) == 1)
            ;
        else {
            std::string port_(std::to_string(port));
            addrinfo* addr_res;
            if (getaddrinfo(ip, port_.c_str(), nullptr, &addr_res)) {
                freeaddrinfo(addr_res);
                throw std::invalid_argument("Invalid ip address");
            }
            memset(&addr_storage, 0, sizeof(addr_storage));
            memcpy(&addr_storage, addr_res->ai_addr, addr_res->ai_addrlen);
            freeaddrinfo(addr_res);
            return;
        }
        memset(&addr_storage, 0, sizeof(addr_storage));
        memcpy(&addr_storage, &addr6, sizeof(addr6));
    }

    void internal_makeIP4_port(universal_address& addr_storage, const char* ip_port) {
        init_networking();
        const char* port = strchr(ip_port, ':');
        if (!port)
            throw std::invalid_argument("Invalid ip4 address");
        uint16_t port_num = (uint16_t)std::stoi(port + 1);
        std::string ip(ip_port, port);
        char first_ch = ip[0];
        if (std::isdigit(first_ch))
            internal_makeIP4(addr_storage, ip.c_str(), port_num);
        else {
            addrinfo* addr_res;
            if (getaddrinfo(ip.c_str(), port + 1, nullptr, &addr_res)) {
                freeaddrinfo(addr_res);
                throw std::invalid_argument("Invalid ip4 address");
            }
            memset(&addr_storage, 0, sizeof(addr_storage));
            memcpy(&addr_storage, addr_res->ai_addr, addr_res->ai_addrlen);
            freeaddrinfo(addr_res);
        }
    }

    void internal_makeIP6_port(universal_address& addr_storage, const char* ip_port) {
        init_networking();
        if (ip_port[0] != '[')
            throw std::invalid_argument("Invalid ip6:port address");
        const char* port = strchr(ip_port, ']');
        if (!port)
            throw std::invalid_argument("Invalid ip6:port address");
        if (port[1] != ':')
            throw std::invalid_argument("Invalid ip6:port address");
        if (port[2] == 0)
            throw std::invalid_argument("Invalid ip6:port address");
        uint16_t port_num = (uint16_t)std::stoi(port + 2);


        if (ip_port == port - 1) {
            sockaddr_in6 addr6;
            memset(&addr6, 0, sizeof(addr6));
            addr6.sin6_family = AF_INET6;
            addr6.sin6_port = htons(port_num);
            memcpy(&addr_storage, &addr6, sizeof(addr6));
            return;
        }
        std::string ip(ip_port + 1, port);
        internal_makeIP6(addr_storage, ip.c_str(), port_num);
    }

    void internal_makeIP_port(universal_address& addr_storage, const char* ip_port) {
        if (ip_port[0] == '[')
            return internal_makeIP6_port(addr_storage, ip_port);
        else
            return internal_makeIP4_port(addr_storage, ip_port);
    }

    bool ipv6_supported() {
        if (!inited)
            init_networking();
        static int ipv6_supported = -1;
        if (ipv6_supported == -1) {
            ipv6_supported = 0;
            SOCKET sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
            if (sock != INVALID_SOCKET) {
                ipv6_supported = 1;
#ifdef _WIN32
                closesocket(sock);
#else
                close(sock);
#endif
            }
        }
        return ipv6_supported == 1;
    }
}


#endif /* SRC_NET_SHARED */
