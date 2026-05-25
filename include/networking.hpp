// Copyright Danyil Melnytskyi 2022-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_NETWORKING
#define FAST_TASK_NETWORKING
#include "shared.hpp"
#include "task.hpp"
#include <functional>
#include <span>

namespace fast_task::files {
    class file_handle;
}

namespace fast_task::networking {
    class FT_API address {
        void* data = nullptr;

        friend address to_address(void* addr);
        address(void* ip);

    public:
        static address any();
        static address any(uint16_t port);
        address();
        address(std::string_view ip_port);
        address(std::string_view ip, uint16_t port);
        address(const std::string& ip_port);
        address(const std::string& ip, uint16_t port);
        address(const address& ip);
        address(address&& ip);
        ~address();

        address& operator=(const address& ip);
        address& operator=(address&& ip);


        enum class family : uint8_t {
            none,
            ipv4,
            ipv6,
            other
        };
        family get_family() const;
        uint16_t port() const;

        std::string to_string() const;

        bool operator==(const address& other) const;
        bool operator!=(const address& other) const;

        void* get_data() const {
            return data;
        }

        bool is_loopback() const;

        static size_t data_size();
    };

    struct FT_API tcp_configuration {
        uint32_t recv_timeout_ms = 2000;
        uint32_t send_timeout_ms = 2000;
        uint32_t buffer_size = 8192;
        uint32_t fast_open_queue = 5; //0 - disable fast open

        uint32_t connection_timeout_ms = 2000; //set send_timeout_ms to this value when connecting to server, rollback to send_timeout_ms after connection, also start user space timeout when connecting
        //int32_t max_retransmit_count; is not portable across platforms

        bool allow_ip4 : 1 = true;
        bool enable_delay : 1 = true;      //TCP_NODELAY
        bool enable_timestamps : 1 = true; //TCP_TIMESTAMP, some websites report that enabling this option can cause performance spikes, turn off if you have problems
        bool enable_keep_alive : 1 = true;

        struct {
            uint32_t idle_ms = 5000;
            uint32_t interval_ms = 3000;
            uint8_t retry_count = 3;                                        //255 is max,0 - invalid value and will be replaced by 3
            uint32_t user_timeout_ms = idle_ms + interval_ms * retry_count; //not recommended to decrease this value
        } keep_alive_settings{};
    };

    enum class tcp_error : uint8_t {
        none = 0,
        remote_close = 1,
        local_close = 2,
        local_reset = 3,
        read_queue_overflow = 4,
        invalid_state = 5,
        undefined_error = 0xFF
    };

    enum class shutdown_mode : uint8_t {
        read,
        write,
        read_write
    };

    struct alignas(std::max_align_t) opaque_network_state {
        std::byte data[192];

        tcp_error get_error() const noexcept;
    };

    class FT_API tcp_socket {
        class manager;
        std::unique_ptr<manager> handle;

    public:
        tcp_socket();
        tcp_socket(tcp_socket&&);
        tcp_socket& operator=(tcp_socket&&);
        ~tcp_socket();

        static std::optional<tcp_socket> connect(const address& ip_port, const tcp_configuration& config = {});
        static std::optional<tcp_socket> connect(const address& ip_port, char* data, int32_t& size, const tcp_configuration& config = {});

        int32_t recv(std::span<char> data);
        int32_t send(std::span<const uint8_t> data);
        int32_t sendv(std::span<const std::span<const uint8_t>> data);
        int32_t send_file(const char* file_path, size_t file_path_len, uint32_t data_len, uint64_t offset, uint32_t chunks_size);
        int32_t send_file(class fast_task::files::file_handle& file_path, uint32_t data_len, uint64_t offset, uint32_t chunks_size);

        int32_t sendv_file(const std::span<const uint8_t> prefix, const std::span<const uint8_t> postfix, const char* file_path, size_t file_path_len, uint32_t data_len, uint64_t offset, uint32_t chunks_size);
        int32_t sendv_file(const std::span<const uint8_t> prefix, const std::span<const uint8_t> postfix, class fast_task::files::file_handle& file_path, uint32_t data_len, uint64_t offset, uint32_t chunks_size);

        void shutdown(shutdown_mode mode);
        void reset(); //TCP RST
        void close(); //shutdown + reset


        void set_configuration(const tcp_configuration& config);
        uint32_t available_bytes() const noexcept;
        bool is_open() const noexcept;
        address local_address() const noexcept;
        address remote_address() const noexcept;

        static bool enter_connect(const std::shared_ptr<task>& t, opaque_network_state& state, std::optional<tcp_socket>& res, const address& ip_port, const tcp_configuration& config = {});
        static bool enter_connect(const std::shared_ptr<task>& t, opaque_network_state& state, std::optional<tcp_socket>& res, const address& ip_port, char* data, int32_t& size, const tcp_configuration& config = {});

        bool enter_recv(const std::shared_ptr<task>& t, opaque_network_state& state, int32_t& bytes_read, std::span<char> data);
        bool enter_send(const std::shared_ptr<task>& t, opaque_network_state& state, int32_t& bytes_sent, std::span<const uint8_t> data);
        bool enter_sendv(const std::shared_ptr<task>& t, opaque_network_state& state, int32_t& bytes_sent, std::span<const std::span<const uint8_t>> data);
        bool enter_send_file(const std::shared_ptr<task>& t, opaque_network_state& state, int32_t& bytes_sent, const char* file_path, size_t file_path_len, uint32_t data_len, uint64_t offset, uint32_t chunks_size);
        bool enter_send_file(const std::shared_ptr<task>& t, opaque_network_state& state, int32_t& bytes_sent, class fast_task::files::file_handle& file_path, uint32_t data_len, uint64_t offset, uint32_t chunks_size);

        bool enter_sendv_file(const std::shared_ptr<task>& t, opaque_network_state& state, int32_t& bytes_sent, const std::span<const uint8_t> prefix, const std::span<const uint8_t> postfix, const char* file_path, size_t file_path_len, uint32_t data_len, uint64_t offset, uint32_t chunks_size);
        bool enter_sendv_file(const std::shared_ptr<task>& t, opaque_network_state& state, int32_t& bytes_sent, const std::span<const uint8_t> prefix, const std::span<const uint8_t> postfix, class fast_task::files::file_handle& file_path, uint32_t data_len, uint64_t offset, uint32_t chunks_size);

        bool enter_shutdown(const std::shared_ptr<task>& t, opaque_network_state& state, shutdown_mode mode);
        bool enter_reset(const std::shared_ptr<task>& t, opaque_network_state& state); //TCP RST
        bool enter_close(const std::shared_ptr<task>& t, opaque_network_state& state); //shutdown + reset
    };

    class FT_API tcp_listener {
        class manager;
        std::unique_ptr<manager> handle;

    public:
        tcp_listener();
        tcp_listener(tcp_listener&&);
        tcp_listener& operator=(tcp_listener&&);
        ~tcp_listener();

        static tcp_listener bind(const address& ip_port, const tcp_configuration& config = {});

        std::optional<tcp_socket> accept();
        bool enter_accept(const std::shared_ptr<task>& t, opaque_network_state& state, std::optional<tcp_socket>& res);

        void close();
        bool is_open() const noexcept;
        bool enter_close(const std::shared_ptr<task>& t, opaque_network_state& state);
    };

    class FT_API udp_socket {
        class udp_handle* handle;

    public:
        udp_socket(const address& ip_port, uint32_t timeout_ms);
        ~udp_socket();

        uint32_t recv(std::span<uint8_t> data, address& sender);
        uint32_t send(std::span<const uint8_t> data, address& to);

        address local_address();
        address remote_address();

        bool enter_recv(const std::shared_ptr<task>& t, opaque_network_state& state, uint32_t& bytes_read, std::span<uint8_t> data, address& sender);
        bool enter_send(const std::shared_ptr<task>& t, opaque_network_state& state, uint32_t& bytes_sent, std::span<const uint8_t> data, address& to);
    };

    uint8_t FT_API init_networking();
    void FT_API deinit_networking();
    bool FT_API ipv6_supported();
}

namespace std {
    template <>
    struct FT_API hash<fast_task::networking::address> {
        size_t operator()(const fast_task::networking::address& addr) const {
            std::string_view data{(char*)addr.get_data(), addr.data_size()};
            return std::hash<std::string_view>()(data);
        }
    };
}
#endif