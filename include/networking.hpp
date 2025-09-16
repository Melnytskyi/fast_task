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

namespace fast_task {
    namespace files {
        class file_handle;
    }

    namespace networking {
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

        class FT_API tcp_network_stream {
        public:
            virtual ~tcp_network_stream() noexcept(false) {};
            virtual std::span<char> read_available_ref() = 0;
            virtual int read_available(char* buffer, int buffer_len) = 0;
            virtual bool data_available() = 0;
            virtual void write(const char* data, size_t size) = 0;
            virtual bool write_file(char* path, size_t path_len, uint64_t data_len = 0, uint64_t offset = 0, uint32_t chunks_size = 0) = 0;
#ifdef _WIN64
            virtual bool write_file(void* fhandle, uint64_t data_len = 0, uint64_t offset = 0, uint32_t chunks_size = 0) = 0;
#else
            virtual bool write_file(int fhandle, uint64_t data_len = 0, uint64_t offset = 0, uint32_t chunks_size = 0) = 0;
#endif
            virtual void force_write() = 0;
            virtual void force_write_and_close(const char* data, size_t size) = 0;
            virtual void close() = 0;
            virtual void reset() = 0;
            virtual void rebuffer(int32_t new_size) = 0;
            virtual bool is_closed() = 0;
            virtual tcp_error error() = 0;
            virtual address local_address() = 0;
            virtual address remote_address() = 0;
        };

        class FT_API tcp_network_blocking {
        public:
            virtual ~tcp_network_blocking() noexcept(false) {};
            virtual std::vector<char> read(uint32_t len) = 0;
            virtual uint32_t available_bytes() = 0;
            virtual int64_t write(const char* data, uint32_t len) = 0;
            virtual bool write_file(char* path, size_t len, uint64_t data_len = 0, uint64_t offset = 0, uint32_t block_size = 0) = 0;
#ifdef _WIN64
            virtual bool write_file(void* fhandle, uint64_t data_len = 0, uint64_t offset = 0, uint32_t block_size = 0) = 0;
#else
            virtual bool write_file(int fhandle, uint64_t data_len = 0, uint64_t offset = 0, uint32_t block_size = 0) = 0;
#endif
            virtual void close() = 0;
            virtual void reset() = 0;
            virtual void rebuffer(int32_t new_size) = 0;
            virtual bool is_closed() = 0;
            virtual tcp_error error() = 0;
            virtual address local_address() = 0;
            virtual address remote_address() = 0;
        };

        class FT_API tcp_network_server {
            class tcp_network_manager* handle;

        public:
            tcp_network_server(std::function<void(tcp_network_blocking&)> on_connect, const address& ip_port, size_t acceptors = 10, const tcp_configuration& config = {});
            tcp_network_server(std::function<void(tcp_network_stream&)> on_connect, const address& ip_port, size_t acceptors = 10, const tcp_configuration& config = {});
            ~tcp_network_server();
            void start();
            void pause();
            void resume();
            void stop();
            tcp_network_blocking* accept_blocking(bool ignore_acceptors = false);
            tcp_network_stream* accept_stream(bool ignore_acceptors = false);
            void _await();

            bool is_running();
            bool is_paused();
            bool is_corrupted();

            uint16_t server_port();
            std::string server_ip();
            address server_address();
            //apply to new connections
            void set_configuration(const tcp_configuration& config);
            void set_accept_filter(std::function<bool(address& client, address& server)>&& filter);
        };

        class FT_API tcp_client_socket {
            class tcp_client_manager* handle;
            tcp_client_socket();

        public:
            ~tcp_client_socket();
            static tcp_client_socket* connect(const address& ip_port, const tcp_configuration& config = {});
            static tcp_client_socket* connect(const address& ip_port, char* data, uint32_t size, const tcp_configuration& config = {});
            //apply to current connection
            void set_configuration(const tcp_configuration& config);
            int32_t recv(uint8_t* data, int32_t size);
            bool send(uint8_t* data, int32_t size);
            bool send_file(const char* file_path, size_t file_path_len, uint64_t data_len, uint64_t offset, uint32_t chunks_size);
            bool send_file(class fast_task::files::file_handle& file_path, uint64_t data_len, uint64_t offset, uint32_t chunks_size);
            void close();
            void reset();
            void rebuffer(int32_t size);
        };

        struct FT_API udp_socket {
            class udp_handle* handle;
            udp_socket(const address& ip_port, uint32_t timeout_ms);
            ~udp_socket();

            uint32_t recv(uint8_t* data, uint32_t size, address& sender);
            uint32_t send(uint8_t* data, uint32_t size, address& to);

            address local_address();
            address remote_address();
        };

        uint8_t FT_API init_networking();
        void FT_API deinit_networking();
        bool FT_API ipv6_supported();
    }
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