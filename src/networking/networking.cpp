// Copyright Danyil Melnytskyi 2022-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

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
    #include <netinet/tcp.h>
    #include <sys/ioctl.h>
    #include <sys/mman.h>
#endif

#include <condition_variable>
#include <files/files.hpp>
#include <filesystem>
#include <networking/networking.hpp>
#include <tasks/util/native_workers_singleton.hpp>
#include <variant>

namespace fast_task::networking {
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
            if (auto res = getaddrinfo(ip, port_.c_str(), nullptr, &addr_res)) {
                freeaddrinfo(addr_res);
                throw std::invalid_argument("Invalid ip address");
            }
            auto& res = *addr_res;
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
            if (auto res = getaddrinfo(ip.c_str(), port + 1, nullptr, &addr_res)) {
                freeaddrinfo(addr_res);
                throw std::invalid_argument("Invalid ip4 address");
            }
            auto& res = *addr_res;
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

    address address::any() {
        address res;
        internal_makeIP(*(universal_address*)res.data, "[::]", 0);
        return res;
    }

    address address::any(uint16_t port) {
        address res;
        internal_makeIP(*(universal_address*)res.data, "[::]", port);
        return res;
    }

    address::address(void* ip) {
        if (ip) {
            data = new universal_address();
            memcpy(data, ip, sizeof(universal_address));
        }
    }

    address::address() {
        data = nullptr;
    }

    address::address(std::string_view ip_port) {
        data = new universal_address();
        if (ip_port.empty())
            ip_port = "[::]:0";
        internal_makeIP_port(*((universal_address*)data), ip_port.data());
    }

    address::address(std::string_view ip, uint16_t port) {
        data = new universal_address();
        if (ip.empty())
            ip = "[::]";
        internal_makeIP(*((universal_address*)data), ip.data(), port);
    }

    address::address(const std::string& ip_port) : address(std::string_view(ip_port)) {}

    address::address(const std::string& ip, uint16_t port) : address(std::string_view(ip), port) {}

    address::address(const address& ip) {
        data = new universal_address(*((universal_address*)ip.data));
    }

    address::address(address&& ip) {
        data = ip.data;
        ip.data = nullptr;
    }

    address::~address() {
        if (data != nullptr)
            delete (universal_address*)data;
    }

    address& address::operator=(const address& ip) {
        if (data != nullptr)
            delete (universal_address*)data;
        data = new universal_address(*((universal_address*)ip.data));
        return *this;
    }

    address& address::operator=(address&& ip) {
        if (data != nullptr)
            delete (universal_address*)data;
        data = ip.data;
        ip.data = nullptr;
        return *this;
    }

    address::family address::get_family() const {
        if (data == nullptr)
            return family::none;
        universal_address* addr = (universal_address*)data;
        if (addr->ss_family == AF_INET)
            return family::ipv4;
        else if (addr->ss_family == AF_INET6)
            return family::ipv6;
        else
            return family::other;
    }

    uint16_t address::port() const {
        if (data == nullptr)
            return 0;
        universal_address* addr = (universal_address*)data;
        if (addr->ss_family == AF_INET) {
            return ntohs(((sockaddr_in*)addr)->sin_port);
        } else if (addr->ss_family == AF_INET6) {
            return ntohs(((sockaddr_in6*)addr)->sin6_port);
        } else
            return 0;
    }

    std::string address::to_string() const {
        if (data == nullptr)
            return "";
        universal_address* addr = (universal_address*)data;
        static constexpr size_t addr_len = (INET6_ADDRSTRLEN > INET_ADDRSTRLEN ? INET6_ADDRSTRLEN : INET_ADDRSTRLEN) + 1;
        std::string res;
        char str[addr_len] = {'\0'};
        switch (addr->ss_family) {
        case AF_INET: {
            struct sockaddr_in* addr_in = (struct sockaddr_in*)addr;
            inet_ntop(AF_INET, &(addr_in->sin_addr), str, INET_ADDRSTRLEN);
            res = std::string(str) + ":" + std::to_string(ntohs(addr_in->sin_port));
            break;
        }
        case AF_INET6: {
            struct sockaddr_in6* addr_in6 = (struct sockaddr_in6*)addr;
            inet_ntop(AF_INET6, &(addr_in6->sin6_addr), str, INET6_ADDRSTRLEN);
            res = "[" + std::string(str) + "]:" + std::to_string(ntohs(addr_in6->sin6_port));
            break;
        }
        default:
            break;
        }
        return res;
    }

    bool address::operator==(const address& other) const {
        if (data == nullptr || other.data == nullptr)
            return false;
        return memcmp(data, other.data, sizeof(universal_address)) == 0;
    }

    bool address::operator!=(const address& other) const {
        return !(*this == other);
    }

    bool address::is_loopback() const {
        if (data == nullptr)
            return false;
        universal_address* addr = (universal_address*)data;
        switch (addr->ss_family) {
        case AF_INET:
            return ((sockaddr_in*)addr)->sin_addr.s_addr == htonl(INADDR_LOOPBACK);
        case AF_INET6: {
            auto& tmp = ((sockaddr_in6*)addr)->sin6_addr;
            if (IN6_IS_ADDR_V4MAPPED(&tmp)) {
                char* p = (char*)(&tmp);
                return p[12] == 127 && p[13] == 0 && p[14] == 0 && p[15] == 1;
            } else
                return IN6_IS_ADDR_LOOPBACK(&tmp);
        }
        default:
            break;
        }
        return false;
    }

    size_t address::data_size() {
        return sizeof(universal_address);
    }

    address to_address(void* addr) {
        return address(addr);
    }

    address to_address(universal_address& addr) {
        return to_address(&addr);
    }

    universal_address& from_address(const address& addr) {
        return *(universal_address*)addr.get_data();
    }
}

namespace fast_task::networking {
#if _WIN64
    bool inited = false;

    ::LPFN_ACCEPTEX _AcceptEx;
    ::LPFN_GETACCEPTEXSOCKADDRS _GetAcceptExSockaddrs;
    ::LPFN_CONNECTEX _ConnectEx;
    ::LPFN_TRANSMITFILE _TransmitFile;
    ::LPFN_DISCONNECTEX _DisconnectEx;
    ::WSADATA wsaData;

    void init_win_fns(SOCKET sock) {
        static bool inited = false;
        if (inited)
            return;
        ::GUID GuidAcceptEx = WSAID_ACCEPTEX;
        ::GUID GuidGetAcceptExSockaddrs = WSAID_GETACCEPTEXSOCKADDRS;
        ::GUID GuidConnectEx = WSAID_CONNECTEX;
        ::GUID GuidTransmitFile = WSAID_TRANSMITFILE;
        ::GUID GuidDisconnectEx = WSAID_DISCONNECTEX;
        ::DWORD dwBytes = 0;

        if (SOCKET_ERROR == ::WSAIoctl(sock, SIO_GET_EXTENSION_FUNCTION_POINTER, &GuidAcceptEx, sizeof(GuidAcceptEx), &_AcceptEx, sizeof(_AcceptEx), &dwBytes, NULL, NULL))
            throw std::runtime_error("WSAIoctl failed get AcceptEx");
        if (SOCKET_ERROR == ::WSAIoctl(sock, SIO_GET_EXTENSION_FUNCTION_POINTER, &GuidGetAcceptExSockaddrs, sizeof(GuidGetAcceptExSockaddrs), &_GetAcceptExSockaddrs, sizeof(_GetAcceptExSockaddrs), &dwBytes, NULL, NULL))
            throw std::runtime_error("WSAIoctl failed get GetAcceptExSockaddrs");
        if (SOCKET_ERROR == ::WSAIoctl(sock, SIO_GET_EXTENSION_FUNCTION_POINTER, &GuidConnectEx, sizeof(GuidConnectEx), &_ConnectEx, sizeof(_ConnectEx), &dwBytes, NULL, NULL))
            throw std::runtime_error("WSAIoctl failed get ConnectEx");
        if (SOCKET_ERROR == ::WSAIoctl(sock, SIO_GET_EXTENSION_FUNCTION_POINTER, &GuidTransmitFile, sizeof(GuidTransmitFile), &_TransmitFile, sizeof(_TransmitFile), &dwBytes, NULL, NULL))
            throw std::runtime_error("WSAIoctl failed get TransmitFile");
        if (SOCKET_ERROR == ::WSAIoctl(sock, SIO_GET_EXTENSION_FUNCTION_POINTER, &GuidDisconnectEx, sizeof(GuidDisconnectEx), &_DisconnectEx, sizeof(_DisconnectEx), &dwBytes, NULL, NULL))
            throw std::runtime_error("WSAIoctl failed get DisconnectEx");


        inited = true;
    }

    #pragma region TCP

    struct tcp_handle : public util::native_worker_handle {
        std::list<std::tuple<char*, size_t>> write_queue;
        std::list<std::tuple<char*, size_t>> read_queue;
        task_condition_variable cv;
        task_mutex cv_mutex;
        ::SOCKET socket;
        ::WSABUF buffer;
        char* data;
        int total_bytes;
        int sent_bytes;
        int readed_bytes;
        int data_len;
        bool force_mode;
        bool is_bound = false;
        uint32_t max_read_queue_size;
        TcpError invalid_reason = TcpError::none;
        enum class Opcode : uint8_t {
            HALT,
            ACCEPT,
            READ,
            WRITE,
            TRANSMIT_FILE,
            INTERNAL_READ,
            INTERNAL_CLOSE,
            FINISH
        } opcode = Opcode::ACCEPT;

        tcp_handle(SOCKET socket, int32_t buffer_len, util::native_worker_manager* manager, uint32_t read_queue_size = 10)
            : socket(socket), util::native_worker_handle(manager), max_read_queue_size(read_queue_size) {
            if (buffer_len < 0)
                throw std::invalid_argument("buffer_len must be positive");
            data = new char[buffer_len];
            buffer.buf = data;
            buffer.len = buffer_len;
            data_len = buffer_len;
            total_bytes = 0;
            sent_bytes = 0;
            readed_bytes = 0;
            force_mode = false;
        }

        ~tcp_handle() {
            close();
        }

        uint32_t available_bytes() {
            if (!data)
                return 0;
            if (readed_bytes)
                return true;
            DWORD value = 0;
            int result = ::ioctlsocket(socket, FIONREAD, &value);
            if (result == SOCKET_ERROR)
                return 0;
            else
                return value;
        }

        bool data_available() {
            return available_bytes() > 0;
        }

        void send_data(const char* data, int len) {
            if (!data)
                return;
            char* new_data = new char[len];
            memcpy(new_data, data, len);
            write_queue.push_back(std::make_tuple(new_data, len));
        }

        //async
        bool send_queue_item() {
            if (!data)
                return false;
            if (write_queue.empty())
                return false;
            auto item = write_queue.front();
            write_queue.pop_front();
            auto& send_data = std::get<0>(item);
            auto& val_len = std::get<1>(item);
            std::unique_ptr<char[]> send_data_ptr(send_data);
            //set buffer
            buffer.len = data_len;
            buffer.buf = data;
            while (val_len) {
                size_t to_sent_bytes = val_len > data_len ? data_len : val_len;
                memcpy(data, send_data, to_sent_bytes);
                buffer.len = to_sent_bytes;
                buffer.buf = data;
                if (!send_await()) {
                    return false;
                }
                if (val_len < sent_bytes)
                    return true;
                val_len -= sent_bytes;
                send_data += sent_bytes;
            }
            return true;
        }

        void read_force(uint32_t buffer_len, char* buffer) {
            if (!data)
                return;
            if (!buffer_len)
                return;
            if (!buffer)
                return;
            while (buffer_len) {
                int readed = 0;
                read_available(buffer, buffer_len, readed);
                buffer += readed;
                if (readed > buffer_len)
                    return;
                buffer_len -= readed;
            }
        }

        int64_t write_force(const char* to_write, uint32_t to_write_len) {
            if (!data)
                return -1;
            if (!to_write_len)
                return -1;
            if (!to_write)
                return -1;

            force_mode = true;
            if (data_len < to_write_len) {
                buffer.len = data_len;
                buffer.buf = this->data;
                if (!send_await())
                    return -1;
                force_mode = false;
                return sent_bytes;
            } else {
                buffer.len = to_write_len;
                buffer.buf = this->data;
                memcpy(this->data, to_write, to_write_len);
                if (!send_await())
                    return -1;
                force_mode = false;
                return sent_bytes;
            }
        }

        void read_data() {
            if (!data)
                return;
            if (read_queue.empty()) {
                mutex_unify mutex(cv_mutex);
                std::unique_lock<mutex_unify> lock(mutex);
                opcode = Opcode::READ;

                if ((SOCKET_ERROR == read())) {
                    lock.unlock();
                    if (handle_error())
                        lock.lock();
                    else
                        return;
                }

                cv.wait(lock);
                opcode = Opcode::HALT;
            } else {
                auto item = read_queue.front();
                read_queue.pop_front();
                auto& read_data = std::get<0>(item);
                auto& val_len = std::get<1>(item);
                std::unique_ptr<char[]> read_data_ptr(read_data);
                buffer.buf = data;
                buffer.len = data_len;
                readed_bytes = val_len;
                memcpy(data, read_data, val_len);
            }
        }

        void read_available_no_block(char* extern_buffer, int buffer_len, int& readed) {
            if (!readed_bytes)
                readed = 0;
            else if (readed_bytes < buffer_len) {
                readed = readed_bytes;
                memcpy(extern_buffer, data, readed_bytes);
                readed_bytes = 0;
            } else {
                readed = buffer_len;
                memcpy(extern_buffer, buffer.buf, buffer_len);
                readed_bytes -= buffer_len;
                buffer.buf += buffer_len;
                buffer.len -= buffer_len;
            }
        }

        void read_available(char* extern_buffer, int buffer_len, int& readed) {
            if (!readed_bytes)
                read_data();
            if (readed_bytes < buffer_len) {
                readed = readed_bytes;
                memcpy(extern_buffer, data, readed_bytes);
                readed_bytes = 0;
            } else {
                readed = buffer_len;
                memcpy(extern_buffer, buffer.buf, buffer_len);
                readed_bytes -= buffer_len;
                buffer.buf += buffer_len;
                buffer.len -= buffer_len;
            }
        }

        char* read_available_no_copy(int& readed) {
            if (!readed_bytes)
                read_data();
            readed = readed_bytes;
            readed_bytes = 0;
            return data;
        }

        void close(TcpError err = TcpError::local_close) {
            if (!data)
                return;
            pre_close(err);
            internal_close();
        }

        void handle(unsigned long dwBytesTransferred) {
            DWORD flags = 0, bytes = 0;
            if (!data) {
                if (opcode != Opcode::INTERNAL_CLOSE)
                    return;
            }
            mutex_unify mutex(cv_mutex);
            std::unique_lock<mutex_unify> lock(mutex);
            switch (opcode) {
            case Opcode::READ: {
                readed_bytes = dwBytesTransferred;
                cv.notify_all();
                break;
            }
            case Opcode::WRITE:
                sent_bytes += dwBytesTransferred;
                if (sent_bytes < total_bytes) {
                    buffer.buf = data + sent_bytes;
                    buffer.len = total_bytes - sent_bytes;
                    if (!data_available()) {
                        if (!send())
                            cv.notify_all();
                    } else {
                        char* data = new char[buffer.len];
                        memcpy(data, buffer.buf, buffer.len);
                        write_queue.push_front(std::make_tuple(data, buffer.len));
                        if (force_mode) {
                            opcode = Opcode::INTERNAL_READ;
                            if ((SOCKET_ERROR == read())) {
                                lock.unlock();
                                handle_error();
                                lock.lock();
                            }
                        } else
                            cv.notify_all();
                    }
                } else
                    cv.notify_all();
                break;
            case Opcode::TRANSMIT_FILE:
                cv.notify_all();
                break;
            case Opcode::INTERNAL_READ:
                if (dwBytesTransferred) {
                    char* buffer = new char[dwBytesTransferred];
                    memcpy(buffer, data, dwBytesTransferred);
                    read_queue.push_back(std::make_tuple(buffer, dwBytesTransferred));
                }
                if (!data_available()) {
                    if (read_queue.size() > max_read_queue_size)
                        close(TcpError::read_queue_overflow);
                    else if (SOCKET_ERROR == read()) {
                        lock.unlock();
                        handle_error();
                        lock.lock();
                    }
                } else {
                    if (write_queue.empty())
                        close(TcpError::invalid_state);
                    else {
                        auto item = write_queue.front();
                        write_queue.pop_front();
                        auto& write_data = std::get<0>(item);
                        auto& val_len = std::get<1>(item);
                        memcpy(data, write_data, val_len);
                        delete[] write_data;
                        buffer.buf = data;
                        buffer.len = val_len;
                        if (!send())
                            cv.notify_all();
                    }
                }
                break;
            case Opcode::INTERNAL_CLOSE:
                closesocket(socket);
                socket = INVALID_SOCKET;
                cv.notify_all();
                break;
            default:
                break;
            }
            opcode = Opcode::FINISH;
        }

        void send_and_close(const char* data, int len) {
            if (!data)
                return;
            buffer.len = data_len;
            buffer.buf = this->data;
            write_queue = {};
            force_mode = true;
            while (data_len < len) {
                memcpy(buffer.buf, data, buffer.len);
                if (!send_await())
                    return;
                data += buffer.len;
                len -= buffer.len;
            }
            if (len) {
                //send last part of data and close
                memcpy(buffer.buf, data, len);
                buffer.len = len;
                send_await();
            }
            force_mode = false;
            close();
        }

        bool send_file(void* file, uint64_t data_len, uint64_t offset, uint32_t chunks_size) {
            if (!data)
                return false;
            if (chunks_size == 0)
                chunks_size = 0x1000;
            if (data_len == 0) {
                LARGE_INTEGER file_size;
                if (!GetFileSizeEx(file, &file_size))
                    return false;
                data_len = file_size.QuadPart;
                if (offset > data_len)
                    return false;
                data_len -= offset;
            }

            if (data_len > 0x7FFFFFFE) {
                //send file in chunks using TransmitFile
                uint64_t sended = 0;
                uint64_t blocks = data_len / 0x7FFFFFFE;
                uint64_t last_block = data_len % blocks;

                while (blocks--)
                    if (!transfer_file(socket, file, 0x7FFFFFFE, chunks_size, sended + offset))
                        return false;
                    else
                        sended += 0x7FFFFFFE;


                if (last_block)
                    if (!transfer_file(socket, file, last_block, chunks_size, sended + offset))
                        return false;
            } else {
                if (!transfer_file(socket, file, data_len, chunks_size, offset))
                    return false;
            }
            return true;
        }

        bool send_file(const char* path, size_t path_len, uint64_t data_len, uint64_t offset, uint32_t chunks_size) {
            if (!data)
                return false;
            auto wpath = std::filesystem::path(path, path + path_len).wstring();
            HANDLE file = CreateFileW(wpath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
            if (!file)
                return false;
            bool result;
            try {
                result = send_file(file, data_len, offset, chunks_size);
            } catch (...) {
                CloseHandle(file);
                throw;
            }
            CloseHandle(file);
            return result;
        }

        bool valid() {
            return data != nullptr;
        }

        void reset() {
            if (!data)
                return;
            pre_close(TcpError::local_reset);
            closesocket(socket); //with iocp socket not send everything and cancel all operations
        }

        void connection_reset() {
            if (opcode != Opcode::HALT) {
                mutex_unify mutex(cv_mutex);
                std::unique_lock<mutex_unify> lock(mutex);
                data = nullptr;
                invalid_reason = TcpError::remote_close;
                readed_bytes = 0;
                cv.notify_all();
            } else {
                mutex_unify mutex(cv_mutex);
                std::unique_lock<mutex_unify> lock(mutex);
                data = nullptr;
                invalid_reason = TcpError::remote_close;
                readed_bytes = 0;
                cv.notify_all();
                lock.unlock();
                internal_close();
            }
        }

        void rebuffer(int32_t buffer_len) {
            if (!data)
                return;
            if (buffer_len < 0)
                throw std::invalid_argument("buffer_len must be positive");
            if (buffer_len == 0)
                buffer_len = 0x1000;
            if (buffer_len == data_len)
                return;
            char* new_data = new char[buffer_len];
            delete[] data;
            data = new_data;
            data_len = buffer_len;
        }

    private:
        void pre_close(TcpError err) {
            mutex_unify mutex(cv_mutex);
            std::unique_lock<mutex_unify> lock(mutex);
            std::list<std::tuple<char*, size_t>> clear_write_queue;
            std::list<std::tuple<char*, size_t>> clear_read_queue;
            if (opcode != Opcode::FINISH && opcode != Opcode::ACCEPT && opcode != Opcode::HALT)
                cv.wait(lock);
            readed_bytes = 0;
            sent_bytes = 0;
            delete[] data;
            data = nullptr;
            invalid_reason = err;
            write_queue.swap(clear_write_queue);
            read_queue.swap(clear_read_queue);
            cv.notify_all();

            lock.unlock();
            for (auto& item : clear_write_queue)
                delete[] std::get<0>(item);
            for (auto& item : clear_read_queue)
                delete[] std::get<0>(item);
        }

        void internal_close() {
            mutex_unify mutex(cv_mutex);
            std::unique_lock<mutex_unify> lock(mutex);
            opcode = Opcode::INTERNAL_CLOSE;
            shutdown(socket, SD_BOTH);
            if (!_DisconnectEx(socket, &overlapped, TF_REUSE_SOCKET, 0)) {
                if (WSAGetLastError() != ERROR_IO_PENDING)
                    invalid_reason = TcpError::local_close;
                cv.wait(lock);
            }
            closesocket(socket);
            opcode = Opcode::HALT;
        }

        bool handle_error() {
            auto error = WSAGetLastError();
            if (WSA_IO_PENDING == error)
                return true;
            else {
                switch (error) {
                case WSAECONNRESET:
                    invalid_reason = TcpError::remote_close;
                    break;
                case WSAECONNABORTED:
                case WSA_OPERATION_ABORTED:
                case WSAENETRESET:
                    invalid_reason = TcpError::local_close;
                    break;
                case WSAEWOULDBLOCK:
                    return false; //try later
                default:
                    invalid_reason = TcpError::undefined_error;
                    break;
                }
                close();
                return false;
            }
        }

        int read() {
            DWORD flags = 0;
            buffer.buf = this->data;
            buffer.len = data_len;
            return WSARecv(socket, &buffer, 1, NULL, &flags, &overlapped, NULL);
        }

        bool send() {
            DWORD flags = 0;
            opcode = Opcode::WRITE;
            int result = WSASend(socket, &buffer, 1, NULL, flags, &overlapped, NULL);
            if ((SOCKET_ERROR == result)) {
                opcode = Opcode::HALT;
                return handle_error();
            }
            return true;
        }

        bool send_await() {
            mutex_unify mutex(cv_mutex);
            std::unique_lock<mutex_unify> lock(mutex);
            if (!send())
                return false;
            cv.wait(lock);
            opcode = Opcode::HALT;
            return data; //if data is null, then socket is closed
        }

        bool transfer_file(SOCKET sock, HANDLE FILE, uint32_t block, uint32_t chunks_size, uint64_t offset) {
            mutex_unify mutex(cv_mutex);
            std::unique_lock<mutex_unify> lock(mutex);
            overlapped.Offset = offset & 0xFFFFFFFF;
            overlapped.OffsetHigh = offset >> 32;
            opcode = Opcode::TRANSMIT_FILE;
            bool res = _TransmitFile(sock, FILE, block, chunks_size, &overlapped, NULL, TF_USE_KERNEL_APC | TF_WRITE_BEHIND);
            if (!res && WSAGetLastError() != WSA_IO_PENDING)
                res = false;
            cv.wait(lock);
            opcode = Opcode::HALT;
            return res;
        }
    };

    #pragma region TcpNetworkStream

    class TcpNetworkStreamImpl : public TcpNetworkStream {
        friend class TcpNetworkManager;
        struct tcp_handle* handle;
        task_mutex mutex;
        TcpError last_error;

        bool checkup() {
            if (!handle)
                return false;
            if (!handle->valid()) {
                last_error = handle->invalid_reason;
                delete handle;
                handle = nullptr;
                return false;
            }
            return true;
        }

    public:
        TcpNetworkStreamImpl(tcp_handle* handle)
            : handle(handle), last_error(TcpError::none) {}

        ~TcpNetworkStreamImpl() override {
            if (handle) {
                std::lock_guard lg(mutex);
                handle->close();
                delete handle;
            }
            handle = nullptr;
        }

        std::span<char> read_available_ref() override {
            std::lock_guard lg(mutex);
            if (!handle)
                return {};
            while (!handle->data_available()) {
                if (!handle->send_queue_item())
                    break;
            }
            if (!checkup())
                return {};
            int readed = 0;
            char* data = handle->read_available_no_copy(readed);
            return {data, (size_t)readed};
        }

        int read_available(char* buffer, int buffer_len) override {
            std::lock_guard lg(mutex);
            if (!handle)
                return 0;
            while (!handle->data_available()) {
                if (!handle->send_queue_item())
                    break;
            }

            if (!checkup())
                return (uint32_t)0;
            int readed = 0;
            handle->read_available(buffer, buffer_len, readed);
            return readed;
        }

        bool data_available() override {
            std::lock_guard lg(mutex);
            if (handle)
                return handle->data_available();
            return false;
        }

        void write(const char* data, size_t size) override {
            std::lock_guard lg(mutex);
            if (handle) {
                handle->send_data(data, size);
                while (!handle->data_available()) {
                    if (!handle->send_queue_item())
                        break;
                }
                checkup();
            }
        }

        bool write_file(char* path, size_t path_len, uint64_t data_len, uint64_t offset, uint32_t chunks_size) override {
            std::lock_guard lg(mutex);
            if (handle) {
                while (handle->valid())
                    if (!handle->send_queue_item())
                        break;

                if (!checkup())
                    return false;

                return handle->send_file(path, path_len, data_len, offset, chunks_size);
            }
            return false;
        }

        bool write_file(void* fhandle, uint64_t data_len, uint64_t offset, uint32_t chunks_size) override {
            std::lock_guard lg(mutex);
            if (handle) {
                while (handle->valid())
                    if (!handle->send_queue_item())
                        break;
                if (!checkup())
                    return false;
                return handle->send_file(fhandle, data_len, offset, chunks_size);
            }
            return false;
        }

        //write all data from write_queue
        void force_write() override {
            std::lock_guard lg(mutex);
            if (handle) {
                while (handle->valid())
                    if (!handle->send_queue_item())
                        break;
                checkup();
            }
        }

        void force_write_and_close(const char* data, size_t size) override {
            std::lock_guard lg(mutex);
            if (handle) {
                handle->send_and_close(data, size);
                last_error = handle->invalid_reason;
                delete handle;
            }
            handle = nullptr;
        }

        void close() override {
            std::lock_guard lg(mutex);
            if (handle) {
                handle->close();
                last_error = handle->invalid_reason;
                delete handle;
            }
            handle = nullptr;
        }

        void reset() override {
            std::lock_guard lg(mutex);
            if (handle) {
                handle->reset();
                last_error = handle->invalid_reason;
                delete handle;
            }
            handle = nullptr;
        }

        void rebuffer(int32_t new_size) override {
            std::lock_guard lg(mutex);
            if (handle)
                handle->rebuffer(new_size);
        }

        bool is_closed() override {
            std::lock_guard lg(mutex);
            if (handle) {
                bool res = handle->valid();
                if (!res) {
                    delete handle;
                    handle = nullptr;
                }
                return !res;
            }
            return true;
        }

        TcpError error() override {
            std::lock_guard lg(mutex);
            if (handle)
                return handle->invalid_reason;
            return last_error;
        }

        address local_address() override {
            std::lock_guard lg(mutex);
            if (!handle)
                return {};
            universal_address addr;
            int socklen = sizeof(universal_address);
            if (getsockname(handle->socket, (sockaddr*)&addr, &socklen) == -1)
                return {};
            return to_address(addr);
        }

        address remote_address() override {
            std::lock_guard lg(mutex);
            if (!handle)
                return {};
            universal_address addr;
            int socklen = sizeof(universal_address);
            if (getpeername(handle->socket, (sockaddr*)&addr, &socklen) == -1)
                return {};
            return to_address(addr);
        }
    };

    #pragma endregion

    #pragma region TcpNetworkBlocking

    class TcpNetworkBlockingImpl : public TcpNetworkBlocking {
        friend class TcpNetworkManager;
        tcp_handle* handle;
        task_mutex mutex;
        TcpError last_error;

        bool checkup() {
            if (!handle)
                return false;
            if (!handle->valid()) {
                last_error = handle->invalid_reason;
                delete handle;
                handle = nullptr;
                return false;
            }
            return true;
        }

    public:
        TcpNetworkBlockingImpl(tcp_handle* handle)
            : handle(handle), last_error(TcpError::none) {}

        ~TcpNetworkBlockingImpl() override {
            std::lock_guard lg(mutex);
            if (handle)
                delete handle;
            handle = nullptr;
        }

        std::vector<char> read(uint32_t len) override {
            std::lock_guard lg(mutex);
            if (handle) {
                if (!checkup())
                    return {};
                std::vector<char> buf;
                buf.resize(len);
                handle->read_force(len, buf.data());
                if (len == 0)
                    return {};
                else
                    buf.resize(len);
                return buf;
            }
            return {};
        }

        uint32_t available_bytes() override {
            std::lock_guard lg(mutex);
            if (handle)
                return handle->available_bytes();
            return 0ui32;
        }

        int64_t write(const char* data, uint32_t len) override {
            std::lock_guard lg(mutex);
            if (handle) {
                if (!checkup())
                    return 0;
                return handle->write_force(data, len);
            }
            return 0;
        }

        bool write_file(char* path, size_t len, uint64_t data_len, uint64_t offset, uint32_t block_size) override {
            std::lock_guard lg(mutex);
            if (handle) {
                if (!checkup())
                    return false;
                return handle->send_file(path, len, data_len, offset, block_size);
            }
            return false;
        }

        bool write_file(void* fhandle, uint64_t data_len, uint64_t offset, uint32_t block_size) override {
            std::lock_guard lg(mutex);
            if (handle) {
                if (!checkup())
                    return false;
                return handle->send_file(fhandle, data_len, offset, block_size);
            }
            return false;
        }

        void close() override {
            std::lock_guard lg(mutex);
            if (handle) {
                handle->close();
                last_error = handle->invalid_reason;
                delete handle;
                handle = nullptr;
            }
        }

        void reset() override {
            std::lock_guard lg(mutex);
            if (handle) {
                handle->reset();
                last_error = handle->invalid_reason;
                delete handle;
                handle = nullptr;
            }
        }

        void rebuffer(size_t new_size) override {
            std::lock_guard lg(mutex);
            if (handle)
                handle->rebuffer(new_size);
        }

        bool is_closed() override {
            std::lock_guard lg(mutex);
            if (handle) {
                bool res = handle->valid();
                if (!res) {
                    last_error = handle->invalid_reason;
                    delete handle;
                    handle = nullptr;
                }
                return !res;
            }
            return true;
        }

        TcpError error() override {
            std::lock_guard lg(mutex);
            if (handle)
                return handle->invalid_reason;
            return last_error;
        }

        address local_address() override {
            std::lock_guard lg(mutex);
            if (!handle)
                return {};
            universal_address addr;
            int socklen = sizeof(universal_address);
            if (getsockname(handle->socket, (sockaddr*)&addr, &socklen) == -1)
                return {};
            return to_address(addr);
        }

        address remote_address() override {
            std::lock_guard lg(mutex);
            if (!handle)
                return {};
            universal_address addr;
            int socklen = sizeof(universal_address);
            if (getpeername(handle->socket, (sockaddr*)&addr, &socklen) == -1)
                return {};
            return to_address(addr);
        }
    };

    #pragma endregion

    class TcpNetworkManager : public util::native_worker_manager {
        task_mutex safety;
        std::variant<std::function<void(TcpNetworkBlocking&)>, std::function<void(TcpNetworkStream&)>> handler_fn;
        std::function<bool(address& client, address& server)> accept_filter;
        address _address;
        SOCKET main_socket;
        int timeout_ms;

    public:
        TcpConfiguration config;

    private:
        bool allow_new_connections = false;
        bool disabled = true;
        bool corrupted = false;
        size_t acceptors;
        task_condition_variable state_changed_cv;

        void make_acceptEx(tcp_handle* pClientContext) {
        re_try:
            static const auto address_len = sizeof(sockaddr_storage) + 16;
            auto new_sock = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
            pClientContext->socket = new_sock;
            pClientContext->opcode = tcp_handle::Opcode::ACCEPT;
            BOOL success = _AcceptEx(
                main_socket,
                new_sock,
                pClientContext->buffer.buf,
                0,
                address_len,
                address_len,
                nullptr,
                &pClientContext->overlapped
            );
            if (success != TRUE) {
                auto err = WSAGetLastError();
                if (err == WSA_IO_PENDING)
                    return;
                else if (err == WSAECONNRESET) {
                    closesocket(new_sock);
                    goto re_try;
                } else {
                    closesocket(new_sock);
                    return;
                }
            }
        }

        void make_acceptEx(void) {
            tcp_handle* pClientContext = new tcp_handle(0, config.buffer_size, this);
            make_acceptEx(pClientContext);
        }

        void accepted(tcp_handle* self, address&& clientAddr, address&& localAddr) {
            if (!allow_new_connections) {
                delete self;
                return;
            }
            std::lock_guard guard(safety);
            task::run([handler_fn = this->handler_fn, self, clientAddr = std::move(clientAddr), localAddr = std::move(localAddr)]() {
                std::visit(
                    [&](auto&& f) {
                        using T = std::decay_t<decltype(f)>;
                        if constexpr (std::is_same_v<T, std::function<void(TcpNetworkBlocking&)>>) {
                            TcpNetworkBlockingImpl rr(self);
                            f(rr);
                        } else {
                            TcpNetworkStreamImpl rr(self);
                            f(rr);
                        }
                    },
                    handler_fn
                );
            });
        }

        void new_connection(tcp_handle& data, bool good) {
            if (!data.is_bound)
                make_acceptEx();

            universal_address* pClientAddr = NULL;
            universal_address* pLocalAddr = NULL;
            int remoteLen = sizeof(universal_address);
            int localLen = sizeof(universal_address);
            _GetAcceptExSockaddrs(data.buffer.buf, 0, sizeof(universal_address) + 16, sizeof(universal_address) + 16, (LPSOCKADDR*)&pLocalAddr, &localLen, (LPSOCKADDR*)&pClientAddr, &remoteLen);
            address clientAddress = to_address(*pClientAddr);
            address localAddress = to_address(*pLocalAddr);
            if (accept_filter) {
                if (accept_filter(clientAddress, localAddress)) {
                    closesocket(data.socket);
                    if (!data.is_bound)
                        delete &data;
                    else
                        make_acceptEx(&data);
                    return;
                }
            }

            setsockopt(data.socket, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char*)&main_socket, sizeof(main_socket));
            {
                std::lock_guard lock(safety);
                if (!util::native_workers_singleton::register_handle((HANDLE)data.socket, &data)) {
                    closesocket(data.socket);
                    if (!data.is_bound)
                        delete &data;
                    else
                        make_acceptEx(&data);
                    return;
                }
            }
            if (data.is_bound) {
                std::lock_guard guard(data.cv_mutex);
                data.cv.notify_all();
            } else
                accepted(&data, std::move(clientAddress), std::move(localAddress));
            return;
        }

        void make_socket() {
            main_socket = WSASocketW(AF_INET6, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
            if (main_socket == INVALID_SOCKET) {
                corrupted = true;
                return;
            }
            DWORD argp = 1; //non blocking
            int result = setsockopt(main_socket, SOL_SOCKET, SO_REUSEADDR, (char*)&argp, sizeof(argp));
            if (result == SOCKET_ERROR) {
                corrupted = true;
                return;
            }
            if (ioctlsocket(main_socket, FIONBIO, &argp) == SOCKET_ERROR) {
                corrupted = true;
                return;
            }
            int cfg = !config.allow_ip4;
            if (setsockopt(main_socket, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&cfg, sizeof(cfg)) == -1) {
                corrupted = true;
                return;
            }
            cfg = !config.enable_timestamps;
            if (setsockopt(main_socket, IPPROTO_TCP, TCP_TIMESTAMPS, (char*)&cfg, sizeof(cfg)) == -1) {
                corrupted = true;
                return;
            }
            cfg = !config.enable_delay;
            if (setsockopt(main_socket, IPPROTO_TCP, TCP_NODELAY, (char*)&cfg, sizeof(cfg)) == -1) {
                corrupted = true;
                return;
            }
            cfg = config.fast_open_queue;
            if (setsockopt(main_socket, IPPROTO_TCP, TCP_FASTOPEN, (char*)&cfg, sizeof(cfg))) {
                //TODO notify
            }
            cfg = config.recv_timeout_ms;
            if (setsockopt(main_socket, SOL_SOCKET, SO_RCVTIMEO, (char*)&cfg, sizeof(cfg)) == -1) {
                corrupted = true;
                return;
            }
            cfg = config.send_timeout_ms;
            if (setsockopt(main_socket, SOL_SOCKET, SO_SNDTIMEO, (char*)&cfg, sizeof(cfg)) == -1) {
                corrupted = true;
                return;
            }
            cfg = config.enable_keep_alive;
            if (setsockopt(main_socket, SOL_SOCKET, SO_KEEPALIVE, (char*)&cfg, sizeof(cfg)) == -1) {
                corrupted = true;
                return;
            }
            if (config.enable_keep_alive) {
                int cfg = config.keep_alive_settings.idle_ms;
                if (setsockopt(main_socket, IPPROTO_TCP, TCP_KEEPIDLE, (char*)&cfg, sizeof(cfg)) == -1) {
                    corrupted = true;
                    return;
                }
                cfg = config.keep_alive_settings.interval_ms;
                if (setsockopt(main_socket, IPPROTO_TCP, TCP_KEEPINTVL, (char*)&cfg, sizeof(cfg)) == -1) {
                    corrupted = true;
                    return;
                }
                cfg = config.keep_alive_settings.retry_count;
                if (setsockopt(main_socket, IPPROTO_TCP, TCP_KEEPCNT, (char*)&cfg, sizeof(cfg)) == -1) {
                    corrupted = true;
                    return;
                }
    #ifdef TCP_MAXRTMS
                cfg = config.keep_alive_settings.user_timeout_ms;
                if (setsockopt(main_socket, IPPROTO_TCP, TCP_MAXRTMS, (char*)&cfg, sizeof(cfg)) == -1) {
                    corrupted = true;
                    return;
                }
    #else
                cfg = config.keep_alive_settings.user_timeout_ms / 1000;
                if (setsockopt(main_socket, IPPROTO_TCP, TCP_MAXRT, (char*)&cfg, sizeof(cfg)) == -1) {
                    corrupted = true;
                    return;
                }
    #endif
            }

            init_win_fns(main_socket);
            if (bind(main_socket, (sockaddr*)_address.get_data(), _address.data_size()) == SOCKET_ERROR) {
                corrupted = true;
                return;
            }
            if (!util::native_workers_singleton::register_handle((HANDLE)main_socket, this)) {
                corrupted = true;
                return;
            }
            if (listen(main_socket, SOMAXCONN) == SOCKET_ERROR) {
                WSACleanup();
                corrupted = true;
            }
        }

    public:
        TcpNetworkManager(const address& ip_port, size_t acceptors, const TcpConfiguration& config)
            : acceptors(acceptors), config(config), main_socket(INVALID_SOCKET), timeout_ms(0), _address(ip_port) {
        }

        ~TcpNetworkManager() override {
            if (!corrupted)
                shutdown();
        }

        void handle(void* _data, util::native_worker_handle* overlapped, unsigned long dwBytesTransferred, bool status) override {
            auto& data = *(tcp_handle*)overlapped;
            if (data.opcode == tcp_handle::Opcode::ACCEPT)
                new_connection(data, !((FALSE == status) || ((true == status) && (0 == dwBytesTransferred))));
            else if (!((FALSE == status) || ((true == status) && (0 == dwBytesTransferred))))
                data.handle(dwBytesTransferred);
            else
                data.connection_reset();
        }

        void set_configuration(const TcpConfiguration& tcp) {
            if (corrupted)
                throw std::runtime_error("TcpNetworkManager is corrupted");
            std::lock_guard lock(safety);
            config = tcp;
        }

        void set_on_connect(std::function<void(TcpNetworkStream&)> handler_fn) {
            if (corrupted)
                throw std::runtime_error("TcpNetworkManager is corrupted");
            std::lock_guard lock(safety);
            this->handler_fn = handler_fn;
        }

        void set_on_connect(std::function<void(TcpNetworkBlocking&)> handler_fn) {
            if (corrupted)
                throw std::runtime_error("TcpNetworkManager is corrupted");
            std::lock_guard lock(safety);
            this->handler_fn = handler_fn;
        }

        void shutdown() {
            if (corrupted)
                throw std::runtime_error("TcpNetworkManager is corrupted");
            std::lock_guard lock(safety);
            if (disabled)
                return;
            if (closesocket(main_socket) == SOCKET_ERROR)
                WSACleanup();
            allow_new_connections = false;
            disabled = true;
            state_changed_cv.notify_all();
        }

        void pause() {
            if (corrupted)
                throw std::runtime_error("TcpNetworkManager is corrupted");
            allow_new_connections = false;
        }

        void resume() {
            if (corrupted)
                throw std::runtime_error("TcpNetworkManager is corrupted");
            allow_new_connections = true;
        }

        void start() {
            if (corrupted)
                throw std::runtime_error("TcpNetworkManager is corrupted");
            std::lock_guard lock(safety);
            allow_new_connections = true;
            if (!disabled)
                return;
            make_socket();
            if (corrupted)
                return;
            for (size_t i = 0; i < acceptors; i++)
                make_acceptEx();
            disabled = false;
            state_changed_cv.notify_all();
        }

        tcp_handle* base_accept(bool ignore_acceptors) {
            if (!ignore_acceptors && acceptors)
                throw std::runtime_error("Tried to accept connection with enabled acceptors and ignore_acceptors = false");
            if (corrupted)
                throw std::runtime_error("TcpNetworkManager is corrupted");
            if (disabled)
                throw std::runtime_error("TcpNetworkManager is disabled");
            if (!allow_new_connections)
                throw std::runtime_error("TcpNetworkManager is paused");
            tcp_handle* data = new tcp_handle(0, config.buffer_size, this);
            mutex_unify um(data->cv_mutex);
            std::unique_lock lock(um);
            data->opcode = tcp_handle::Opcode::ACCEPT;
            data->is_bound = true;
            make_acceptEx(data);
            data->cv.wait(lock);
            return data;
        }

        TcpNetworkBlocking* accept_blocking(bool ignore_acceptors = false) {
            return new TcpNetworkBlockingImpl(base_accept(ignore_acceptors));
        }

        TcpNetworkStream* accept_stream(bool ignore_acceptors = false) {
            return new TcpNetworkStreamImpl(base_accept(ignore_acceptors));
        }

        void _await() {
            mutex_unify um(safety);
            std::unique_lock lock(um);
            if (corrupted)
                throw std::runtime_error("TcpNetworkManager is corrupted");
            while (!disabled)
                state_changed_cv.wait(lock);
        }

        void set_accept_filter(std::function<bool(address&, address&)>&& filter) {
            if (corrupted)
                throw std::runtime_error("TcpNetworkManager is corrupted");
            std::lock_guard lock(safety);
            this->accept_filter = std::move(filter);
        }

        bool is_corrupted() {
            return corrupted;
        }

        uint16_t port() {
            if (corrupted)
                throw std::runtime_error("TcpNetworkManager is corrupted");
            return _address.port();
        }

        std::string ip() {
            return _address.to_string();
        }

        address get_address() {
            if (corrupted)
                throw std::runtime_error("TcpNetworkManager is corrupted");

            return _address;
        }

        bool is_paused() {
            return !disabled && !allow_new_connections;
        }

        bool in_run() {
            return !disabled;
        }
    };

    class TcpClientManager : public util::native_worker_manager {
        task_mutex mutex;
        sockaddr_in6 connectionAddress;
        tcp_handle* _handle;
        bool corrupted = false;

        void set_configuration(SOCKET sock, const TcpConfiguration& config) {
            int cfg = !config.allow_ip4;

            if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&cfg, sizeof(cfg)) == -1) {
                corrupted = true;
                return;
            }
            cfg = !config.enable_timestamps;
            if (setsockopt(sock, IPPROTO_TCP, TCP_TIMESTAMPS, (char*)&cfg, sizeof(cfg)) == -1) {
                corrupted = true;
                return;
            }
            cfg = !config.enable_delay;
            if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char*)&cfg, sizeof(cfg)) == -1) {
                corrupted = true;
                return;
            }
            cfg = config.recv_timeout_ms;
            if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&cfg, sizeof(cfg)) == -1) {
                corrupted = true;
                return;
            }
            cfg = config.send_timeout_ms;
            if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&cfg, sizeof(cfg)) == -1) {
                corrupted = true;
                return;
            }
            cfg = config.enable_keep_alive;
            if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (char*)&cfg, sizeof(cfg)) == -1) {
                corrupted = true;
                return;
            }
            if (config.enable_keep_alive) {
                int cfg = config.keep_alive_settings.idle_ms;
                if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, (char*)&cfg, sizeof(cfg)) == -1) {
                    corrupted = true;
                    return;
                }
                cfg = config.keep_alive_settings.interval_ms;
                if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, (char*)&cfg, sizeof(cfg)) == -1) {
                    corrupted = true;
                    return;
                }
                cfg = config.keep_alive_settings.retry_count;
                if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, (char*)&cfg, sizeof(cfg)) == -1) {
                    corrupted = true;
                    return;
                }
    #ifdef TCP_MAXRTMS
                cfg = config.keep_alive_settings.user_timeout_ms;
                if (setsockopt(sock, IPPROTO_TCP, TCP_MAXRTMS, (char*)&cfg, sizeof(cfg)) == -1) {
                    corrupted = true;
                    return;
                }
    #else
                cfg = config.keep_alive_settings.user_timeout_ms / 1000;
                if (setsockopt(sock, IPPROTO_TCP, TCP_MAXRT, (char*)&cfg, sizeof(cfg)) == -1) {
                    corrupted = true;
                    return;
                }
    #endif
            }
            DWORD argp = 1;
            if (ioctlsocket(sock, FIONBIO, &argp) == SOCKET_ERROR) {
                corrupted = true;
                return;
            }
        }

    public:
        void handle(void* _data, util::native_worker_handle* overlapped, unsigned long dwBytesTransferred, bool status) override {
            tcp_handle& handle = *(tcp_handle*)overlapped;
            if ((FALSE == status) || ((true == status) && (0 == dwBytesTransferred)))
                handle.connection_reset();
            else if (handle.opcode == tcp_handle::Opcode::ACCEPT)
                handle.cv.notify_all();
            else
                handle.handle(dwBytesTransferred);
        }

        TcpClientManager(sockaddr_in6& _connectionAddress, const TcpConfiguration& config)
            : connectionAddress(_connectionAddress) {
            SOCKET clientSocket = WSASocketW(AF_INET6, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
            if (clientSocket == INVALID_SOCKET) {
                corrupted = true;
                return;
            }
            set_configuration(clientSocket, config);
            if (corrupted) {
                closesocket(clientSocket);
                return;
            }

            _handle = new tcp_handle(clientSocket, 4096, this);
            mutex_unify umutex(_handle->cv_mutex);
            std::unique_lock<mutex_unify> lock(umutex);
            if (!_ConnectEx(clientSocket, (sockaddr*)&connectionAddress, sizeof(connectionAddress), NULL, 0, nullptr, (OVERLAPPED*)_handle)) {
                auto err = WSAGetLastError();
                if (err != ERROR_IO_PENDING) {
                    corrupted = true;
                    _handle->reset();
                    return;
                }
            }
            if (config.connection_timeout_ms > 0) {
                if (!_handle->cv.wait_for(lock, config.connection_timeout_ms)) {
                    corrupted = true;
                    _handle->reset();
                    return;
                }
            } else
                _handle->cv.wait(lock);
        }

        TcpClientManager(sockaddr_in6& _connectionAddress, char* data, uint32_t len, const TcpConfiguration& config)
            : connectionAddress(_connectionAddress), _handle(nullptr) {
            SOCKET clientSocket = WSASocketW(AF_INET6, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
            if (clientSocket == INVALID_SOCKET) {
                corrupted = true;
                return;
            }
            set_configuration(clientSocket, config);
            if (corrupted) {
                closesocket(clientSocket);
                return;
            }
            int cfg = !config.enable_delay;
            if (setsockopt(clientSocket, IPPROTO_TCP, TCP_FASTOPEN, (char*)&cfg, sizeof(cfg)) == -1) {
                corrupted = true;
                closesocket(clientSocket);
                return;
            }

            _handle = new tcp_handle(clientSocket, 4096, this);
            char* old_buffer = _handle->data;
            _handle->data = data;
            _handle->buffer.buf = data;
            _handle->buffer.len = len;
            _handle->total_bytes = len;
            _handle->opcode = tcp_handle::Opcode::WRITE;
            mutex_unify umutex(_handle->cv_mutex);
            std::unique_lock<mutex_unify> lock(umutex);
            if (!_ConnectEx(clientSocket, (sockaddr*)&connectionAddress, sizeof(connectionAddress), data, len, nullptr, (OVERLAPPED*)_handle)) {
                auto err = WSAGetLastError();
                if (err != ERROR_IO_PENDING) {
                    corrupted = true;
                    return;
                }
            }
            if (config.connection_timeout_ms > 0) {
                if (!_handle->cv.wait_for(lock, config.connection_timeout_ms)) {
                    corrupted = true;
                    _handle->data = old_buffer;
                    _handle->reset();
                    return;
                }
            } else
                _handle->cv.wait(lock);
            _handle->data = old_buffer;
        }

        ~TcpClientManager() override {
            if (corrupted)
                return;
            delete _handle;
        }

        void set_configuration(const TcpConfiguration& config) {
            if (corrupted)
                throw std::runtime_error("TcpClientManager::read, corrupted");
            if (_handle) {
                set_configuration(_handle->socket, config);
                if (!corrupted)
                    _handle->rebuffer(config.buffer_size);
            }
        }

        int32_t read(char* data, int32_t len) {
            if (corrupted)
                throw std::runtime_error("TcpClientManager::read, corrupted");
            std::lock_guard<task_mutex> lock(mutex);
            int32_t readed = 0;
            while (!_handle->available_bytes())
                if (!_handle->send_queue_item())
                    break;
            _handle->read_available(data, len, readed);
            return readed;
        }

        bool write(const char* data, int32_t len) {
            if (corrupted)
                throw std::runtime_error("TcpClientManager::write, corrupted");
            std::lock_guard<task_mutex> lock(mutex);
            _handle->send_data(data, len);
            while (!_handle->available_bytes())
                if (!_handle->send_queue_item())
                    break;
            return _handle->valid();
        }

        bool write_file(const char* path, size_t len, uint64_t data_len, uint64_t offset, uint32_t chunks_size) {
            if (corrupted)
                throw std::runtime_error("TcpClientManager::write_file, corrupted");
            std::lock_guard<task_mutex> lock(mutex);
            while (!_handle->available_bytes())
                if (!_handle->send_queue_item())
                    break;
            return _handle->send_file(path, len, data_len, offset, chunks_size);
        }

        bool write_file(void* handle, uint64_t data_len, uint64_t offset, uint32_t chunks_size) {
            if (corrupted)
                throw std::runtime_error("TcpClientManager::write_file, corrupted");
            std::lock_guard<task_mutex> lock(mutex);
            while (!_handle->available_bytes())
                if (!_handle->send_queue_item())
                    break;
            return _handle->send_file(handle, data_len, offset, chunks_size);
        }

        void close() {
            if (corrupted)
                throw std::runtime_error("TcpClientManager::close, corrupted");
            std::lock_guard<task_mutex> lock(mutex);
            _handle->close();
        }

        void reset() {
            if (corrupted)
                throw std::runtime_error("TcpClientManager::close, corrupted");
            std::lock_guard<task_mutex> lock(mutex);
            _handle->reset();
        }

        bool is_corrupted() {
            return corrupted;
        }

        void rebuffer(uint32_t size) {
            if (corrupted)
                throw std::runtime_error("TcpClientManager::rebuffer, corrupted");
            std::lock_guard<task_mutex> lock(mutex);
            _handle->rebuffer(size);
        }
    };

    #pragma endregion

    class udp_handle : public util::native_worker_handle, public util::native_worker_manager {
        std::shared_ptr<task> notify_task;
        SOCKET socket;
        sockaddr_in6 server_address;

    public:
        DWORD fullifed_bytes;
        bool status;
        DWORD last_error;

        udp_handle(sockaddr_in6& address, uint32_t timeout_ms)
            : util::native_worker_handle(this), last_error(0), fullifed_bytes(0), status(false), server_address{0} {
            socket = WSASocketW(AF_INET6, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, WSA_FLAG_OVERLAPPED);

            if (socket == INVALID_SOCKET)
                return;
            if (bind(socket, (sockaddr*)&address, sizeof(sockaddr_in6)) == SOCKET_ERROR) {
                closesocket(socket);
                socket = INVALID_SOCKET;
                return;
            }
            server_address = address;
        }

        void handle(void* data, util::native_worker_handle* overlapped, unsigned long fullifed_bytes, bool status) override {
            this->fullifed_bytes = fullifed_bytes;
            this->status = status;
            last_error = GetLastError();
            task::start(notify_task);
        }

        void recv(uint8_t* data, uint32_t size, sockaddr_storage& sender, int& sender_len) {
            if (socket == INVALID_SOCKET)
                throw std::runtime_error("Socket not connected");
            WSABUF buf;
            buf.buf = (char*)data;
            buf.len = size;
            notify_task = task::dummy_task();
            DWORD flags = 0;
            if (WSARecvFrom(socket, &buf, 1, nullptr, &flags, (sockaddr*)&sender, &sender_len, (OVERLAPPED*)this, nullptr)) {
                if (WSAGetLastError() != WSA_IO_PENDING) {
                    last_error = WSAGetLastError();
                    status = false;
                    fullifed_bytes = 0;
                    notify_task = nullptr;
                    return;
                }
            }
            task::await_task(notify_task);
            notify_task = nullptr;
        }

        void send(uint8_t* data, uint32_t size, sockaddr_storage& to) {
            sockaddr_in6 sender;
            WSABUF buf;
            buf.buf = (char*)data;
            buf.len = size;
            notify_task = task::dummy_task();
            if (WSASendTo(socket, &buf, 1, nullptr, 0, (sockaddr*)&to, sizeof(to), (OVERLAPPED*)this, nullptr)) {
                if (WSAGetLastError() != WSA_IO_PENDING) {
                    last_error = WSAGetLastError();
                    status = false;
                    fullifed_bytes = 0;
                    notify_task = nullptr;
                    return;
                }
            }
            task::await_task(notify_task);
            notify_task = nullptr;
        }

        address local_address() {
            universal_address addr;
            int socklen = sizeof(universal_address);
            if (getsockname(socket, (sockaddr*)&addr, &socklen) == -1)
                return {};
            return to_address(addr);
        }

        address remote_address() {
            universal_address addr;
            int socklen = sizeof(universal_address);
            if (getpeername(socket, (sockaddr*)&addr, &socklen) == -1)
                return {};
            return to_address(addr);
        }
    };

    uint8_t init_networking() {
        if (!inited)
            if (WSAStartup(MAKEWORD(2, 2), &wsaData)) {
                auto err = WSAGetLastError();
                switch (err) {
                case WSASYSNOTREADY:
                    return 1;
                case WSAVERNOTSUPPORTED:
                    return 2;
                    return 3;
                case WSAEPROCLIM:
                    return 4;
                case WSAEFAULT:
                    return 5;
                default:
                    return 0xFF;
                }
            };
        inited = true;
        return 0;
    }

    void deinit_networking() {
        if (inited)
            WSACleanup();
        inited = false;
    }

#else
    bool inited = false;
    using SOCKET = int;
    #define INVALID_SOCKET -1

    struct tcp_handle : public util::native_worker_handle {
        std::list<std::tuple<char*, size_t>> write_queue;
        std::list<std::tuple<char*, size_t>> read_queue;
        task_condition_variable cv;
        task_mutex cv_mutex;
        SOCKET socket;

        struct {
            char* buf;
            int len;
        } buffer;

        char* data;
        int total_bytes;
        int sent_bytes;
        int readed_bytes;
        int data_len;
        int aerrno = 0;
        bool force_mode;
        bool is_bound = false;
        uint32_t max_read_queue_size;
        TcpError invalid_reason = TcpError::none;
        sockaddr_storage clientAddress;
        socklen_t clientAddressLen = sizeof(sockaddr_storage);

        enum class Opcode : uint8_t {
            ACCEPT,
            READ,
            WRITE,
            INTERNAL_READ,
            INTERNAL_CLOSE
        } opcode = Opcode::ACCEPT;

        tcp_handle(SOCKET socket, int32_t buffer_len, util::native_worker_manager* manager, uint32_t read_queue_size = 10)
            : socket(socket), util::native_worker_handle(manager), max_read_queue_size(read_queue_size), clientAddress(), clientAddressLen(sizeof(sockaddr_storage)), buffer{0}, data_len(0) {
            if (buffer_len < 0)
                throw std::invalid_argument("buffer_len must be positive");
            if (buffer_len) {
                data = new char[buffer_len];
                buffer.buf = data;
                buffer.len = buffer_len;
                data_len = buffer_len;
            } else
                data = nullptr;
            total_bytes = 0;
            sent_bytes = 0;
            readed_bytes = 0;
            force_mode = false;
        }

        ~tcp_handle() {
            close();
        }

        uint32_t available_bytes() {
            if (!data)
                return 0;
            if (readed_bytes)
                return true;
            int value = 0;
            int result = ioctl(socket, FIONREAD, &value);
            if (result != 0)
                return 0;
            else
                return value;
        }

        bool data_available() {
            return available_bytes() > 0;
        }

        void send_data(const char* data, int len) {
            if (!data)
                return;
            char* new_data = new char[len];
            memcpy(new_data, data, len);
            write_queue.push_back(std::make_tuple(new_data, len));
        }

        //async
        bool send_queue_item() {
            if (!data)
                return false;
            if (write_queue.empty())
                return false;
            auto item = write_queue.front();
            write_queue.pop_front();
            auto& send_data = std::get<0>(item);
            auto& val_len = std::get<1>(item);
            std::unique_ptr<char[]> send_data_ptr(send_data);
            //set buffer
            buffer.len = data_len;
            buffer.buf = data;
            while (val_len) {
                size_t to_sent_bytes = val_len > data_len ? data_len : val_len;
                memcpy(data, send_data, to_sent_bytes);
                buffer.len = to_sent_bytes;
                buffer.buf = data;
                if (!send_await()) {
                    return false;
                }
                if (val_len < sent_bytes)
                    return true;
                val_len -= sent_bytes;
                send_data += sent_bytes;
            }
            return true;
        }

        void read_force(uint32_t buffer_len, char* buffer) {
            if (!data)
                return;
            if (!buffer_len)
                return;
            if (!buffer)
                return;
            while (buffer_len) {
                int readed = 0;
                read_available(buffer, buffer_len, readed);
                buffer += readed;
                if (readed > buffer_len)
                    return;
                buffer_len -= readed;
            }
        }

        int64_t write_force_no_copy(const char* to_write, uint32_t to_write_len) {
            if (!data)
                return -1;
            if (!to_write_len)
                return -1;
            if (!to_write)
                return -1;

            while (to_write_len >= data_len) {
                buffer.len = data_len;
                buffer.buf = const_cast<char*>(to_write);
                force_mode = true;
                if (!send_await())
                    return -1;
                to_write += data_len;
                to_write_len -= data_len;
            }
            if (to_write_len) {
                buffer.len = to_write_len;
                buffer.buf = const_cast<char*>(to_write);
                force_mode = true;
                if (!send_await())
                    return -1;
            }
            force_mode = false;
            return sent_bytes;
        }

        int64_t write_force(const char* to_write, uint32_t to_write_len) {
            if (!data)
                return -1;
            if (!to_write_len)
                return -1;
            if (!to_write)
                return -1;

            force_mode = true;
            if (data_len < to_write_len) {
                buffer.len = data_len;
                buffer.buf = this->data;
                if (!send_await())
                    return -1;
                force_mode = false;
                return sent_bytes;
            } else {
                buffer.len = to_write_len;
                buffer.buf = this->data;
                memcpy(this->data, to_write, to_write_len);
                if (!send_await())
                    return -1;
                force_mode = false;
                return sent_bytes;
            }
        }

        void read_data() {
            if (!data)
                return;

            if (read_queue.empty()) {
                mutex_unify mutex(cv_mutex);
                std::unique_lock<mutex_unify> lock(mutex);
                opcode = Opcode::READ;
                read();
                cv.wait(lock);
            } else {
                auto item = read_queue.front();
                read_queue.pop_front();
                auto& read_data = std::get<0>(item);
                auto& val_len = std::get<1>(item);
                std::unique_ptr<char[]> read_data_ptr(read_data);
                buffer.buf = data;
                buffer.len = data_len;
                readed_bytes = val_len;
                memcpy(data, read_data, val_len);
            }
        }

        void read_available_no_block(char* extern_buffer, int buffer_len, int& readed) {
            if (!readed_bytes)
                readed = 0;
            else if (readed_bytes < buffer_len) {
                readed = readed_bytes;
                memcpy(extern_buffer, data, readed_bytes);
                readed_bytes = 0;
            } else {
                readed = buffer_len;
                memcpy(extern_buffer, buffer.buf, buffer_len);
                readed_bytes -= buffer_len;
                buffer.buf += buffer_len;
                buffer.len -= buffer_len;
            }
        }

        void read_available(char* extern_buffer, int buffer_len, int& readed) {
            if (!readed_bytes)
                read_data();
            if (readed_bytes < buffer_len) {
                readed = readed_bytes;
                memcpy(extern_buffer, data, readed_bytes);
                readed_bytes = 0;
            } else {
                readed = buffer_len;
                memcpy(extern_buffer, buffer.buf, buffer_len);
                readed_bytes -= buffer_len;
                buffer.buf += buffer_len;
                buffer.len -= buffer_len;
            }
        }

        char* read_available_no_copy(int& readed) {
            if (!readed_bytes)
                read_data();
            readed = readed_bytes;
            readed_bytes = 0;
            return buffer.buf - readed;
        }

        void close(TcpError err = TcpError::local_close) {
            if (!data)
                return;
            pre_close(err);
            internal_close();
        }

        void handle(unsigned long dwBytesTransferred, int sock_error) {
            int flags = 0, bytes = 0;
            if (!data) {
                if (opcode != Opcode::INTERNAL_CLOSE)
                    return;
            }
            if (sock_error) {
                switch (sock_error) {
                case EFAULT:
                case EINVAL:
                case EAGAIN:
    #if EAGAIN != EWOULDBLOCK
                case EWOULDBLOCK:
    #endif
                    pre_close(TcpError::invalid_state, true);
                    return;
                case ECONNRESET:
                    pre_close(TcpError::remote_close, true);
                    return;
                default:
                    pre_close(TcpError::undefined_error, true);
                    return;
                }
            }
            mutex_unify mutex(cv_mutex);
            std::unique_lock<mutex_unify> lock(mutex);
            switch (opcode) {
            case Opcode::READ: {
                readed_bytes = dwBytesTransferred;
                cv.notify_all();
                break;
            }
            case Opcode::WRITE:
                sent_bytes += dwBytesTransferred;
                if (sent_bytes < total_bytes) {
                    buffer.buf = data + sent_bytes;
                    buffer.len = total_bytes - sent_bytes;
                    if (!data_available())
                        send();
                    else {
                        char* data = new char[buffer.len];
                        memcpy(data, buffer.buf, buffer.len);
                        write_queue.push_front(std::make_tuple(data, buffer.len));
                        if (force_mode) {
                            opcode = Opcode::INTERNAL_READ;
                            read();
                        } else
                            cv.notify_all();
                    }
                } else
                    cv.notify_all();
                break;
            case Opcode::INTERNAL_READ:
                if (dwBytesTransferred) {
                    char* buffer = new char[dwBytesTransferred];
                    memcpy(buffer, data, dwBytesTransferred);
                    read_queue.push_back(std::make_tuple(buffer, dwBytesTransferred));
                }
                if (!data_available()) {
                    if (read_queue.size() > max_read_queue_size)
                        close(TcpError::read_queue_overflow);
                    else
                        read();
                } else {
                    if (write_queue.empty())
                        close(TcpError::invalid_state);
                    else {
                        auto item = write_queue.front();
                        write_queue.pop_front();
                        auto& write_data = std::get<0>(item);
                        auto& val_len = std::get<1>(item);
                        memcpy(data, write_data, val_len);
                        delete[] write_data;
                        buffer.buf = data;
                        buffer.len = val_len;
                        send();
                    }
                }
                break;
            case Opcode::INTERNAL_CLOSE:
                cv.notify_all();
                break;
            default:
                break;
            }
        }

        void send_and_close(const char* send_data, int send_len) {
            if (!data)
                return;
            shutdown(true, false);
            write_queue = {};
            write_force_no_copy(send_data, send_len);
            close();
        }

        bool send_file(int file, uint64_t data_len, uint64_t offset, uint32_t chunks_size) {
            if (!data)
                return false;
            if (chunks_size == 0)
                chunks_size = 0x1000;
            if (data_len == 0) {
                struct stat file_stat;
                if (fstat(file, &file_stat) == -1)
                    return false;
                data_len = file_stat.st_size;
                if (data_len < offset)
                    return false;
                data_len -= offset;
            }

            if (data_len > UINT_MAX) {
                uint64_t sended = 0;
                uint64_t blocks = data_len / UINT_MAX;
                uint64_t last_block = data_len % blocks;

                while (blocks--)
                    if (!transfer_file(socket, file, UINT_MAX, chunks_size, sended + offset))
                        return false;
                    else
                        sended += UINT_MAX;


                if (last_block)
                    if (!transfer_file(socket, file, last_block, chunks_size, sended + offset))
                        return false;
            } else {
                if (!transfer_file(socket, file, data_len, chunks_size, offset))
                    return false;
            }
            return true;
        }

        bool send_file(const char* path, size_t path_len, uint64_t data_len, uint64_t offset, uint32_t chunks_size) {
            if (!data)
                return false;
            if (chunks_size == 0)
                chunks_size = 0x1000;
            int file = ::open(path, O_RDONLY | O_NONBLOCK);
            if (file == -1)
                return false;
            bool result;
            try {
                result = send_file(file, data_len, offset, chunks_size);
            } catch (...) {
                ::close(file);
                throw;
            }
            ::close(file);
            return result;
        }

        bool valid() {
            return data != nullptr;
        }

        void reset() {
            if (!data)
                return;
            struct linger sl;
            sl.l_onoff = 1;
            sl.l_linger = 0;
            setsockopt(socket, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));
            pre_close(TcpError::local_reset);
            internal_close();
        }

        void connection_reset() {
            mutex_unify mutex(cv_mutex);
            std::unique_lock<mutex_unify> lock(mutex);
            char* old_data = data;
            data = nullptr;
            invalid_reason = TcpError::remote_close;
            readed_bytes = 0;
            cv.notify_all();
            delete[] data;
        }

        void rebuffer(int32_t buffer_len) {
            if (!data)
                return;
            if (buffer_len < 0)
                throw std::invalid_argument("buffer_len must be positive");
            char* new_data = new char[buffer_len];
            delete[] data;
            data = new_data;
            data_len = buffer_len;
        }

        void shutdown(bool stop_read, bool stop_write) {
            if (!stop_read && !stop_write)
                return;
            int method = 0;
            if (stop_read && stop_write)
                method = SHUT_RDWR;
            if (stop_read)
                method = SHUT_RD;
            if (stop_write)
                method = SHUT_WR;
            mutex_unify mutex(cv_mutex);
            std::unique_lock<mutex_unify> lock(mutex);
            opcode = Opcode::INTERNAL_CLOSE;
            util::native_workers_singleton::post_shutdown(this, socket, method);
            cv.wait(lock);
        }

    private:
        void pre_close(TcpError err, bool handle_error = false) {
            mutex_unify mutex(cv_mutex);
            std::unique_lock<mutex_unify> lock(mutex);
            opcode = Opcode::INTERNAL_CLOSE;
            if (handle_error) {
                util::native_workers_singleton::post_shutdown(this, socket, SHUT_RDWR);
                cv.wait(lock);
            }
            std::list<std::tuple<char*, size_t>> clear_write_queue;
            std::list<std::tuple<char*, size_t>> clear_read_queue;
            readed_bytes = 0;
            sent_bytes = 0;
            delete[] data;
            data = nullptr;
            invalid_reason = err;
            write_queue.swap(clear_write_queue);
            read_queue.swap(clear_read_queue);
            cv.notify_all();

            lock.unlock();
            for (auto& item : clear_write_queue)
                delete[] std::get<0>(item);
            for (auto& item : clear_read_queue)
                delete[] std::get<0>(item);
        }

        void internal_close() {
            mutex_unify mutex(cv_mutex);
            std::unique_lock<mutex_unify> lock(mutex);
            opcode = Opcode::INTERNAL_CLOSE;
            util::native_workers_singleton::post_close(this, socket);
            cv.wait(lock);
            socket = INVALID_SOCKET;
        }

        void read() {
            buffer.buf = this->data;
            buffer.len = data_len;
            util::native_workers_singleton::post_recv(this, socket, buffer.buf, buffer.len, 0);
        }

        void send() {
            opcode = Opcode::WRITE;
            util::native_workers_singleton::post_send(this, socket, buffer.buf, buffer.len, 0);
        }

        bool send_await() {
            mutex_unify mutex(cv_mutex);
            std::unique_lock<mutex_unify> lock(mutex);
            send();
            cv.wait(lock);
            return data; //if data is null, then socket is closed
        }

        bool transfer_file(SOCKET sock, int file, uint32_t total_size, uint32_t chunks_size, uint64_t offset) {
            uint64_t sent_bytes = 0;
            struct stat file_stat;
            bool result = true;
            if (fstat(file, &file_stat) == -1)
                return false;
            if (file_stat.st_size < offset + total_size)
                return false;

            char* file_data = (char*)mmap(NULL, file_stat.st_size, PROT_READ, MAP_PRIVATE, file, 0);
            if (file_data == MAP_FAILED)
                return false;

            if (!total_size) {
                while (file_stat.st_size > offset) {
                    int chunk_size = std::min((uint64_t)chunks_size, file_stat.st_size - offset);
                    if (write_force_no_copy(file_data + offset, chunk_size) == -1) {
                        result = false;
                        break;
                    }
                    if (chunk_size >= file_stat.st_size + offset)
                        break;
                    offset += chunk_size;
                }
            } else {
                while (total_size) {
                    int chunk_size = std::min((uint64_t)std::min(chunks_size, total_size), file_stat.st_size - offset);
                    if (write_force_no_copy(file_data + offset, chunk_size) == -1) {
                        result = false;
                        break;
                    }
                    offset += chunk_size;
                    total_size -= chunk_size;
                }
            }
            munmap(file_data, file_stat.st_size);
            return result;
        }
    };

    #pragma region TcpNetworkStream

    class TcpNetworkStreamImpl : public TcpNetworkStream {
        friend class TcpNetworkManager;
        struct tcp_handle* handle;
        task_mutex mutex;
        TcpError last_error;

        bool checkup() {
            if (!handle)
                return false;
            if (!handle->valid()) {
                last_error = handle->invalid_reason;
                delete handle;
                handle = nullptr;
                return false;
            }
            return true;
        }

    public:
        TcpNetworkStreamImpl(tcp_handle* handle)
            : handle(handle), last_error(TcpError::none) {}

        ~TcpNetworkStreamImpl() {
            if (handle) {
                std::lock_guard lg(mutex);
                handle->close();
                delete handle;
            }
            handle = nullptr;
        }

        std::span<char> read_available_ref() override {
            std::lock_guard lg(mutex);
            if (!handle)
                return {};
            while (!handle->data_available()) {
                if (!handle->send_queue_item())
                    break;
            }
            if (!checkup())
                return {};
            int readed = 0;
            char* data = handle->read_available_no_copy(readed);
            return {data, (size_t)readed};
        }

        int read_available(char* buffer, int buffer_len) override {
            std::lock_guard lg(mutex);
            if (!handle)
                return 0;
            while (!handle->data_available()) {
                if (!handle->send_queue_item())
                    break;
            }

            if (!checkup())
                return 0;
            int readed = 0;
            handle->read_available(buffer, buffer_len, readed);
            return readed;
        }

        bool data_available() override {
            std::lock_guard lg(mutex);
            if (handle)
                return handle->data_available();
            return false;
        }

        void write(const char* data, size_t size) override {
            std::lock_guard lg(mutex);
            if (handle) {
                handle->send_data(data, size);
                while (!handle->data_available()) {
                    if (!handle->send_queue_item())
                        break;
                }
                checkup();
            }
        }

        bool write_file(char* path, size_t path_len, uint64_t data_len, uint64_t offset, uint32_t chunks_size) override {
            std::lock_guard lg(mutex);
            if (handle) {
                while (handle->valid())
                    if (!handle->send_queue_item())
                        break;

                if (!checkup())
                    return false;

                return handle->send_file(path, path_len, data_len, offset, chunks_size);
            }
            return false;
        }

        bool write_file(int fhandle, uint64_t data_len, uint64_t offset, uint32_t chunks_size) override {
            std::lock_guard lg(mutex);
            if (handle) {
                while (handle->valid())
                    if (!handle->send_queue_item())
                        break;
                if (!checkup())
                    return false;
                return handle->send_file(fhandle, data_len, offset, chunks_size);
            }
            return false;
        }

        //write all data from write_queue
        void force_write() override {
            std::lock_guard lg(mutex);
            if (handle) {
                while (handle->valid())
                    if (!handle->send_queue_item())
                        break;
                checkup();
            }
        }

        void force_write_and_close(const char* data, size_t size) override {
            std::lock_guard lg(mutex);
            if (handle) {
                handle->send_and_close(data, size);
                last_error = handle->invalid_reason;
                delete handle;
            }
            handle = nullptr;
        }

        void close() override {
            std::lock_guard lg(mutex);
            if (handle) {
                handle->close();
                last_error = handle->invalid_reason;
                delete handle;
            }
            handle = nullptr;
        }

        void reset() override {
            std::lock_guard lg(mutex);
            if (handle) {
                handle->reset();
                last_error = handle->invalid_reason;
                delete handle;
            }
            handle = nullptr;
        }

        void rebuffer(int32_t new_size) override {
            std::lock_guard lg(mutex);
            if (handle)
                handle->rebuffer(new_size);
        }

        bool is_closed() override {
            std::lock_guard lg(mutex);
            if (handle) {
                bool res = handle->valid();
                if (!res) {
                    delete handle;
                    handle = nullptr;
                }
                return !res;
            }
            return true;
        }

        TcpError error() override {
            std::lock_guard lg(mutex);
            if (handle)
                return handle->invalid_reason;
            return last_error;
        }

        address local_address() override {
            std::lock_guard lg(mutex);
            if (!handle)
                return {};
            universal_address addr;
            socklen_t socklen = sizeof(universal_address);
            if (getsockname(handle->socket, (sockaddr*)&addr, &socklen) == -1)
                return {};
            return to_address(addr);
        }

        address remote_address() override {
            std::lock_guard lg(mutex);
            if (!handle)
                return {};
            universal_address addr;
            socklen_t socklen = sizeof(universal_address);
            if (getpeername(handle->socket, (sockaddr*)&addr, &socklen) == -1)
                return {};
            return to_address(addr);
        }
    };

    #pragma endregion

    #pragma region TcpNetworkBlocking

    class TcpNetworkBlockingImpl : public TcpNetworkBlocking {
        friend class TcpNetworkManager;
        tcp_handle* handle;
        task_mutex mutex;
        TcpError last_error;

        bool checkup() {
            if (!handle)
                return false;
            if (!handle->valid()) {
                last_error = handle->invalid_reason;
                delete handle;
                handle = nullptr;
                return false;
            }
            return true;
        }

    public:
        TcpNetworkBlockingImpl(tcp_handle* handle)
            : handle(handle), last_error(TcpError::none) {}

        ~TcpNetworkBlockingImpl() {
            std::lock_guard lg(mutex);
            if (handle)
                delete handle;
            handle = nullptr;
        }

        std::vector<char> read(uint32_t len) override {
            std::lock_guard lg(mutex);
            if (handle) {
                if (!checkup())
                    return {};
                std::vector<char> buf;
                buf.resize(len);
                handle->read_force(len, buf.data());
                if (len == 0)
                    return {};
                else
                    buf.resize(len);
                return buf;
            }
            return {};
        }

        uint32_t available_bytes() override {
            std::lock_guard lg(mutex);
            if (handle)
                return handle->available_bytes();
            return (uint32_t)0;
        }

        int64_t write(const char* data, uint32_t len) override {
            std::lock_guard lg(mutex);
            if (handle) {
                if (!checkup())
                    return nullptr;
                return handle->write_force(data, len);
            }
            return nullptr;
        }

        bool write_file(char* path, size_t len, uint64_t data_len, uint64_t offset, uint32_t block_size) override {
            std::lock_guard lg(mutex);
            if (handle) {
                if (!checkup())
                    return false;
                return handle->send_file(path, len, data_len, offset, block_size);
            }
            return false;
        }

        bool write_file(int fhandle, uint64_t data_len, uint64_t offset, uint32_t block_size) override {
            std::lock_guard lg(mutex);
            if (handle) {
                if (!checkup())
                    return false;
                return handle->send_file(fhandle, data_len, offset, block_size);
            }
            return false;
        }

        void close() override {
            std::lock_guard lg(mutex);
            if (handle) {
                handle->close();
                last_error = handle->invalid_reason;
                delete handle;
                handle = nullptr;
            }
        }

        void reset() override {
            std::lock_guard lg(mutex);
            if (handle) {
                handle->reset();
                last_error = handle->invalid_reason;
                delete handle;
                handle = nullptr;
            }
        }

        void rebuffer(size_t new_size) override {
            std::lock_guard lg(mutex);
            if (handle)
                handle->rebuffer(new_size);
        }

        bool is_closed() override {
            std::lock_guard lg(mutex);
            if (handle) {
                bool res = handle->valid();
                if (!res) {
                    last_error = handle->invalid_reason;
                    delete handle;
                    handle = nullptr;
                }
                return !res;
            }
            return true;
        }

        TcpError error() override {
            std::lock_guard lg(mutex);
            if (handle)
                return handle->invalid_reason;
            return last_error;
        }

        address local_address() override {
            std::lock_guard lg(mutex);
            if (!handle)
                return {};
            universal_address addr;
            socklen_t socklen = sizeof(universal_address);
            if (getsockname(handle->socket, (sockaddr*)&addr, &socklen) == -1)
                return {};
            return to_address(addr);
        }

        address remote_address() override {
            std::lock_guard lg(mutex);
            if (!handle)
                return {};
            universal_address addr;
            socklen_t socklen = sizeof(universal_address);
            if (getpeername(handle->socket, (sockaddr*)&addr, &socklen) == -1)
                return {};
            return to_address(addr);
        }
    };

    #pragma endregion

    class TcpNetworkManager : public util::native_worker_manager {
        task_mutex safety;
        std::variant<std::function<void(TcpNetworkBlocking&)>, std::function<void(TcpNetworkStream&)>> handler_fn;
        std::function<bool(address& client, address& server)> accept_filter;
        sockaddr_in6 connectionAddress;
        SOCKET main_socket;

    public:
        TcpConfiguration config;

    private:
        bool allow_new_connections = false;
        bool disabled = true;
        bool corrupted = false;
        size_t acceptors;
        task_condition_variable state_changed_cv;

        void make_acceptEx(void) {
            tcp_handle* pClientContext = new tcp_handle(0, config.buffer_size, this);
            util::native_workers_singleton::post_accept(pClientContext, main_socket, nullptr, nullptr, 0);
        }

        void accepted(tcp_handle* self, address&& clientAddr, address&& localAddr) {
            if (!allow_new_connections) {
                delete self;
                return;
            }
            if (self->aerrno) {
                self->connection_reset();
                delete self;
                return;
            }
            std::lock_guard guard(safety);
            task::run([handler_fn = this->handler_fn, self, clientAddr = std::move(clientAddr), localAddr = std::move(localAddr)]() {
                std::visit(
                    [&](auto&& f) {
                        using T = std::decay_t<decltype(f)>;
                        if constexpr (std::is_same_v<T, std::function<void(TcpNetworkBlocking&)>>) {
                            TcpNetworkBlockingImpl rr(self);
                            f(rr);
                        } else {
                            TcpNetworkStreamImpl rr(self);
                            f(rr);
                        }
                    },
                    handler_fn
                );
            });
        }

        void accept_bounded(tcp_handle& data, SOCKET client_socket) {
            std::lock_guard guard(data.cv_mutex);
            data.socket = client_socket;
            data.cv.notify_all();
        }

        void new_connection(tcp_handle& data, SOCKET client_socket) {
            if (!allow_new_connections) {
                util::native_workers_singleton::post_accept(&data, main_socket, nullptr, nullptr, 0);
                close(client_socket);
            }
            if (data.is_bound && !accept_filter)
                return accept_bounded(data, client_socket);
            if (!accept_filter)
                make_acceptEx();
            universal_address pClientAddr;
            universal_address pLocalAddr;
            socklen_t remoteLen = sizeof(universal_address);
            socklen_t localLen = sizeof(universal_address);
            getsockname(client_socket, (sockaddr*)&pLocalAddr, &localLen);
            getpeername(client_socket, (sockaddr*)&pClientAddr, &remoteLen);
            
            address clientAddress = to_address(*pClientAddr);
            address localAddress = to_address(*pLocalAddr);
            if (accept_filter) {
                if (accept_filter(clientAddress, localAddress)) {
                    util::native_workers_singleton::post_accept(&data, main_socket, nullptr, nullptr, 0);
                    close(client_socket);
                    return;
                }
                make_acceptEx();
            }

            if (data.is_bound)
                accept_bounded(data, client_socket);
            else {
                data.socket = client_socket;
                accepted(&data, std::move(clientAddress), std::move(localAddress));
            }
            return;
        }

        void make_socket() {
            main_socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
            if (main_socket == INVALID_SOCKET) {
                corrupted = true;
                return;
            }
            int argp = 1;
            if (setsockopt(main_socket, SOL_SOCKET, SO_REUSEADDR, &argp, sizeof(argp)) == -1) {
                corrupted = true;
                return;
            }
            if (setsockopt(main_socket, SOL_SOCKET, SO_REUSEPORT, &argp, sizeof(argp)) == -1) {
                corrupted = true;
                return;
            }


            int cfg = !config.allow_ip4;
            if (setsockopt(main_socket, IPPROTO_IPV6, IPV6_V6ONLY, &cfg, sizeof(cfg)) == -1) {
                corrupted = true;
                return;
            }
            cfg = !config.enable_timestamps;
            if (setsockopt(main_socket, IPPROTO_TCP, TCP_TIMESTAMP, &cfg, sizeof(cfg)) == -1) {
                if (errno != 1) {
                    corrupted = true;
                    return;
                }
            }
            cfg = !config.enable_delay;
            if (setsockopt(main_socket, IPPROTO_TCP, TCP_NODELAY, &cfg, sizeof(cfg)) == -1) {
                corrupted = true;
                return;
            }
            cfg = config.fast_open_queue;
            if (setsockopt(main_socket, IPPROTO_TCP, TCP_FASTOPEN, &cfg, sizeof(cfg))) {
                //TODO notify
            }
            struct timeval cfgt = {};
            cfgt.tv_sec = config.recv_timeout_ms / 1000;
            cfgt.tv_usec = (config.recv_timeout_ms % 1000) * 1000;
            if (setsockopt(main_socket, SOL_SOCKET, SO_RCVTIMEO, &cfgt, sizeof(cfgt)) == -1) {
                corrupted = true;
                return;
            }
            cfgt.tv_sec = config.send_timeout_ms / 1000;
            cfgt.tv_usec = (config.send_timeout_ms % 1000) * 1000;
            if (setsockopt(main_socket, SOL_SOCKET, SO_SNDTIMEO, &cfgt, sizeof(cfgt)) == -1) {
                corrupted = true;
                return;
            }
            cfg = config.enable_keep_alive;
            if (setsockopt(main_socket, SOL_SOCKET, SO_KEEPALIVE, &cfg, sizeof(cfg)) == -1) {
                corrupted = true;
                return;
            }
            if (config.enable_keep_alive) {
                int cfg = config.keep_alive_settings.idle_ms;
                if (setsockopt(main_socket, IPPROTO_TCP, TCP_KEEPIDLE, &cfg, sizeof(cfg)) == -1) {
                    corrupted = true;
                    return;
                }
                cfg = config.keep_alive_settings.interval_ms;
                if (setsockopt(main_socket, IPPROTO_TCP, TCP_KEEPINTVL, &cfg, sizeof(cfg)) == -1) {
                    corrupted = true;
                    return;
                }
                cfg = config.keep_alive_settings.retry_count;
                if (setsockopt(main_socket, IPPROTO_TCP, TCP_KEEPCNT, &cfg, sizeof(cfg)) == -1) {
                    corrupted = true;
                    return;
                }
                cfg = config.keep_alive_settings.user_timeout_ms;
                if (setsockopt(main_socket, IPPROTO_TCP, TCP_USER_TIMEOUT, &cfg, sizeof(cfg)) == -1) {
                    corrupted = true;
                    return;
                }
            }
            if (bind(main_socket, (sockaddr*)&connectionAddress, sizeof(sockaddr_in6)) == -1) {
                corrupted = true;
                return;
            }
            if (listen(main_socket, SOMAXCONN) == -1) {
                corrupted = true;
                return;
            }
        }

    public:
        TcpNetworkManager(universal_address& ip_port, size_t acceptors, TcpNetworkServer::ManageType manage_type, const TcpConfiguration& config)
            : acceptors(acceptors), manage_type(manage_type), config(config), main_socket(INVALID_SOCKET) {
            memcpy(&connectionAddress, &ip_port, sizeof(sockaddr_in6));
        }

        ~TcpNetworkManager() noexcept(false) {
            shutdown();
        }

        void handle(util::native_worker_handle* completion, io_uring_cqe* cqe) override {
            auto& data = *(tcp_handle*)completion;
            if (cqe->res < 0)
                data.aerrno = -cqe->res;
            if (data.opcode == tcp_handle::Opcode::ACCEPT)
                new_connection(data, cqe->res);
            else
                data.handle(cqe->res < 0 ? 0 : cqe->res, cqe->res < 0 ? -cqe->res : 0);
        }

        void set_on_connect(std::function<void(TcpNetworkStream&)> handler_fn) {
            if (corrupted)
                throw std::runtime_error("TcpNetworkManager is corrupted");
            std::lock_guard lock(safety);
            this->handler_fn = handler_fn;
        }

        void set_on_connect(std::function<void(TcpNetworkBlocking&)> handler_fn) {
            if (corrupted)
                throw std::runtime_error("TcpNetworkManager is corrupted");
            std::lock_guard lock(safety);
            this->handler_fn = handler_fn;
        }

        void shutdown() {
            if (corrupted)
                throw std::runtime_error("TcpNetworkManager is corrupted");
            std::lock_guard lock(safety);
            if (disabled)
                return;
            tcp_handle* data = new tcp_handle(main_socket, 0, this, 0);
            mutex_unify mutex(data->cv_mutex);
            std::unique_lock lock2(mutex);
            util::native_workers_singleton::post_shutdown(data, main_socket, SHUT_RDWR);
            data->cv.wait(lock2);
            allow_new_connections = false;
            disabled = true;
            state_changed_cv.notify_all();
        }

        void pause() {
            if (corrupted)
                throw std::runtime_error("TcpNetworkManager is corrupted");
            allow_new_connections = false;
        }

        void resume() {
            if (corrupted)
                throw std::runtime_error("TcpNetworkManager is corrupted");
            allow_new_connections = true;
        }

        void start() {
            if (corrupted)
                throw std::runtime_error("TcpNetworkManager is corrupted");
            std::lock_guard lock(safety);
            allow_new_connections = true;
            if (!disabled)
                return;
            make_socket();
            if (corrupted)
                return;
            for (size_t i = 0; i < acceptors; i++)
                make_acceptEx();
            disabled = false;
            state_changed_cv.notify_all();
        }

        tcp_handle* base_accept(bool ignore_acceptors) {
            if (!ignore_acceptors && acceptors)
                throw std::runtime_error("Tried to accept connection with enabled acceptors and ignore_acceptors = false");
            if (corrupted)
                throw std::runtime_error("TcpNetworkManager is corrupted");
            if (disabled)
                throw std::runtime_error("TcpNetworkManager is disabled");
            if (!allow_new_connections)
                throw std::runtime_error("TcpNetworkManager is paused");

            tcp_handle* data = new tcp_handle(0, config.buffer_size, this, 0);
            mutex_unify mutex(data->cv_mutex);
            std::unique_lock lock(mutex);
            data->is_bound = true;
            data->opcode = tcp_handle::Opcode::ACCEPT;
            util::native_workers_singleton::post_accept(data, main_socket, nullptr, nullptr, 0);
            data->cv.wait(lock);
            return data;
        }

        TcpNetworkBlocking* accept_blocking(bool ignore_acceptors = false) {
            return new TcpNetworkBlockingImpl(base_accept(ignore_acceptors));
        }

        TcpNetworkStream* accept_stream(bool ignore_acceptors = false) {
            return new TcpNetworkStreamImpl(base_accept(ignore_acceptors));
        }

        void _await() {
            mutex_unify um(safety);
            std::unique_lock lock(um);
            if (corrupted)
                throw std::runtime_error("TcpNetworkManager is corrupted");
            while (!disabled)
                state_changed_cv.wait(lock);
        }

        void set_configuration(const TcpConfiguration& config) {
            if (corrupted)
                throw std::runtime_error("TcpNetworkManager is corrupted");
            this->config = config;
        }

        void set_accept_filter(std::function<bool(address&, address&)>&& filter) {
            if (corrupted)
                throw std::runtime_error("TcpNetworkManager is corrupted");
            std::lock_guard lock(safety);
            this->accept_filter = std::move(filter);
        }

        bool is_corrupted() {
            return corrupted;
        }

        uint16_t port() {
            if (corrupted)
                throw std::runtime_error("TcpNetworkManager is corrupted");
            return htons(connectionAddress.sin6_port);
        }

        std::string ip() {
            return get_address().to_string();
        }

        address get_address() {
            if (corrupted)
                throw std::runtime_error("TcpNetworkManager is corrupted");

            sockaddr_storage addr;
            memset((char*)&addr, 0, sizeof(sockaddr_storage));
            memcpy(&addr, &connectionAddress, sizeof(sockaddr_in6));
            return to_address(addr);
        }

        bool is_paused() {
            return !disabled && !allow_new_connections;
        }

        bool in_run() {
            return !disabled;
        }
    };

    class TcpClientManager : public util::native_worker_manager {
        task_mutex mutex;
        sockaddr_in6 connectionAddress;
        tcp_handle* _handle;
        bool corrupted = false;

    public:
        void handle(util::native_worker_handle* overlapped, io_uring_cqe* cqe) override {
            tcp_handle& handle = *(tcp_handle*)overlapped;
            if (cqe->res < 0)
                handle.aerrno = -cqe->res;

            if (handle.opcode == tcp_handle::Opcode::ACCEPT)
                handle.cv.notify_all();
            else
                handle.handle(cqe->res, cqe->res < 0 ? -cqe->res : 0);
        }

        TcpClientManager(sockaddr_in6& _connectionAddress, const TcpConfiguration& config)
            : connectionAddress(_connectionAddress) {
            SOCKET clientSocket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
            if (clientSocket == INVALID_SOCKET) {
                corrupted = true;
                return;
            }
            int cfg = config.recv_timeout_ms;
            if (setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, &cfg, sizeof(cfg)) == -1) {
                corrupted = true;
                return;
            }
            cfg = config.connection_timeout_ms ? config.connection_timeout_ms : config.recv_timeout_ms;
            if (setsockopt(clientSocket, SOL_SOCKET, SO_SNDTIMEO, &cfg, sizeof(cfg)) == -1) {
                corrupted = true;
                return;
            }
            cfg = config.enable_keep_alive;
            if (setsockopt(clientSocket, SOL_SOCKET, SO_KEEPALIVE, &cfg, sizeof(cfg)) == -1) {
                corrupted = true;
                return;
            }
            if (config.enable_keep_alive) {
                int cfg = config.keep_alive_settings.idle_ms;
                if (setsockopt(clientSocket, IPPROTO_TCP, TCP_KEEPIDLE, &cfg, sizeof(cfg)) == -1) {
                    corrupted = true;
                    return;
                }
                cfg = config.keep_alive_settings.interval_ms;
                if (setsockopt(clientSocket, IPPROTO_TCP, TCP_KEEPINTVL, &cfg, sizeof(cfg)) == -1) {
                    corrupted = true;
                    return;
                }
                cfg = config.keep_alive_settings.retry_count;
                if (setsockopt(clientSocket, IPPROTO_TCP, TCP_KEEPCNT, &cfg, sizeof(cfg)) == -1) {
                    corrupted = true;
                    return;
                }
                cfg = config.keep_alive_settings.user_timeout_ms;
                if (setsockopt(clientSocket, IPPROTO_TCP, TCP_USER_TIMEOUT, &cfg, sizeof(cfg)) == -1) {
                    corrupted = true;
                    return;
                }
            }
            int argp = 1;
            if (ioctl(clientSocket, FIONBIO, &argp) == -1) {
                corrupted = true;
                return;
            }
            _handle = new tcp_handle(clientSocket, config.buffer_size, this);
            mutex_unify umutex(_handle->cv_mutex);
            std::unique_lock<mutex_unify> lock(umutex);
            util::native_workers_singleton::post_connect(_handle, clientSocket, (sockaddr*)&connectionAddress, sizeof(connectionAddress));
            if (config.connection_timeout_ms > 0) {
                if (!_handle->cv.wait_for(lock, config.connection_timeout_ms)) {
                    corrupted = true;
                    _handle->reset();
                    return;
                }
            } else
                _handle->cv.wait(lock);
            cfg = config.send_timeout_ms;
            if (setsockopt(clientSocket, IPPROTO_TCP, SO_SNDTIMEO, &cfg, sizeof(cfg)) == -1) {
                corrupted = true;
                return;
            }
        }

        TcpClientManager(sockaddr_in6& _connectionAddress, char* data, uint32_t len, const TcpConfiguration& config)
            : connectionAddress(_connectionAddress), _handle(nullptr) {
            SOCKET clientSocket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
            if (clientSocket == INVALID_SOCKET) {
                corrupted = true;
                return;
            }
            int argp = 1;
            int cfg = config.recv_timeout_ms;
            if (setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, &cfg, sizeof(cfg)) == -1) {
                corrupted = true;
                return;
            }
            cfg = config.send_timeout_ms;
            if (setsockopt(clientSocket, SOL_SOCKET, SO_SNDTIMEO, &cfg, sizeof(cfg)) == -1) {
                corrupted = true;
                return;
            }
            cfg = config.enable_keep_alive;
            if (setsockopt(clientSocket, SOL_SOCKET, SO_KEEPALIVE, &cfg, sizeof(cfg)) == -1) {
                corrupted = true;
                return;
            }
            if (config.enable_keep_alive) {
                int cfg = config.keep_alive_settings.idle_ms;
                if (setsockopt(clientSocket, IPPROTO_TCP, TCP_KEEPIDLE, &cfg, sizeof(cfg)) == -1) {
                    corrupted = true;
                    return;
                }
                cfg = config.keep_alive_settings.interval_ms;
                if (setsockopt(clientSocket, IPPROTO_TCP, TCP_KEEPINTVL, &cfg, sizeof(cfg)) == -1) {
                    corrupted = true;
                    return;
                }
                cfg = config.keep_alive_settings.retry_count;
                if (setsockopt(clientSocket, IPPROTO_TCP, TCP_KEEPCNT, &cfg, sizeof(cfg)) == -1) {
                    corrupted = true;
                    return;
                }
                cfg = config.keep_alive_settings.user_timeout_ms;
                if (setsockopt(clientSocket, IPPROTO_TCP, TCP_USER_TIMEOUT, &cfg, sizeof(cfg)) == -1) {
                    corrupted = true;
                    return;
                }
            }
            if (ioctl(clientSocket, FIONBIO, &argp) == -1) {
                corrupted = true;
                return;
            }
            _handle = new tcp_handle(clientSocket, 4096, this);
            char* old_buffer = _handle->data;
            _handle->data = data;
            _handle->buffer.buf = data;
            _handle->buffer.len = len;
            _handle->total_bytes = len;
            _handle->opcode = tcp_handle::Opcode::WRITE;
            mutex_unify umutex(_handle->cv_mutex);
            std::unique_lock<mutex_unify> lock(umutex);
            util::native_workers_singleton::post_sendto(_handle, clientSocket, _handle->buffer.buf, _handle->buffer.len, MSG_FASTOPEN, (sockaddr*)&connectionAddress, sizeof(connectionAddress));
            if (config.connection_timeout_ms > 0) {
                if (!_handle->cv.wait_for(lock, config.connection_timeout_ms)) {
                    corrupted = true;
                    _handle->data = old_buffer;
                    _handle->reset();
                    return;
                }
            } else
                _handle->cv.wait(lock);
            _handle->data = old_buffer;
        }

        ~TcpClientManager() noexcept(false) override {
            if (corrupted)
                return;
            delete _handle;
        }

        void set_configuration(const TcpConfiguration& config) {
            if (corrupted)
                throw std::runtime_error("TcpClientManager::set_configuration, corrupted");
            if (_handle) {
                SOCKET clientSocket = _handle->socket;
                int cfg = config.recv_timeout_ms;
                if (setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, &cfg, sizeof(cfg)) == -1) {
                    corrupted = true;
                    return;
                }
                cfg = config.send_timeout_ms;
                if (setsockopt(clientSocket, SOL_SOCKET, SO_SNDTIMEO, &cfg, sizeof(cfg)) == -1) {
                    corrupted = true;
                    return;
                }
                cfg = config.enable_keep_alive;
                if (setsockopt(clientSocket, SOL_SOCKET, SO_KEEPALIVE, &cfg, sizeof(cfg)) == -1) {
                    corrupted = true;
                    return;
                }
                if (config.enable_keep_alive) {
                    int cfg = config.keep_alive_settings.idle_ms;
                    if (setsockopt(clientSocket, IPPROTO_TCP, TCP_KEEPIDLE, &cfg, sizeof(cfg)) == -1) {
                        corrupted = true;
                        return;
                    }
                    cfg = config.keep_alive_settings.interval_ms;
                    if (setsockopt(clientSocket, IPPROTO_TCP, TCP_KEEPINTVL, &cfg, sizeof(cfg)) == -1) {
                        corrupted = true;
                        return;
                    }
                    cfg = config.keep_alive_settings.retry_count;
                    if (setsockopt(clientSocket, IPPROTO_TCP, TCP_KEEPCNT, &cfg, sizeof(cfg)) == -1) {
                        corrupted = true;
                        return;
                    }
                    cfg = config.keep_alive_settings.user_timeout_ms;
                    if (setsockopt(clientSocket, IPPROTO_TCP, TCP_USER_TIMEOUT, &cfg, sizeof(cfg)) == -1) {
                        corrupted = true;
                        return;
                    }
                }
                if (config.buffer_size > 0 && config.buffer_size != _handle->data_len) {
                    _handle->data_len = config.buffer_size == (int)config.buffer_size ? (int)config.buffer_size : INT_MAX;
                    delete[] _handle->data;
                    _handle->data = new char[_handle->data_len];
                    _handle->buffer.buf = _handle->data;
                    _handle->buffer.len = _handle->data_len;
                }
            }
        }

        int32_t read(char* data, int32_t len) {
            if (corrupted)
                throw std::runtime_error("TcpClientManager::read, corrupted");
            std::lock_guard<task_mutex> lock(mutex);
            int32_t readed = 0;
            while (!_handle->available_bytes())
                if (!_handle->send_queue_item())
                    break;
            _handle->read_available(data, len, readed);
            return readed;
        }

        bool write(const char* data, int32_t len) {
            if (corrupted)
                throw std::runtime_error("TcpClientManager::write, corrupted");
            std::lock_guard<task_mutex> lock(mutex);
            _handle->send_data(data, len);
            while (!_handle->available_bytes())
                if (!_handle->send_queue_item())
                    break;
            return _handle->valid();
        }

        bool write_file(const char* path, size_t len, uint64_t data_len, uint64_t offset, uint32_t chunks_size) {
            if (corrupted)
                throw std::runtime_error("TcpClientManager::write_file, corrupted");
            std::lock_guard<task_mutex> lock(mutex);
            while (!_handle->available_bytes())
                if (!_handle->send_queue_item())
                    break;
            return _handle->send_file(path, len, data_len, offset, chunks_size);
        }

        bool write_file(int handle, uint64_t data_len, uint64_t offset, uint32_t chunks_size) {
            if (corrupted)
                throw std::runtime_error("TcpClientManager::write_file, corrupted");
            std::lock_guard<task_mutex> lock(mutex);
            while (!_handle->available_bytes())
                if (!_handle->send_queue_item())
                    break;
            return _handle->send_file(handle, data_len, offset, chunks_size);
        }

        void close() {
            if (corrupted)
                throw std::runtime_error("TcpClientManager::close, corrupted");
            std::lock_guard<task_mutex> lock(mutex);
            _handle->close();
        }

        void reset() {
            if (corrupted)
                throw std::runtime_error("TcpClientManager::close, corrupted");
            std::lock_guard<task_mutex> lock(mutex);
            _handle->reset();
        }

        bool is_corrupted() {
            return corrupted;
        }

        void rebuffer(uint32_t size) {
            if (corrupted)
                throw std::runtime_error("TcpClientManager::rebuffer, corrupted");
            std::lock_guard<task_mutex> lock(mutex);
            _handle->rebuffer(size);
        }
    };

    class udp_handle : public util::native_worker_handle, public util::native_worker_manager {
        std::shared_ptr<task> notify_task;
        SOCKET socket;
        sockaddr_in6 server_address;

    public:
        uint32_t fullifed_bytes;
        uint32_t last_error;

        udp_handle(sockaddr_in6& address, uint32_t timeout_ms)
            : util::native_worker_handle(this), last_error(0), fullifed_bytes(0) {
            socket = ::socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
            if (socket == INVALID_SOCKET)
                return;
            if (bind(socket, (sockaddr*)&address, sizeof(sockaddr_in6)) == -1) {
                close(socket);
                socket = INVALID_SOCKET;
                return;
            }
            server_address = address;
        }

        void handle(util::native_worker_handle* overlapped, io_uring_cqe* cqe) override {
            this->fullifed_bytes = cqe->res > -1 ? cqe->res : 0;
            this->last_error = cqe->res > -1 ? 0 : errno;
            task::start(notify_task);
        }

        void recv(uint8_t* data, uint32_t size, sockaddr_storage& sender, int& sender_len) {
            if (socket == INVALID_SOCKET)
                throw std::runtime_error("Socket not connected");
            notify_task = task::dummy_task();
            socklen_t sender_len_ = 0;
            util::native_workers_singleton::post_recvfrom(this, socket, data, size, 0, (sockaddr*)&sender, &sender_len_);
            task::await_task(notify_task);
            sender_len = sender_len_;
            notify_task = nullptr;
        }

        void send(uint8_t* data, uint32_t size, sockaddr_storage& to) {
            if (socket == INVALID_SOCKET)
                throw std::runtime_error("Socket not connected");
            notify_task = task::dummy_task();
            util::native_workers_singleton::post_sendto(this, socket, data, size, 0, (sockaddr*)&to, sizeof(sockaddr_in6));
            task::await_task(notify_task);
            notify_task = nullptr;
        }

        address local_address() {
            universal_address addr;
            socklen_t socklen = sizeof(universal_address);
            if (getsockname(socket, (sockaddr*)&addr, &socklen) == -1)
                return {};
            return to_address(addr);
        }

        address remote_address() {
            universal_address addr;
            socklen_t socklen = sizeof(universal_address);
            if (getpeername(socket, (sockaddr*)&addr, &socklen) == -1)
                return {};
            return to_address(addr);
        }
    };

    #pragma endregion

    uint8_t init_networking() {
        inited = true;
        return 0;
    }

    void deinit_networking() {
        inited = false;
    }
#endif

    TcpNetworkServer::TcpNetworkServer(std::function<void(TcpNetworkBlocking&)> on_connect, const address& ip_port, size_t acceptors, const TcpConfiguration& config) {
        if (!inited)
            throw std::runtime_error("Network module not initialized");
        handle = new TcpNetworkManager(ip_port, acceptors, config);
        handle->set_on_connect(on_connect);
    }

    TcpNetworkServer::TcpNetworkServer(std::function<void(TcpNetworkStream&)> on_connect, const address& ip_port, size_t acceptors, const TcpConfiguration& config) {
        if (!inited)
            throw std::runtime_error("Network module not initialized");
        handle = new TcpNetworkManager(ip_port, acceptors, config);
        handle->set_on_connect(on_connect);
    }

    TcpNetworkServer::~TcpNetworkServer() {
        if (handle)
            delete handle;
        handle = nullptr;
    }

    void TcpNetworkServer::start() {
        handle->start();
    }

    void TcpNetworkServer::pause() {
        handle->pause();
    }

    void TcpNetworkServer::resume() {
        handle->resume();
    }

    void TcpNetworkServer::stop() {
        handle->shutdown();
    }

    bool TcpNetworkServer::is_running() {
        return handle->in_run();
    }

    TcpNetworkBlocking* TcpNetworkServer::accept_blocking(bool ignore_acceptors) {
        return handle->accept_blocking(ignore_acceptors);
    }

    TcpNetworkStream* TcpNetworkServer::accept_stream(bool ignore_acceptors) {
        return handle->accept_stream(ignore_acceptors);
    }

    void TcpNetworkServer::_await() {
        handle->_await();
    }

    bool TcpNetworkServer::is_corrupted() {
        return handle->is_corrupted();
    }

    uint16_t TcpNetworkServer::server_port() {
        return handle->port();
    }

    std::string TcpNetworkServer::server_ip() {
        return handle->ip();
    }

    address TcpNetworkServer::server_address() {
        return handle->get_address();
    }

    bool TcpNetworkServer::is_paused() {
        return handle->is_paused();
    }

    void TcpNetworkServer::set_configuration(const TcpConfiguration& config) {
        if (handle)
            handle->set_configuration(config);
    }

    void TcpNetworkServer::set_accept_filter(std::function<bool(address&, address&)>&& filter) {
        if (handle)
            handle->set_accept_filter(std::move(filter));
    }

    TcpClientSocket::TcpClientSocket()
        : handle(nullptr) {}

    TcpClientSocket::~TcpClientSocket() {
        if (handle)
            delete handle;
        handle = nullptr;
    }

    TcpClientSocket* TcpClientSocket::connect(const address& ip_port, const TcpConfiguration& configuration) {
        if (!inited)
            throw std::runtime_error("Network module not initialized");
        sockaddr_storage& address = from_address(ip_port);
        std::unique_ptr<TcpClientSocket> result;
        result.reset(new TcpClientSocket());
        result->handle = new TcpClientManager((sockaddr_in6&)address, configuration);
        return result.release();
    }

    TcpClientSocket* TcpClientSocket::connect(const address& ip_port, char* data, uint32_t size, const TcpConfiguration& configuration) {
        if (!inited)
            throw std::runtime_error("Network module not initialized");
        sockaddr_storage& address = from_address(ip_port);
        std::unique_ptr<TcpClientSocket> result;
        result.reset(new TcpClientSocket());
        result->handle = new TcpClientManager((sockaddr_in6&)address, data, size, configuration);
        return result.release();
    }

    void TcpClientSocket::set_configuration(const TcpConfiguration& config) {
        if (handle)
            handle->set_configuration(config);
    }

    int32_t TcpClientSocket::recv(uint8_t* data, int32_t size) {
        if (!inited)
            throw std::runtime_error("Network module not initialized");

        if (handle)
            return handle->read((char*)data, size);
        return 0;
    }

    bool TcpClientSocket::send(uint8_t* data, int32_t size) {
        if (!inited)
            throw std::runtime_error("Network module not initialized");
        if (handle)
            return handle->write((char*)data, size);
        return false;
    }

    bool TcpClientSocket::send_file(const char* file_path, size_t file_path_len, uint64_t data_len, uint64_t offset, uint32_t chunks_size) {
        if (!handle)
            throw std::runtime_error("Socket not connected");
        return handle->write_file(file_path, file_path_len, data_len, offset, chunks_size);
    }

    bool TcpClientSocket::send_file(class fast_task::files::FileHandle& file, uint64_t data_len, uint64_t offset, uint32_t chunks_size) {
        if (!handle)
            throw std::runtime_error("Socket not connected");
        return handle->write_file(file.internal_get_handle(), data_len, offset, chunks_size);
    }

    void TcpClientSocket::close() {
        if (handle) {
            handle->close();
            delete handle;
            handle = nullptr;
        }
    }

    void TcpClientSocket::reset() {
        if (handle) {
            handle->reset();
            delete handle;
            handle = nullptr;
        }
    }

    void TcpClientSocket::rebuffer(int32_t size) {
        if (handle)
            handle->rebuffer(size);
    }

    udp_socket::udp_socket(const address& ip_port, uint32_t timeout_ms) {
        handle = new udp_handle((sockaddr_in6&)from_address(ip_port), timeout_ms);
    }

    udp_socket::~udp_socket() {
        if (handle)
            delete handle;
    }

    uint32_t udp_socket::recv(uint8_t* data, uint32_t size, address& sender) {
        sockaddr_storage& sender_address = from_address(sender);
        int sender_len = sizeof(sender_address);
        handle->recv(data, size, sender_address, sender_len);
        if (handle->fullifed_bytes == 0 && handle->last_error != 0)
            throw std::runtime_error("Error while receiving data from udp socket with error code: " + std::to_string(handle->last_error));
        return handle->fullifed_bytes;
    }

    uint32_t udp_socket::send(uint8_t* data, uint32_t size, address& to) {
        sockaddr_storage& to_ip_port = from_address(to);
        handle->send(data, size, to_ip_port);
        if (handle->fullifed_bytes == 0 && handle->last_error != 0)
            throw std::runtime_error("Error while receiving data from udp socket with error code: " + std::to_string(handle->last_error));
        return handle->fullifed_bytes;
    }

    address udp_socket::local_address() {
        if (!handle)
            return {};
        return handle->local_address();
    }

    address udp_socket::remote_address() {
        if (!handle)
            return {};
        return handle->remote_address();
    }

    bool ipv6_supported() {
        if (!inited)
            throw std::runtime_error("Network module not initialized");
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