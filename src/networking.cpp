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
    #include <netdb.h>
    #include <netinet/tcp.h>
    #include <sys/ioctl.h>
    #include <sys/mman.h>
    #include <sys/socket.h>
    #include <sys/types.h>
#endif

#include <condition_variable>
#include <files.hpp>
#include <filesystem>
#include <functional>
#include <networking.hpp>
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
        static bool win_fns_inited = false;
        if (win_fns_inited)
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


        win_fns_inited = true;
    }

    #pragma region TCP

    struct tcp_handle_2 {
        struct operation : public util::native_worker_handle {
            std::shared_ptr<task_mutex> cv_mutex;
            task_condition_variable cv;
            WSABUF buffer;
            tcp_handle_2* self;
            unsigned long transferred = 0;
            bool accept_flag = false;
            bool close_flag = false;

            operation(tcp_handle_2* self, const std::shared_ptr<task_mutex>& lock, util::native_worker_manager* manager) : util::native_worker_handle(manager), cv_mutex(lock), self(self), buffer{} {}

            void handle(void* _, unsigned long dwBytesTransferred, util::native_worker_handle* overlap) {
                fast_task::unique_lock lock(*cv_mutex);
                auto res = static_cast<operation*>(overlap);
                res->transferred = dwBytesTransferred;
                res->cv.notify_all();
            }
        };

        std::shared_ptr<task_mutex> cv_mutex = std::make_shared<task_mutex>();
        util::native_worker_manager* manager;
        ::SOCKET socket;
        int32_t buffer_size = 0x1000;
        std::vector<char>* temp_read_buffer = nullptr;
        tcp_error invalid_reason = tcp_error::none;
        bool bound = false;
        bool delayed_buffer_clean = false;

        tcp_handle_2(SOCKET socket, int32_t buffer_len, util::native_worker_manager* manager)
            : manager(manager), socket(socket), buffer_size(buffer_len) {
            if (buffer_len < 0)
                buffer_size = 0x1000;
        }

        ~tcp_handle_2() {
            close();
        }

        uint32_t bytes_available_count() {
            fast_task::unique_lock lock(*cv_mutex);
            if (temp_read_buffer)
                return (uint32_t)std::min<size_t>(temp_read_buffer->size(), UINT32_MAX);
            DWORD value = 0;
            int result = ::ioctlsocket(socket, FIONREAD, &value);
            if (result == SOCKET_ERROR)
                return 0;
            else
                return value;
        }

        bool bytes_available() {
            return bytes_available_count() > 0;
        }

        int send(const char* data, int len) {
            if (!valid())
                return 0;

            auto op = std::make_unique<operation>(this, cv_mutex, manager);
            op->buffer.buf = (CHAR*)data;
            op->buffer.len = len;
            DWORD sent = 0;
            mutex_unify mutex(*cv_mutex);
            fast_task::unique_lock lock(mutex);
            auto res = WSASend(socket, &op->buffer, 1, &sent, 0, &op->overlapped, NULL);
            if (res) {
                if (!handle_error(lock, invalid_reason))
                    return 0;
            }
            op->cv.wait(lock);
            return op->transferred;
        }

        void read(char* extern_buffer, int buffer_len, int& readed) {
            if (!valid()) {
                readed = 0;
                return;
            }
            auto op = std::make_unique<operation>(this, cv_mutex, manager);
            op->buffer.buf = extern_buffer;
            op->buffer.len = buffer_len;
            readed = 0;
            DWORD flags = 0, recvd = 0;
            mutex_unify mutex(*cv_mutex);
            fast_task::unique_lock lock(mutex);
            if (temp_read_buffer) {
                if (!delayed_buffer_clean) {
                    auto to_read = std::min<size_t>(temp_read_buffer->size(), buffer_len);
                    std::memcpy(extern_buffer, temp_read_buffer->data(), to_read);
                    readed = (int)to_read;
                    temp_read_buffer->erase(temp_read_buffer->begin(), temp_read_buffer->begin() + to_read);
                    if (temp_read_buffer->empty()) {
                        delete temp_read_buffer;
                        temp_read_buffer = nullptr;
                    }
                    return;
                } else {
                    delete temp_read_buffer;
                    temp_read_buffer = nullptr;
                }
            }
            auto res = WSARecv(socket, &op->buffer, 1, &recvd, &flags, &op->overlapped, NULL);
            if (res) {
                if (!handle_error(lock, invalid_reason))
                    return;
            }
            op->cv.wait(lock);
            readed = op->transferred;
        }

        void read_fixed(char* extern_buffer, int buffer_len) {
            while (valid() && buffer_len) {
                int readed = 0;
                read(extern_buffer, buffer_len, readed);
                extern_buffer += readed;
                buffer_len -= readed;
            }
        }

        char* read_no_copy(unsigned long& readed) {
            if (!valid()) {
                readed = 0;
                return nullptr;
            }
            bool reuse_buf = false;
            fast_task::unique_lock lock(*cv_mutex);
            if (temp_read_buffer) {
                if (!delayed_buffer_clean) {
                    readed = (uint32_t)std::min<size_t>(temp_read_buffer->size(), UINT32_MAX);
                    delayed_buffer_clean = true;
                    return temp_read_buffer->data();
                } else {
                    if (buffer_size != temp_read_buffer->size()) {
                        delete temp_read_buffer;
                        temp_read_buffer = nullptr;
                    } else
                        reuse_buf = true;
                }
            }
            std::vector<char> buf;
            if (reuse_buf) {
                buf = std::move(*temp_read_buffer);
            } else
                buf = std::vector<char>(buffer_size);
            lock.unlock();
            int _readed = 0;
            read(buf.data(), (int)buf.size(), _readed);
            if (_readed) {
                buf.resize(_readed);
                readed = _readed;
                lock.lock();
                temp_read_buffer = new std::vector<char>(std::move(buf));
                delayed_buffer_clean = true;
                return temp_read_buffer->data();
            } else {
                readed = 0;
                return nullptr;
            }
        }

        void close(fast_task::unique_lock<mutex_unify>& lock, tcp_error err = tcp_error::local_close) {
            if (!valid())
                return;
            invalid_reason = err;
            internal_close(lock);
        }

        void close(tcp_error err = tcp_error::local_close) {
            mutex_unify mutex(*cv_mutex);
            fast_task::unique_lock lock(mutex);
            close(lock, err);
        }

        void send_and_close(const char* data, int len) {
            send(data, len);
            close();
        }

        bool send_file(void* file, uint64_t data_len, uint64_t offset, uint32_t chunks_size) {
            if (!valid())
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
                uint32_t last_block = data_len % 0x7FFFFFFE;

                while (blocks--)
                    if (!transfer_file(socket, file, 0x7FFFFFFE, chunks_size, sended + offset))
                        return false;
                    else
                        sended += 0x7FFFFFFE;


                if (last_block)
                    if (!transfer_file(socket, file, last_block, chunks_size, sended + offset))
                        return false;
            } else {
                if (!transfer_file(socket, file, (uint32_t)data_len, chunks_size, offset))
                    return false;
            }
            return true;
        }

        bool send_file(const char* path, size_t path_len, uint64_t data_len, uint64_t offset, uint32_t chunks_size) {
            if (!valid())
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
            return socket != INVALID_SOCKET && invalid_reason == tcp_error::none;
        }

        void reset() {
            mutex_unify mutex(*cv_mutex);
            fast_task::unique_lock lock(mutex);
            if (!valid())
                return;
            invalid_reason = tcp_error::local_reset;
            closesocket(socket); //with iocp socket not send everything and cancel all operations
        }

        void connection_reset() {
            mutex_unify mutex(*cv_mutex);
            fast_task::unique_lock lock(mutex);
            invalid_reason = tcp_error::remote_close;
            internal_close(lock);
        }

        void rebuffer(int32_t buffer_len) {
            if (buffer_len < 0)
                throw std::invalid_argument("buffer_len must be positive");
            if (buffer_len == 0)
                buffer_len = 0x1000;
            if (buffer_len == buffer_size)
                return;
            fast_task::unique_lock lock(*cv_mutex);
            if (!valid())
                return;
            buffer_size = buffer_len;
        }

    private:
        void internal_close(fast_task::unique_lock<mutex_unify>& lock) {
            auto op = std::make_unique<operation>(this, cv_mutex, manager);
            op->close_flag = true;
            shutdown(socket, SD_BOTH);
            if (!_DisconnectEx(socket, &op->overlapped, TF_REUSE_SOCKET, 0)) {
                if (WSAGetLastError() != ERROR_IO_PENDING)
                    invalid_reason = tcp_error::local_close;
                op->cv.wait(lock);
            }
            closesocket(socket);
            socket = INVALID_SOCKET;
        }

        bool handle_error(fast_task::unique_lock<mutex_unify>& lock, tcp_error& reason) {
            auto error = WSAGetLastError();
            if (WSA_IO_PENDING == error)
                return true;
            else {
                switch (error) {
                case WSAECONNRESET:
                    reason = tcp_error::remote_close;
                    break;
                case WSAECONNABORTED:
                case WSA_OPERATION_ABORTED:
                case WSAENETRESET:
                    reason = tcp_error::local_close;
                    break;
                case WSAEWOULDBLOCK:
                    return false; //try later
                default:
                    reason = tcp_error::undefined_error;
                    break;
                }
                close(lock);
                return false;
            }
        }

        bool transfer_file(SOCKET sock, HANDLE FILE, uint32_t block, uint32_t chunks_size, uint64_t offset) {
            auto op = std::make_unique<operation>(this, cv_mutex, manager);
            op->overlapped.Offset = offset & 0xFFFFFFFF;
            op->overlapped.OffsetHigh = offset >> 32;
            mutex_unify mutex(*cv_mutex);
            fast_task::unique_lock lock(mutex);
            if (!valid())
                return false;
            bool res = _TransmitFile(sock, FILE, block, chunks_size, &op->overlapped, NULL, TF_USE_KERNEL_APC | TF_WRITE_BEHIND);
            if (!res)
                if (!handle_error(lock, invalid_reason))
                    return false;
            if (res)
                op->cv.wait(lock);
            return res;
        }
    };

    #pragma region tcp_network_stream

    class tcp_network_streamImpl : public tcp_network_stream {
        friend class tcp_network_manager;
        struct tcp_handle_2* handle;
        task_rw_mutex mutex;
        tcp_error last_error;

        bool checkup() {
            if (!handle)
                return false;
            if (!handle->valid()) {
                last_error = handle->invalid_reason;
                return false;
            }
            return true;
        }

    public:
        tcp_network_streamImpl(tcp_handle_2* handle)
            : handle(handle), last_error(tcp_error::none) {}

        ~tcp_network_streamImpl() override {
            if (checkup()) {
                write_lock lg(mutex);
                handle->close();
                delete handle;
            }
            handle = nullptr;
        }

        std::span<char> read_available_ref() override {
            read_lock lock(mutex);
            if (!checkup())
                return {};
            unsigned long readed = 0;
            char* data = handle->read_no_copy(readed);
            return {data, (size_t)readed};
        }

        int read_available(char* buffer, int buffer_len) override {
            read_lock lock(mutex);
            if (!checkup())
                return 0;
            int readed = 0;
            handle->read(buffer, buffer_len, readed);
            return readed;
        }

        bool data_available() override {
            read_lock lock(mutex);
            if (checkup())
                return handle->bytes_available();
            return false;
        }

        void write(const char* data, size_t size) override {
            read_lock lock(mutex);
            if (checkup()) {
                while (size && handle->valid()) {
                    auto to_send = (int32_t)std::min<size_t>(size, INT32_MAX);
                    handle->send(data, to_send);
                    size -= to_send;
                    data += to_send;
                    if (!handle->valid())
                        last_error = handle->invalid_reason;
                }
            }
        }

        bool write_file(char* path, size_t path_len, uint64_t data_len, uint64_t offset, uint32_t chunks_size) override {
            read_lock lock(mutex);
            if (checkup())
                return handle->send_file(path, path_len, data_len, offset, chunks_size);
            return false;
        }

        bool write_file(void* fhandle, uint64_t data_len, uint64_t offset, uint32_t chunks_size) override {
            read_lock lock(mutex);
            if (checkup())
                return handle->send_file(fhandle, data_len, offset, chunks_size);
            return false;
        }

        //write all data from write_queue
        void force_write() override {
        }

        void force_write_and_close(const char* data, size_t size) override {
            read_lock lock(mutex);
            if (checkup()) {
                while (size && handle->valid()) {
                    auto to_send = (int32_t)std::min<size_t>(size, INT32_MAX);
                    if (to_send == size)
                        handle->send_and_close(data, to_send);
                    else
                        handle->send(data, to_send);
                    size -= to_send;
                    data += to_send;
                    if (!handle->valid())
                        last_error = handle->invalid_reason;
                }
                last_error = handle->invalid_reason;
            }
        }

        void close() override {
            read_lock lock(mutex);
            if (checkup()) {
                handle->close();
                last_error = handle->invalid_reason;
            }
        }

        void reset() override {
            read_lock lock(mutex);
            if (checkup()) {
                handle->reset();
                last_error = handle->invalid_reason;
            }
        }

        void rebuffer(int32_t new_size) override {
            read_lock lock(mutex);
            if (checkup())
                handle->rebuffer(new_size);
        }

        bool is_closed() override {
            read_lock lock(mutex);
            return handle ? !handle->valid() : true;
        }

        tcp_error error() override {
            read_lock lock(mutex);
            if (checkup())
                return handle->invalid_reason;
            return last_error;
        }

        address local_address() override {
            write_lock lg(mutex);
            if (!checkup())
                return {};
            universal_address addr;
            int socklen = sizeof(universal_address);
            if (getsockname(handle->socket, (sockaddr*)&addr, &socklen) == -1)
                return {};
            return to_address(addr);
        }

        address remote_address() override {
            write_lock lg(mutex);
            if (!checkup())
                return {};
            universal_address addr;
            int socklen = sizeof(universal_address);
            if (getpeername(handle->socket, (sockaddr*)&addr, &socklen) == -1)
                return {};
            return to_address(addr);
        }
    };

    #pragma endregion

    #pragma region tcp_network_blocking

    class tcp_network_blockingImpl : public tcp_network_blocking {
        friend class tcp_network_manager;
        tcp_handle_2* handle;
        task_mutex mutex;
        tcp_error last_error;

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
        tcp_network_blockingImpl(tcp_handle_2* handle)
            : handle(handle), last_error(tcp_error::none) {}

        ~tcp_network_blockingImpl() override {
            fast_task::lock_guard lg(mutex);
            if (handle)
                delete handle;
            handle = nullptr;
        }

        std::vector<char> read(uint32_t len) override {
            fast_task::lock_guard lg(mutex);
            if (checkup()) {
                std::vector<char> buf;
                buf.resize(len);
                handle->read_fixed(buf.data(), len);
                if (len == 0)
                    return {};
                else
                    buf.resize(len);
                return buf;
            }
            return {};
        }

        uint32_t available_bytes() override {
            fast_task::lock_guard lg(mutex);
            if (checkup())
                return handle->bytes_available_count();
            return 0ui32;
        }

        int64_t write(const char* data, uint32_t len) override {
            fast_task::lock_guard lg(mutex);
            if (checkup())
                return handle->send(data, len);
            return 0;
        }

        bool write_file(char* path, size_t len, uint64_t data_len, uint64_t offset, uint32_t block_size) override {
            fast_task::lock_guard lg(mutex);
            if (checkup())
                return handle->send_file(path, len, data_len, offset, block_size);
            return false;
        }

        bool write_file(void* fhandle, uint64_t data_len, uint64_t offset, uint32_t block_size) override {
            fast_task::lock_guard lg(mutex);
            if (checkup())
                return handle->send_file(fhandle, data_len, offset, block_size);
            return false;
        }

        void close() override {
            fast_task::lock_guard lg(mutex);
            if (checkup()) {
                handle->close();
                last_error = handle->invalid_reason;
                delete handle;
                handle = nullptr;
            }
        }

        void reset() override {
            fast_task::lock_guard lg(mutex);
            if (checkup()) {
                handle->reset();
                last_error = handle->invalid_reason;
                delete handle;
                handle = nullptr;
            }
        }

        void rebuffer(int32_t new_size) override {
            fast_task::lock_guard lg(mutex);
            if (checkup())
                handle->rebuffer(new_size);
        }

        bool is_closed() override {
            fast_task::lock_guard lg(mutex);
            if (checkup()) {
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

        tcp_error error() override {
            fast_task::lock_guard lg(mutex);
            if (checkup())
                return handle->invalid_reason;
            return last_error;
        }

        address local_address() override {
            fast_task::lock_guard lg(mutex);
            if (!checkup())
                return {};
            universal_address addr;
            int socklen = sizeof(universal_address);
            if (getsockname(handle->socket, (sockaddr*)&addr, &socklen) == -1)
                return {};
            return to_address(addr);
        }

        address remote_address() override {
            fast_task::lock_guard lg(mutex);
            if (!checkup())
                return {};
            universal_address addr;
            int socklen = sizeof(universal_address);
            if (getpeername(handle->socket, (sockaddr*)&addr, &socklen) == -1)
                return {};
            return to_address(addr);
        }
    };

    #pragma endregion

    class tcp_network_manager : public util::native_worker_manager {
        task_mutex safety;
        std::variant<std::function<void(tcp_network_blocking&)>, std::function<void(tcp_network_stream&)>> handler_fn;
        std::function<bool(address& client, address& server)> accept_filter;
        address _address;
        SOCKET main_socket;

    public:
        tcp_configuration config;

    private:
        bool allow_new_connections = false;
        std::atomic_bool disabled = true;
        bool corrupted = false;
        size_t acceptors;
        task_condition_variable state_changed_cv;

        tcp_handle_2::operation* make_acceptEx(tcp_handle_2* pClientContext) {
        re_try:
            static const auto address_len = sizeof(sockaddr_storage) + 16;

            auto op = new tcp_handle_2::operation(pClientContext, std::make_shared<task_mutex>(), this);
            op->accept_flag = true;
            auto new_sock = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
            pClientContext->socket = new_sock;
            BOOL success;
            if (config.fast_open_queue) {
                op->buffer.len = config.buffer_size;
                op->buffer.buf = new char[op->buffer.len + sizeof(universal_address) + 16 + sizeof(universal_address) + 16];
                success = _AcceptEx(
                    main_socket,
                    new_sock,
                    op->buffer.buf,
                    op->buffer.len,
                    address_len,
                    address_len,
                    nullptr,
                    &op->overlapped
                );
            } else {
                success = _AcceptEx(
                    main_socket,
                    new_sock,
                    nullptr,
                    0,
                    address_len,
                    address_len,
                    nullptr,
                    &op->overlapped
                );
            }
            util::native_workers_singleton::register_handle((HANDLE)new_sock, nullptr);
            if (success == FALSE) {
                auto err = WSAGetLastError();
                if (err == WSA_IO_PENDING)
                    return op;
                else if (err == WSAECONNRESET) {
                    closesocket(new_sock);
                    goto re_try;
                } else {
                    closesocket(new_sock);
                    return op;
                }
            }
            return op;
        }

        void make_acceptEx(void) {
            tcp_handle_2* pClientContext = new tcp_handle_2(0, config.buffer_size, this);
            make_acceptEx(pClientContext); //no memory leak, the tcp_handle_2 destructs itself
        }

        void accepted(tcp_handle_2* self, address&& clientAddr, address&& localAddr) {
            fast_task::lock_guard guard(safety);
            task::run([handler_fn = this->handler_fn, self, clientAddr = std::move(clientAddr), localAddr = std::move(localAddr), allow_new_connections = this->allow_new_connections]() {
                if (!allow_new_connections) {
                    delete self;
                    return;
                }
                std::visit(
                    [&](auto&& f) {
                        using T = std::decay_t<decltype(f)>;
                        if constexpr (std::is_same_v<T, std::function<void(tcp_network_blocking&)>>) {
                            tcp_network_blockingImpl rr(self);
                            f(rr);
                        } else {
                            tcp_network_streamImpl rr(self);
                            f(rr);
                        }
                    },
                    handler_fn
                );
            });
        }

        void new_connection(tcp_handle_2::operation* op, tcp_handle_2& data, bool good) {
            if (!good) {
                closesocket(data.socket);
                data.socket = INVALID_SOCKET;
                if (!data.bound) {
                    delete &data;
                    delete op;
                } else {
                    fast_task::lock_guard guard(*data.cv_mutex);
                    op->cv.notify_all();
                    return;
                }

                if (!disabled)
                    make_acceptEx();
                return;
            }
            if (!data.bound)
                make_acceptEx();

            universal_address* pClientAddr = NULL;
            universal_address* pLocalAddr = NULL;
            int remoteLen = sizeof(universal_address);
            int localLen = sizeof(universal_address);
            _GetAcceptExSockaddrs(op->buffer.buf, op->transferred, sizeof(universal_address) + 16, sizeof(universal_address) + 16, (LPSOCKADDR*)&pLocalAddr, &localLen, (LPSOCKADDR*)&pClientAddr, &remoteLen);
            address clientAddress = to_address(*pClientAddr);
            address localAddress = to_address(*pLocalAddr);
            if (accept_filter) {
                if (accept_filter(clientAddress, localAddress)) {
                    closesocket(data.socket);
                    data.socket = INVALID_SOCKET;
                    if (!data.bound)
                        delete &data;
                    else {
                        fast_task::lock_guard guard(*data.cv_mutex);
                        op->cv.notify_all();
                    }
                    return;
                }
            }

            setsockopt(data.socket, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char*)&main_socket, sizeof(main_socket));
            if (op->buffer.buf) {
                data.temp_read_buffer = new std::vector<char>(op->buffer.buf, op->buffer.buf + op->transferred);
                delete[] (char*)op->buffer.buf;
                op->buffer.buf = nullptr;
            }

            if (data.bound) {
                fast_task::lock_guard guard(*data.cv_mutex);
                op->cv.notify_all();
            } else {
                accepted(&data, std::move(clientAddress), std::move(localAddress));
                delete op;
            }
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
                cfg = config.keep_alive_settings.idle_ms;
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
            if (bind(main_socket, (sockaddr*)_address.get_data(), (int)_address.data_size()) == SOCKET_ERROR) {
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
        tcp_network_manager(const address& ip_port, size_t acceptors, const tcp_configuration& config)
            : _address(ip_port), main_socket(INVALID_SOCKET), config(config), acceptors(acceptors) {
        }

        ~tcp_network_manager() override {
            if (!corrupted)
                shutdown();
        }

        void handle(void* _data, util::native_worker_handle* overlapped, unsigned long dwBytesTransferred) override {
            auto& data = *(tcp_handle_2::operation*)overlapped;
            auto error = (DWORD)overlapped->overlapped.Internal;
            if (data.accept_flag) {
                data.transferred = dwBytesTransferred;
                new_connection(&data, *data.self, !error);
            } else if (0 != dwBytesTransferred && !error)
                data.handle(_data, dwBytesTransferred, &data);
            else {
                {
                    fast_task::lock_guard lock(*data.cv_mutex);
                    data.self->invalid_reason = tcp_error::remote_close;
                    data.cv.notify_all();
                }
                if (!data.close_flag)
                    data.self->connection_reset();
            }
        }

        void set_configuration(const tcp_configuration& tcp) {
            if (corrupted)
                throw std::runtime_error("tcp_network_manager is corrupted");
            fast_task::lock_guard lock(safety);
            config = tcp;
        }

        void set_on_connect(std::function<void(tcp_network_stream&)> handler_fn_) {
            if (corrupted)
                throw std::runtime_error("tcp_network_manager is corrupted");
            fast_task::lock_guard lock(safety);
            handler_fn = handler_fn_;
        }

        void set_on_connect(std::function<void(tcp_network_blocking&)> handler_fn_) {
            if (corrupted)
                throw std::runtime_error("tcp_network_manager is corrupted");
            fast_task::lock_guard lock(safety);
            handler_fn = handler_fn_;
        }

        void shutdown() {
            if (corrupted)
                throw std::runtime_error("tcp_network_manager is corrupted");
            fast_task::lock_guard lock(safety);
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
                throw std::runtime_error("tcp_network_manager is corrupted");
            allow_new_connections = false;
        }

        void resume() {
            if (corrupted)
                throw std::runtime_error("tcp_network_manager is corrupted");
            allow_new_connections = true;
        }

        void start() {
            if (corrupted)
                throw std::runtime_error("tcp_network_manager is corrupted");
            fast_task::lock_guard lock(safety);
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

        tcp_handle_2* base_accept(bool ignore_acceptors) {
            if (!ignore_acceptors && acceptors)
                throw std::runtime_error("Thread tried to accept connection with enabled acceptors and ignore_acceptors = false");
            if (corrupted)
                throw std::runtime_error("tcp_network_manager is corrupted");
            if (disabled)
                throw std::runtime_error("tcp_network_manager is disabled");
            if (!allow_new_connections)
                throw std::runtime_error("tcp_network_manager is paused");
            tcp_handle_2* data = new tcp_handle_2(0, config.buffer_size, this);
            mutex_unify um(*data->cv_mutex);
            fast_task::unique_lock lock(um);
            data->bound = true;
            auto res = make_acceptEx(data);
            res->cv.wait(lock);
            delete res;
            return data;
        }

        tcp_network_blocking* accept_blocking(bool ignore_acceptors = false) {
            return new tcp_network_blockingImpl(base_accept(ignore_acceptors));
        }

        tcp_network_stream* accept_stream(bool ignore_acceptors = false) {
            return new tcp_network_streamImpl(base_accept(ignore_acceptors));
        }

        void _await() {
            mutex_unify um(safety);
            fast_task::unique_lock lock(um);
            if (corrupted)
                throw std::runtime_error("tcp_network_manager is corrupted");
            while (!disabled)
                state_changed_cv.wait(lock);
        }

        void set_accept_filter(std::function<bool(address&, address&)>&& filter) {
            if (corrupted)
                throw std::runtime_error("tcp_network_manager is corrupted");
            fast_task::lock_guard lock(safety);
            this->accept_filter = std::move(filter);
        }

        bool is_corrupted() {
            return corrupted;
        }

        uint16_t port() {
            if (corrupted)
                throw std::runtime_error("tcp_network_manager is corrupted");
            return _address.port();
        }

        std::string ip() {
            return _address.to_string();
        }

        address get_address() {
            if (corrupted)
                throw std::runtime_error("tcp_network_manager is corrupted");

            return _address;
        }

        bool is_paused() {
            return !disabled && !allow_new_connections;
        }

        bool in_run() {
            return !disabled;
        }
    };

    class tcp_client_manager : public util::native_worker_manager {
        task_mutex mutex;
        sockaddr_in6 connectionAddress;
        tcp_handle_2* _handle;
        bool corrupted = false;

        void set_configuration(SOCKET sock, const tcp_configuration& config) {
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
                cfg = config.keep_alive_settings.idle_ms;
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
        void handle(void* _data, util::native_worker_handle* overlapped, unsigned long dwBytesTransferred) override {
            auto& data = *(tcp_handle_2::operation*)overlapped;
            auto error = overlapped->overlapped.Internal;
            if (data.accept_flag) {
                fast_task::lock_guard lock(*data.cv_mutex);
                data.transferred = dwBytesTransferred;
                data.cv.notify_all();
            } else if (0 != dwBytesTransferred && !error)
                data.handle(_data, dwBytesTransferred, &data);
            else
                data.self->connection_reset();
        }

        tcp_client_manager(sockaddr_in6& _connectionAddress, const tcp_configuration& config)
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

            _handle = new tcp_handle_2(clientSocket, config.buffer_size, this);
            auto op = std::make_unique<tcp_handle_2::operation>(_handle, std::make_shared<task_mutex>(), this);
            op->accept_flag = true;
            mutex_unify umutex(*_handle->cv_mutex);
            fast_task::unique_lock<mutex_unify> lock(umutex);
            if (!_ConnectEx(clientSocket, (sockaddr*)&connectionAddress, sizeof(connectionAddress), NULL, 0, nullptr, (OVERLAPPED*)&op->overlapped)) {
                auto err = WSAGetLastError();
                if (err != ERROR_IO_PENDING) {
                    corrupted = true;
                    _handle->reset();
                    return;
                }
            }
            util::native_workers_singleton::register_handle((HANDLE)clientSocket, nullptr);
            if (config.connection_timeout_ms > 0) {
                if (!op->cv.wait_for(lock, config.connection_timeout_ms)) {
                    corrupted = true;
                    _handle->reset();
                    return;
                }
            } else
                op->cv.wait(lock);
        }

        tcp_client_manager(sockaddr_in6& _connectionAddress, char* data, uint32_t len, const tcp_configuration& config)
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

            _handle = new tcp_handle_2(clientSocket, 4096, this);
            auto op = std::make_unique<tcp_handle_2::operation>(_handle, std::make_shared<task_mutex>(), this);
            op->accept_flag = true;
            op->buffer.buf = data;
            op->buffer.len = len;
            mutex_unify umutex(*_handle->cv_mutex);
            fast_task::unique_lock<mutex_unify> lock(umutex);
            if (!_ConnectEx(clientSocket, (sockaddr*)&connectionAddress, sizeof(connectionAddress), data, len, nullptr, (OVERLAPPED*)&op->overlapped)) {
                auto err = WSAGetLastError();
                if (err != ERROR_IO_PENDING) {
                    corrupted = true;
                    return;
                }
            }
            util::native_workers_singleton::register_handle((HANDLE)clientSocket, nullptr);
            if (config.connection_timeout_ms > 0) {
                if (!op->cv.wait_for(lock, config.connection_timeout_ms)) {
                    corrupted = true;
                    _handle->reset();
                    return;
                }
            } else
                op->cv.wait(lock);
        }

        ~tcp_client_manager() override {
            if (corrupted)
                return;
            delete _handle;
        }

        void set_configuration(const tcp_configuration& config) {
            if (corrupted)
                throw std::runtime_error("tcp_client_manager::read, corrupted");
            if (_handle) {
                set_configuration(_handle->socket, config);
                if (!corrupted)
                    _handle->rebuffer((int32_t)std::min<size_t>(config.buffer_size, INT32_MAX));
            }
        }

        int32_t read(char* data, int32_t len) {
            if (corrupted)
                throw std::runtime_error("tcp_client_manager::read, corrupted");
            fast_task::lock_guard<task_mutex> lock(mutex);
            int32_t readed = 0;
            _handle->read(data, len, readed);
            return readed;
        }

        bool write(const char* data, int32_t len) {
            if (corrupted)
                throw std::runtime_error("tcp_client_manager::write, corrupted");
            fast_task::lock_guard<task_mutex> lock(mutex);
            _handle->send(data, len);
            return _handle->valid();
        }

        bool write_file(const char* path, size_t len, uint64_t data_len, uint64_t offset, uint32_t chunks_size) {
            if (corrupted)
                throw std::runtime_error("tcp_client_manager::write_file, corrupted");
            fast_task::lock_guard<task_mutex> lock(mutex);
            return _handle->send_file(path, len, data_len, offset, chunks_size);
        }

        bool write_file(void* handle, uint64_t data_len, uint64_t offset, uint32_t chunks_size) {
            if (corrupted)
                throw std::runtime_error("tcp_client_manager::write_file, corrupted");
            fast_task::lock_guard<task_mutex> lock(mutex);
            return _handle->send_file(handle, data_len, offset, chunks_size);
        }

        void close() {
            if (corrupted)
                throw std::runtime_error("tcp_client_manager::close, corrupted");
            fast_task::lock_guard<task_mutex> lock(mutex);
            _handle->close();
        }

        void reset() {
            if (corrupted)
                throw std::runtime_error("tcp_client_manager::close, corrupted");
            fast_task::lock_guard<task_mutex> lock(mutex);
            _handle->reset();
        }

        bool is_corrupted() {
            return corrupted;
        }

        void rebuffer(int32_t size) {
            if (corrupted)
                throw std::runtime_error("tcp_client_manager::rebuffer, corrupted");
            fast_task::lock_guard<task_mutex> lock(mutex);
            _handle->rebuffer(size);
        }
    };

    #pragma endregion

    class udp_handle : public util::native_worker_handle, public util::native_worker_manager {
        task_mutex mt;
        task_condition_variable cv;
        SOCKET socket;
        sockaddr_in6 server_address;
        bool is_complete = true;

    public:
        DWORD fullifed_bytes;
        DWORD last_error;

        udp_handle(sockaddr_in6& address, uint32_t timeout_ms)
            : util::native_worker_handle(this), server_address{0}, fullifed_bytes(0), last_error(0) {
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

        void handle(void* data, util::native_worker_handle* overlap, unsigned long fullifed_bytes_) override {
            fullifed_bytes = fullifed_bytes_;
            last_error = (DWORD)overlap->overlapped.Internal;
            unique_lock lock(mt);
            is_complete = true;
            cv.notify_all();
        }

        void recv(uint8_t* data, uint32_t size, sockaddr_storage& sender, int& sender_len) {
            if (socket == INVALID_SOCKET)
                throw std::runtime_error("Socket is not connected");
            WSABUF buf;
            buf.buf = (char*)data;
            buf.len = size;
            DWORD flags = 0;
            mutex_unify u(mt);
            unique_lock lock(u);
            while (!is_complete)
                cv.wait(lock);
            is_complete = false;
            if (WSARecvFrom(socket, &buf, 1, nullptr, &flags, (sockaddr*)&sender, &sender_len, (OVERLAPPED*)this, nullptr)) {
                if (WSAGetLastError() != WSA_IO_PENDING) {
                    last_error = WSAGetLastError();
                    fullifed_bytes = 0;
                    return;
                }
            }
            while (!is_complete)
                cv.wait(lock);
            is_complete = false;
        }

        void send(uint8_t* data, uint32_t size, sockaddr_storage& to) {
            WSABUF buf;
            buf.buf = (char*)data;
            buf.len = size;
            mutex_unify u(mt);
            unique_lock lock(u);
            while (!is_complete)
                cv.wait(lock);
            is_complete = false;
            if (WSASendTo(socket, &buf, 1, nullptr, 0, (sockaddr*)&to, sizeof(to), (OVERLAPPED*)this, nullptr)) {
                if (WSAGetLastError() != WSA_IO_PENDING) {
                    last_error = WSAGetLastError();
                    fullifed_bytes = 0;
                    return;
                }
            }
            while (!is_complete)
                cv.wait(lock);
            is_complete = false;
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

    struct tcp_handle_2 {
        struct operation : public util::native_worker_handle {
            std::shared_ptr<task_mutex> cv_mutex;
            task_condition_variable cv;
            tcp_handle_2* self;
            unsigned long transferred = 0;
            int sock_err = 0;
            bool accept_flag = false;
            bool close_flag = false;

            operation(tcp_handle_2* self, const std::shared_ptr<task_mutex>& lock, util::native_worker_manager* manager) : util::native_worker_handle(manager), cv_mutex(lock), self(self) {}

            void handle(unsigned long dwBytesTransferred, int sock_error) {
                fast_task::unique_lock lock(*cv_mutex);
                transferred = dwBytesTransferred;
                sock_err = sock_error;
                cv.notify_all();
            }
        };

        std::shared_ptr<task_mutex> cv_mutex = std::make_shared<task_mutex>();
        util::native_worker_manager* manager;
        SOCKET socket;
        int32_t buffer_size = 0x1000;
        std::vector<char>* temp_read_buffer = nullptr;
        tcp_error invalid_reason = tcp_error::none;
        bool bound = false;
        bool delayed_buffer_clean = false;

        tcp_handle_2(SOCKET socket, int32_t buffer_len, util::native_worker_manager* manager)
            : manager(manager), socket(socket), buffer_size(buffer_len) {
            if (buffer_len < 0)
                buffer_size = 0x1000;
        }

        ~tcp_handle_2() {
            close();
        }

        uint32_t bytes_available_count() {
            fast_task::unique_lock lock(*cv_mutex);
            if (temp_read_buffer)
                return (uint32_t)std::min<size_t>(temp_read_buffer->size(), UINT32_MAX);
            int value = 0;
            int result = ::ioctl(socket, FIONREAD, &value);
            if (result == -1)
                return 0;
            else
                return value;
        }

        bool bytes_available() {
            return bytes_available_count() > 0;
        }

        int send(const char* data, uint32_t len) {
            if (!valid())
                return 0;

            auto op = std::make_unique<operation>(this, cv_mutex, manager);
            mutex_unify mutex(*cv_mutex);
            fast_task::unique_lock lock(mutex);
            util::native_workers_singleton::post_send(op.get(), socket, data, len, 0);
            op->cv.wait(lock);
            handle_error(lock, invalid_reason, op->sock_err);
            return op->transferred;
        }

        void read(char* extern_buffer, uint32_t buffer_len, int& readed) {
            if (!valid()) {
                readed = 0;
                return;
            }
            auto op = std::make_unique<operation>(this, cv_mutex, manager);
            mutex_unify mutex(*cv_mutex);
            fast_task::unique_lock lock(mutex);
            if (temp_read_buffer) {
                if (!delayed_buffer_clean) {
                    auto to_read = std::min<size_t>(temp_read_buffer->size(), buffer_len);
                    std::memcpy(extern_buffer, temp_read_buffer->data(), to_read);
                    readed = (int)to_read;
                    temp_read_buffer->erase(temp_read_buffer->begin(), temp_read_buffer->begin() + to_read);
                    if (temp_read_buffer->empty()) {
                        delete temp_read_buffer;
                        temp_read_buffer = nullptr;
                    }
                    return;
                } else {
                    delete temp_read_buffer;
                    temp_read_buffer = nullptr;
                }
            }
            util::native_workers_singleton::post_recv(op.get(), socket, extern_buffer, buffer_len, 0);
            op->cv.wait(lock);
            handle_error(lock, invalid_reason, op->sock_err);
            readed = op->transferred;
        }

        void read_fixed(char* extern_buffer, uint32_t buffer_len) {
            while (valid() && buffer_len) {
                int readed = 0;
                read(extern_buffer, buffer_len, readed);
                extern_buffer += readed;
                buffer_len -= readed;
            }
        }

        char* read_no_copy(unsigned long& readed) {
            if (!valid()) {
                readed = 0;
                return nullptr;
            }
            bool reuse_buf = false;
            fast_task::unique_lock lock(*cv_mutex);
            if (temp_read_buffer) {
                if (!delayed_buffer_clean) {
                    readed = (unsigned long)std::min<size_t>(temp_read_buffer->size(), UINT32_MAX);
                    delayed_buffer_clean = true;
                    return temp_read_buffer->data();
                } else {
                    if (buffer_size != temp_read_buffer->size()) {
                        delete temp_read_buffer;
                        temp_read_buffer = nullptr;
                    } else
                        reuse_buf = true;
                }
            }
            std::vector<char> buf;
            if (reuse_buf) {
                buf = std::move(*temp_read_buffer);
            } else
                buf = std::vector<char>(buffer_size);
            lock.unlock();
            int _readed = 0;
            read(buf.data(), (int)buf.size(), _readed);
            if (_readed) {
                buf.resize(_readed);
                readed = _readed;
                lock.lock();
                temp_read_buffer = new std::vector<char>(std::move(buf));
                delayed_buffer_clean = true;
                return temp_read_buffer->data();
            } else {
                readed = 0;
                return nullptr;
            }
        }

        void close(fast_task::unique_lock<mutex_unify>& lock, tcp_error err = tcp_error::local_close) {
            if (!valid())
                return;
            invalid_reason = err;
            shut_down(lock);
            internal_close(lock);
        }

        void close(tcp_error err = tcp_error::local_close) {
            mutex_unify mutex(*cv_mutex);
            fast_task::unique_lock lock(mutex);
            close(lock, err);
        }

        void send_and_close(const char* data, uint32_t len) {
            send(data, len);
            close();
        }

        bool send_file(int file, uint64_t data_len, uint64_t offset, uint32_t chunks_size) {
            if (!valid())
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
                uint32_t last_block = data_len % UINT_MAX;

                while (blocks--)
                    if (!transfer_file(file, UINT_MAX, chunks_size, sended + offset))
                        return false;
                    else
                        sended += UINT_MAX;


                if (last_block)
                    if (!transfer_file(file, last_block, chunks_size, sended + offset))
                        return false;
            } else {
                if (!transfer_file(file, (uint32_t)data_len, chunks_size, offset))
                    return false;
            }
            return true;
        }

        bool send_file(const char* path, [[maybe_unused]] size_t path_len, uint64_t data_len, uint64_t offset, uint32_t chunks_size) {
            if (!valid())
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
            return socket != INVALID_SOCKET && invalid_reason == tcp_error::none;
        }

        void reset() {
            mutex_unify mutex(*cv_mutex);
            fast_task::unique_lock lock(mutex);
            if (!valid())
                return;
            struct linger sl;
            sl.l_onoff = 1;
            sl.l_linger = 0;
            setsockopt(socket, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));
            invalid_reason = tcp_error::local_reset;
            shut_down(lock);
            ::close(socket);
        }

        void connection_reset() {
            mutex_unify mutex(*cv_mutex);
            fast_task::unique_lock lock(mutex);
            invalid_reason = tcp_error::remote_close;
            internal_close(lock);
        }

        void rebuffer(int32_t buffer_len) {
            if (buffer_len < 0)
                throw std::invalid_argument("buffer_len must be positive");
            if (buffer_len == 0)
                buffer_len = 0x1000;
            if (buffer_len == buffer_size)
                return;
            fast_task::unique_lock lock(*cv_mutex);
            if (!valid())
                return;
            buffer_size = buffer_len;
        }

    private:
        void shut_down(fast_task::unique_lock<mutex_unify>& lock) {
            auto op = std::make_unique<operation>(this, cv_mutex, manager);
            util::native_workers_singleton::post_shutdown(op.get(), socket, SHUT_RDWR);
            op->cv.wait(lock);
        }

        void internal_close(fast_task::unique_lock<mutex_unify>& lock) {
            auto op = std::make_unique<operation>(this, cv_mutex, manager);
            op->close_flag = true;
            util::native_workers_singleton::post_close(op.get(), socket);
            op->cv.wait(lock);
            socket = INVALID_SOCKET;
        }

        void handle_error(fast_task::unique_lock<mutex_unify>& lock, tcp_error& reason, int sock_error) {
            if (sock_error) {
                switch (sock_error) {
                case EFAULT:
                case EINVAL:
                case EAGAIN:
    #if EAGAIN != EWOULDBLOCK
                case EWOULDBLOCK:
    #endif
                    reason = tcp_error::invalid_state;
                    return;
                case ECONNRESET:
                    reason = tcp_error::remote_close;
                    return;
                default:
                    reason = tcp_error::undefined_error;
                    return;
                }
                close(lock);
            }
        }

        bool transfer_file(int file, uint32_t total_size, uint32_t chunks_size, uint64_t offset) {
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
                    off_t chunk_size = std::min((uint64_t)chunks_size, file_stat.st_size - offset);
                    if (send(file_data + offset, chunk_size) == 0) {
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
                    if (send(file_data + offset, chunk_size) == 0) {
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

    #pragma region tcp_network_stream

    class tcp_network_streamImpl : public tcp_network_stream {
        friend class tcp_network_manager;
        struct tcp_handle_2* handle;
        task_rw_mutex mutex;
        tcp_error last_error;

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
        tcp_network_streamImpl(tcp_handle_2* handle)
            : handle(handle), last_error(tcp_error::none) {}

        ~tcp_network_streamImpl() {
            if (checkup()) {
                write_lock lg(mutex);
                handle->close();
                delete handle;
            }
            handle = nullptr;
        }

        std::span<char> read_available_ref() override {
            read_lock lg(mutex);
            if (!checkup())
                return {};
            unsigned long readed = 0;
            char* data = handle->read_no_copy(readed);
            return {data, (size_t)readed};
        }

        int read_available(char* buffer, int buffer_len) override {
            read_lock lg(mutex);
            if (!checkup())
                return 0;
            int readed = 0;
            handle->read(buffer, buffer_len, readed);
            return readed;
        }

        bool data_available() override {
            read_lock lg(mutex);
            if (checkup())
                return handle->bytes_available();
            return false;
        }

        void write(const char* data, size_t size) override {
            write_lock lg(mutex);
            if (checkup())
                handle->send(data, size);
        }

        bool write_file(char* path, size_t path_len, uint64_t data_len, uint64_t offset, uint32_t chunks_size) override {
            write_lock lg(mutex);
            if (checkup())
                return handle->send_file(path, path_len, data_len, offset, chunks_size);
            return false;
        }

        bool write_file(int fhandle, uint64_t data_len, uint64_t offset, uint32_t chunks_size) override {
            write_lock lg(mutex);
            if (checkup())
                return handle->send_file(fhandle, data_len, offset, chunks_size);
            return false;
        }

        //write all data from write_queue
        void force_write() override {
        }

        void force_write_and_close(const char* data, size_t size) override {
            write_lock lg(mutex);
            if (checkup()) {
                while (size && handle->valid()) {
                    auto to_send = (uint32_t)std::min<size_t>(size, UINT32_MAX);
                    if (to_send == size)
                        handle->send_and_close(data, to_send);
                    else
                        handle->send(data, to_send);
                    size -= to_send;
                    data += to_send;
                    if (!handle->valid())
                        last_error = handle->invalid_reason;
                }
                last_error = handle->invalid_reason;
            }
        }

        void close() override {
            write_lock lg(mutex);
            if (checkup()) {
                handle->close();
                last_error = handle->invalid_reason;
                delete handle;
            }
            handle = nullptr;
        }

        void reset() override {
            write_lock lg(mutex);
            if (checkup()) {
                handle->reset();
                last_error = handle->invalid_reason;
                delete handle;
            }
            handle = nullptr;
        }

        void rebuffer(int32_t new_size) override {
            write_lock lg(mutex);
            if (checkup())
                handle->rebuffer(new_size);
        }

        bool is_closed() override {
            write_lock lg(mutex);
            if (checkup()) {
                bool res = handle->valid();
                if (!res) {
                    delete handle;
                    handle = nullptr;
                }
                return !res;
            }
            return true;
        }

        tcp_error error() override {
            write_lock lg(mutex);
            if (checkup())
                return handle->invalid_reason;
            return last_error;
        }

        address local_address() override {
            write_lock lg(mutex);
            if (!checkup())
                return {};
            universal_address addr;
            socklen_t socklen = sizeof(universal_address);
            if (getsockname(handle->socket, (sockaddr*)&addr, &socklen) == -1)
                return {};
            return to_address(addr);
        }

        address remote_address() override {
            write_lock lg(mutex);
            if (!checkup())
                return {};
            universal_address addr;
            socklen_t socklen = sizeof(universal_address);
            if (getpeername(handle->socket, (sockaddr*)&addr, &socklen) == -1)
                return {};
            return to_address(addr);
        }
    };

    #pragma endregion

    #pragma region tcp_network_blocking

    class tcp_network_blockingImpl : public tcp_network_blocking {
        friend class tcp_network_manager;
        tcp_handle_2* handle;
        task_mutex mutex;
        tcp_error last_error;

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
        tcp_network_blockingImpl(tcp_handle_2* handle)
            : handle(handle), last_error(tcp_error::none) {}

        ~tcp_network_blockingImpl() {
            fast_task::lock_guard lg(mutex);
            if (handle)
                delete handle;
            handle = nullptr;
        }

        std::vector<char> read(uint32_t len) override {
            fast_task::lock_guard lg(mutex);
            if (checkup()) {
                std::vector<char> buf;
                buf.resize(len);
                int32_t readed = 0;
                handle->read(buf.data(), len, readed);
                if (readed == 0)
                    return {};
                else
                    buf.resize(readed);
                return buf;
            }
            return {};
        }

        uint32_t available_bytes() override {
            fast_task::lock_guard lg(mutex);
            if (checkup())
                return handle->bytes_available_count();
            return (uint32_t)0;
        }

        int64_t write(const char* data, uint32_t len) override {
            fast_task::lock_guard lg(mutex);
            if (checkup())
                return handle->send(data, len);
            return 0;
        }

        bool write_file(char* path, size_t len, uint64_t data_len, uint64_t offset, uint32_t block_size) override {
            fast_task::lock_guard lg(mutex);
            if (checkup())
                return handle->send_file(path, len, data_len, offset, block_size);
            return false;
        }

        bool write_file(int fhandle, uint64_t data_len, uint64_t offset, uint32_t block_size) override {
            fast_task::lock_guard lg(mutex);
            if (checkup())
                return handle->send_file(fhandle, data_len, offset, block_size);
            return false;
        }

        void close() override {
            fast_task::lock_guard lg(mutex);
            if (checkup()) {
                handle->close();
                last_error = handle->invalid_reason;
                delete handle;
                handle = nullptr;
            }
        }

        void reset() override {
            fast_task::lock_guard lg(mutex);
            if (checkup()) {
                handle->reset();
                last_error = handle->invalid_reason;
                delete handle;
                handle = nullptr;
            }
        }

        void rebuffer(int32_t new_size) override {
            fast_task::lock_guard lg(mutex);
            if (checkup())
                handle->rebuffer(new_size);
        }

        bool is_closed() override {
            fast_task::lock_guard lg(mutex);
            if (checkup()) {
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

        tcp_error error() override {
            fast_task::lock_guard lg(mutex);
            if (checkup())
                return handle->invalid_reason;
            return last_error;
        }

        address local_address() override {
            fast_task::lock_guard lg(mutex);
            if (!checkup())
                return {};
            universal_address addr;
            socklen_t socklen = sizeof(universal_address);
            if (getsockname(handle->socket, (sockaddr*)&addr, &socklen) == -1)
                return {};
            return to_address(addr);
        }

        address remote_address() override {
            fast_task::lock_guard lg(mutex);
            if (!checkup())
                return {};
            universal_address addr;
            socklen_t socklen = sizeof(universal_address);
            if (getpeername(handle->socket, (sockaddr*)&addr, &socklen) == -1)
                return {};
            return to_address(addr);
        }
    };

    #pragma endregion

    class tcp_network_manager : public util::native_worker_manager {
        task_mutex safety;
        std::variant<std::function<void(tcp_network_blocking&)>, std::function<void(tcp_network_stream&)>> handler_fn;
        std::function<bool(address& client, address& server)> accept_filter;
        sockaddr_in6 connectionAddress;
        SOCKET main_socket;

    public:
        tcp_configuration config;

    private:
        bool allow_new_connections = false;
        bool disabled = true;
        bool corrupted = false;
        size_t acceptors;
        task_condition_variable state_changed_cv;

        tcp_handle_2::operation* make_acceptEx(tcp_handle_2* pClientContext) {
            auto op = new tcp_handle_2::operation(pClientContext, std::make_shared<task_mutex>(), this);
            op->accept_flag = true;
            util::native_workers_singleton::post_accept(op, main_socket, nullptr, nullptr, 0);
        }

        void make_acceptEx(void) {
            tcp_handle_2* pClientContext = new tcp_handle_2(0, config.buffer_size, this);
            (void)make_acceptEx(pClientContext);
        }

        void accepted(tcp_handle_2* self, address&& clientAddr, address&& localAddr) {
            if (!allow_new_connections) {
                delete self;
                return;
            }
            fast_task::lock_guard guard(safety);
            task::run([handler_fn = this->handler_fn, self, clientAddr = std::move(clientAddr), localAddr = std::move(localAddr)]() {
                std::visit(
                    [&](auto&& f) {
                        using T = std::decay_t<decltype(f)>;
                        if constexpr (std::is_same_v<T, std::function<void(tcp_network_blocking&)>>) {
                            tcp_network_blockingImpl rr(self);
                            f(rr);
                        } else {
                            tcp_network_streamImpl rr(self);
                            f(rr);
                        }
                    },
                    handler_fn
                );
            });
        }

        void accept_bounded(tcp_handle_2::operation* op, tcp_handle_2& data, SOCKET client_socket) {
            fast_task::lock_guard guard(*op->cv_mutex);
            data.socket = client_socket;
            op->cv.notify_all();
        }

        void new_connection(tcp_handle_2::operation* op, tcp_handle_2& data, SOCKET client_socket, int socket_error) {
            if (!allow_new_connections) {
                close(client_socket);
                util::native_workers_singleton::post_accept(op, main_socket, nullptr, nullptr, 0);
            }
            if (socket_error) {
                close(data.socket);
                data.socket = INVALID_SOCKET;
                if (!data.bound) {
                    delete &data;
                    delete op;
                } else {
                    fast_task::lock_guard guard(*data.cv_mutex);
                    op->cv.notify_all();
                    return;
                }

                if (!disabled)
                    make_acceptEx();
                return;
            }
            if (data.bound && !accept_filter)
                return accept_bounded(op, data, client_socket);
            if (!accept_filter)
                make_acceptEx();
            universal_address pClientAddr;
            universal_address pLocalAddr;
            socklen_t remoteLen = sizeof(universal_address);
            socklen_t localLen = sizeof(universal_address);
            getsockname(client_socket, (sockaddr*)&pLocalAddr, &localLen);
            getpeername(client_socket, (sockaddr*)&pClientAddr, &remoteLen);

            address clientAddress = to_address(pClientAddr);
            address localAddress = to_address(pLocalAddr);
            if (accept_filter) {
                if (accept_filter(clientAddress, localAddress)) {
                    close(client_socket);
                    util::native_workers_singleton::post_accept(op, main_socket, nullptr, nullptr, 0);
                    return;
                }
                make_acceptEx();
            }

            if (data.bound)
                accept_bounded(op, data, client_socket);
            else {
                data.socket = client_socket;
                accepted(&data, std::move(clientAddress), std::move(localAddress));
                delete op;
            }
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
        tcp_network_manager(const address& ip_port, size_t acceptors, const tcp_configuration& config)
            : main_socket(INVALID_SOCKET), config(config), acceptors(acceptors) {
            memcpy(&connectionAddress, &from_address(ip_port), sizeof(sockaddr_in6));
        }

        ~tcp_network_manager() noexcept(false) {
            shutdown();
        }

        void handle(util::native_worker_handle* completion, io_uring_cqe* cqe) override {
            auto data = (tcp_handle_2::operation*)completion;
            if (data->accept_flag)
                new_connection(data, *data->self, cqe->res, cqe->res < 0 ? -cqe->res : 0);
            else
                data->handle(cqe->res < 0 ? 0 : cqe->res, cqe->res < 0 ? -cqe->res : 0);
        }

        void set_on_connect(std::function<void(tcp_network_stream&)> handler_fn) {
            if (corrupted)
                throw std::runtime_error("tcp_network_manager is corrupted");
            fast_task::lock_guard lock(safety);
            this->handler_fn = handler_fn;
        }

        void set_on_connect(std::function<void(tcp_network_blocking&)> handler_fn) {
            if (corrupted)
                throw std::runtime_error("tcp_network_manager is corrupted");
            fast_task::lock_guard lock(safety);
            this->handler_fn = handler_fn;
        }

        void shutdown() {
            if (corrupted)
                throw std::runtime_error("tcp_network_manager is corrupted");

            {
                fast_task::lock_guard lock2(safety);
                if (disabled)
                    return;
            }
            auto mut = std::make_shared<fast_task::task_mutex>();
            auto op = std::make_unique<tcp_handle_2::operation>(nullptr, mut, this);
            util::native_workers_singleton::post_shutdown(op.get(), main_socket, SHUT_RDWR);
            fast_task::mutex_unify unf(*mut);
            fast_task::unique_lock lock(unf);
            op->cv.wait(lock);
            fast_task::lock_guard lock2(safety);
            close(main_socket);
            allow_new_connections = false;
            disabled = true;
            state_changed_cv.notify_all();
        }

        void pause() {
            if (corrupted)
                throw std::runtime_error("tcp_network_manager is corrupted");
            allow_new_connections = false;
        }

        void resume() {
            if (corrupted)
                throw std::runtime_error("tcp_network_manager is corrupted");
            allow_new_connections = true;
        }

        void start() {
            if (corrupted)
                throw std::runtime_error("tcp_network_manager is corrupted");
            fast_task::lock_guard lock(safety);
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

        tcp_handle_2* base_accept(bool ignore_acceptors) {
            if (!ignore_acceptors && acceptors)
                throw std::runtime_error("Thread tried to accept connection with enabled acceptors and ignore_acceptors = false");
            if (corrupted)
                throw std::runtime_error("tcp_network_manager is corrupted");
            if (disabled)
                throw std::runtime_error("tcp_network_manager is disabled");
            if (!allow_new_connections)
                throw std::runtime_error("tcp_network_manager is paused");

            tcp_handle_2* data = new tcp_handle_2(-1, config.buffer_size, this);
            mutex_unify mutex(*data->cv_mutex);
            fast_task::unique_lock lock(mutex);
            data->bound = true;
            auto res = make_acceptEx(data);
            res->cv.wait(lock);
            delete res;
            return data;
        }

        tcp_network_blocking* accept_blocking(bool ignore_acceptors = false) {
            return new tcp_network_blockingImpl(base_accept(ignore_acceptors));
        }

        tcp_network_stream* accept_stream(bool ignore_acceptors = false) {
            return new tcp_network_streamImpl(base_accept(ignore_acceptors));
        }

        void _await() {
            mutex_unify um(safety);
            fast_task::unique_lock lock(um);
            if (corrupted)
                throw std::runtime_error("tcp_network_manager is corrupted");
            while (!disabled)
                state_changed_cv.wait(lock);
        }

        void set_configuration(const tcp_configuration& config) {
            if (corrupted)
                throw std::runtime_error("tcp_network_manager is corrupted");
            this->config = config;
        }

        void set_accept_filter(std::function<bool(address&, address&)>&& filter) {
            if (corrupted)
                throw std::runtime_error("tcp_network_manager is corrupted");
            fast_task::lock_guard lock(safety);
            this->accept_filter = std::move(filter);
        }

        bool is_corrupted() {
            return corrupted;
        }

        uint16_t port() {
            if (corrupted)
                throw std::runtime_error("tcp_network_manager is corrupted");
            return htons(connectionAddress.sin6_port);
        }

        std::string ip() {
            return get_address().to_string();
        }

        address get_address() {
            if (corrupted)
                throw std::runtime_error("tcp_network_manager is corrupted");

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

    class tcp_client_manager : public util::native_worker_manager {
        task_mutex mutex;
        sockaddr_in6 connectionAddress;
        tcp_handle_2* _handle;
        bool corrupted = false;

    public:
        void handle(util::native_worker_handle* overlapped, io_uring_cqe* cqe) override {
            tcp_handle_2::operation& handle = *(tcp_handle_2::operation*)overlapped;
            handle.handle(cqe->res, cqe->res < 0 ? -cqe->res : 0);
        }

        tcp_client_manager(sockaddr_in6& _connectionAddress, const tcp_configuration& config)
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
            _handle = new tcp_handle_2(clientSocket, config.buffer_size, this);
            mutex_unify umutex(*_handle->cv_mutex);
            fast_task::unique_lock<mutex_unify> lock(umutex);
            auto op = std::make_unique<tcp_handle_2::operation>(_handle, _handle->cv_mutex, this);
            util::native_workers_singleton::post_connect(op.get(), clientSocket, (sockaddr*)&connectionAddress, sizeof(connectionAddress));
            if (config.connection_timeout_ms > 0) {
                if (!op->cv.wait_for(lock, config.connection_timeout_ms)) {
                    corrupted = true;
                    _handle->reset();
                    return;
                }
            } else
                op->cv.wait(lock);
            cfg = config.send_timeout_ms;
            if (setsockopt(clientSocket, IPPROTO_TCP, SO_SNDTIMEO, &cfg, sizeof(cfg)) == -1) {
                corrupted = true;
                return;
            }
        }

        tcp_client_manager(sockaddr_in6& _connectionAddress, char* data, uint32_t len, const tcp_configuration& config)
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
            _handle = new tcp_handle_2(clientSocket, 4096, this);
            mutex_unify umutex(*_handle->cv_mutex);
            fast_task::unique_lock<mutex_unify> lock(umutex);
            auto op = std::make_unique<tcp_handle_2::operation>(_handle, _handle->cv_mutex, this);
            util::native_workers_singleton::post_sendto(op.get(), clientSocket, data, len, MSG_FASTOPEN, (sockaddr*)&connectionAddress, sizeof(connectionAddress));
            if (config.connection_timeout_ms > 0) {
                if (!op->cv.wait_for(lock, config.connection_timeout_ms)) {
                    corrupted = true;
                    _handle->reset();
                    return;
                }
            } else
                op->cv.wait(lock);
        }

        ~tcp_client_manager() noexcept(false) override {
            if (corrupted)
                return;
            delete _handle;
        }

        void set_configuration(const tcp_configuration& config) {
            if (corrupted)
                throw std::runtime_error("tcp_client_manager::set_configuration, corrupted");
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
                _handle->rebuffer(config.buffer_size);
            }
        }

        int32_t read(char* data, int32_t len) {
            if (corrupted)
                throw std::runtime_error("tcp_client_manager is corrupted");
            fast_task::lock_guard<task_mutex> lock(mutex);
            int32_t readed = 0;
            _handle->read(data, len, readed);
            return readed;
        }

        bool write(const char* data, int32_t len) {
            if (corrupted)
                throw std::runtime_error("tcp_client_manager is corrupted");
            fast_task::lock_guard<task_mutex> lock(mutex);
            (void)_handle->send(data, len);
            return _handle->valid();
        }

        bool write_file(const char* path, size_t len, uint64_t data_len, uint64_t offset, uint32_t chunks_size) {
            if (corrupted)
                throw std::runtime_error("tcp_client_manager is corrupted");
            fast_task::lock_guard<task_mutex> lock(mutex);
            return _handle->send_file(path, len, data_len, offset, chunks_size);
        }

        bool write_file(int handle, uint64_t data_len, uint64_t offset, uint32_t chunks_size) {
            if (corrupted)
                throw std::runtime_error("tcp_client_manager is corrupted");
            fast_task::lock_guard<task_mutex> lock(mutex);
            return _handle->send_file(handle, data_len, offset, chunks_size);
        }

        void close() {
            if (corrupted)
                throw std::runtime_error("tcp_client_manager is corrupted");
            fast_task::lock_guard<task_mutex> lock(mutex);
            _handle->close();
        }

        void reset() {
            if (corrupted)
                throw std::runtime_error("tcp_client_manager is corrupted");
            fast_task::lock_guard<task_mutex> lock(mutex);
            _handle->reset();
        }

        bool is_corrupted() {
            return corrupted;
        }

        void rebuffer(int32_t size) {
            if (corrupted)
                throw std::runtime_error("tcp_client_manager is corrupted");
            fast_task::lock_guard<task_mutex> lock(mutex);
            _handle->rebuffer(size);
        }
    };

    class udp_handle : public util::native_worker_handle, public util::native_worker_manager {
        task_mutex mt;
        task_condition_variable cv;
        SOCKET socket;
        sockaddr_in6 server_address;
        bool is_complete = false;

    public:
        uint32_t fullifed_bytes;
        uint32_t last_error;

        udp_handle(sockaddr_in6& address, uint32_t _)
            : util::native_worker_handle(this), fullifed_bytes(0), last_error(0) {
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

        void handle(util::native_worker_handle* _, io_uring_cqe* cqe) override {
            this->fullifed_bytes = cqe->res > -1 ? cqe->res : 0;
            this->last_error = cqe->res > -1 ? 0 : errno;

            unique_lock lock(mt);
            is_complete = true;
            cv.notify_all();
        }

        void recv(uint8_t* data, uint32_t size, sockaddr_storage& sender, int& sender_len) {
            if (socket == INVALID_SOCKET)
                throw std::runtime_error("Socket is not connected");
            mutex_unify u(mt);
            unique_lock lock(u);
            is_complete = false;
            socklen_t sender_len_ = 0;
            util::native_workers_singleton::post_recvfrom(this, socket, data, size, 0, (sockaddr*)&sender, &sender_len_);
            while (is_complete)
                cv.wait(lock);
            is_complete = false;
            sender_len = sender_len_;
        }

        void send(uint8_t* data, uint32_t size, sockaddr_storage& to) {
            if (socket == INVALID_SOCKET)
                throw std::runtime_error("Socket is not connected");
            mutex_unify u(mt);
            unique_lock lock(u);
            is_complete = false;
            util::native_workers_singleton::post_sendto(this, socket, data, size, 0, (sockaddr*)&to, sizeof(sockaddr_in6));
            while (is_complete)
                cv.wait(lock);
            is_complete = false;
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

    tcp_network_server::tcp_network_server(std::function<void(tcp_network_blocking&)> on_connect, const address& ip_port, size_t acceptors, const tcp_configuration& config) {
        if (!inited)
            init_networking();
        handle = new tcp_network_manager(ip_port, acceptors, config);
        handle->set_on_connect(on_connect);
    }

    tcp_network_server::tcp_network_server(std::function<void(tcp_network_stream&)> on_connect, const address& ip_port, size_t acceptors, const tcp_configuration& config) {
        if (!inited)
            init_networking();
        handle = new tcp_network_manager(ip_port, acceptors, config);
        handle->set_on_connect(on_connect);
    }

    tcp_network_server::~tcp_network_server() {
        if (handle)
            delete handle;
        handle = nullptr;
    }

    void tcp_network_server::start() {
        handle->start();
    }

    void tcp_network_server::pause() {
        handle->pause();
    }

    void tcp_network_server::resume() {
        handle->resume();
    }

    void tcp_network_server::stop() {
        handle->shutdown();
    }

    bool tcp_network_server::is_running() {
        return handle->in_run();
    }

    tcp_network_blocking* tcp_network_server::accept_blocking(bool ignore_acceptors) {
        return handle->accept_blocking(ignore_acceptors);
    }

    tcp_network_stream* tcp_network_server::accept_stream(bool ignore_acceptors) {
        return handle->accept_stream(ignore_acceptors);
    }

    void tcp_network_server::_await() {
        handle->_await();
    }

    bool tcp_network_server::is_corrupted() {
        return handle->is_corrupted();
    }

    uint16_t tcp_network_server::server_port() {
        return handle->port();
    }

    std::string tcp_network_server::server_ip() {
        return handle->ip();
    }

    address tcp_network_server::server_address() {
        return handle->get_address();
    }

    bool tcp_network_server::is_paused() {
        return handle->is_paused();
    }

    void tcp_network_server::set_configuration(const tcp_configuration& config) {
        if (handle)
            handle->set_configuration(config);
    }

    void tcp_network_server::set_accept_filter(std::function<bool(address&, address&)>&& filter) {
        if (handle)
            handle->set_accept_filter(std::move(filter));
    }

    tcp_client_socket::tcp_client_socket()
        : handle(nullptr) {}

    tcp_client_socket::~tcp_client_socket() {
        if (handle)
            delete handle;
        handle = nullptr;
    }

    tcp_client_socket* tcp_client_socket::connect(const address& ip_port, const tcp_configuration& configuration) {
        if (!inited)
            init_networking();
        sockaddr_storage& address = from_address(ip_port);
        std::unique_ptr<tcp_client_socket> result;
        result.reset(new tcp_client_socket());
        result->handle = new tcp_client_manager((sockaddr_in6&)address, configuration);
        return result.release();
    }

    tcp_client_socket* tcp_client_socket::connect(const address& ip_port, char* data, uint32_t size, const tcp_configuration& configuration) {
        if (!inited)
            init_networking();
        sockaddr_storage& address = from_address(ip_port);
        std::unique_ptr<tcp_client_socket> result;
        result.reset(new tcp_client_socket());
        result->handle = new tcp_client_manager((sockaddr_in6&)address, data, size, configuration);
        return result.release();
    }

    void tcp_client_socket::set_configuration(const tcp_configuration& config) {
        if (handle)
            handle->set_configuration(config);
    }

    int32_t tcp_client_socket::recv(uint8_t* data, int32_t size) {
        if (!inited)
            init_networking();

        if (handle)
            return handle->read((char*)data, size);
        return 0;
    }

    bool tcp_client_socket::send(uint8_t* data, int32_t size) {
        if (!inited)
            init_networking();
        if (handle)
            return handle->write((char*)data, size);
        return false;
    }

    bool tcp_client_socket::send_file(const char* file_path, size_t file_path_len, uint64_t data_len, uint64_t offset, uint32_t chunks_size) {
        if (!handle)
            return false;
        return handle->write_file(file_path, file_path_len, data_len, offset, chunks_size);
    }

    bool tcp_client_socket::send_file(class fast_task::files::file_handle& file, uint64_t data_len, uint64_t offset, uint32_t chunks_size) {
        if (!handle)
            return false;
        return handle->write_file(file.internal_get_handle(), data_len, offset, chunks_size);
    }

    void tcp_client_socket::close() {
        if (handle) {
            handle->close();
            delete handle;
            handle = nullptr;
        }
    }

    void tcp_client_socket::reset() {
        if (handle) {
            handle->reset();
            delete handle;
            handle = nullptr;
        }
    }

    void tcp_client_socket::rebuffer(int32_t size) {
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
            throw std::runtime_error("Received error while trying to receive data from udp socket with error or status code: " + std::to_string(handle->last_error));
        return handle->fullifed_bytes;
    }

    uint32_t udp_socket::send(uint8_t* data, uint32_t size, address& to) {
        sockaddr_storage& to_ip_port = from_address(to);
        handle->send(data, size, to_ip_port);
        if (handle->fullifed_bytes == 0 && handle->last_error != 0)
            throw std::runtime_error("Received error while trying to receive data from udp socket with error or status code: " + std::to_string(handle->last_error));
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