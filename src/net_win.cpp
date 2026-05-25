
// Copyright Danyil Melnytskyi 2022-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)
#ifdef _WIN64
    #include "net_shared.hpp"

    #include "tasks/_internal.hpp"
    #include "tasks/util/native_workers_singleton.hpp"
    #include <file.hpp>
    #include <net.hpp>

namespace fast_task::net {
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

    struct native_state : public util::native_worker_handle {
        std::shared_ptr<task> awaiting_task;
        int32_t* out_processed_bytes = nullptr;
        int error = 0;
        void (*on_complete)(void*) = nullptr;

        native_state(util::native_worker_manager* mgr)
            : util::native_worker_handle(mgr) {
        }
    };

    tcp_error opaque_network_state::get_error() const noexcept {
        auto& state = *reinterpret_cast<const native_state*>(this);
        if (WSA_IO_PENDING == state.error)
            return tcp_error::none;
        else
            switch (state.error) {
            case WSAECONNRESET:
                return tcp_error::remote_close;
            case WSAECONNABORTED:
            case WSA_OPERATION_ABORTED:
            case WSAENETRESET:
                return tcp_error::local_close;
            case WSAEWOULDBLOCK:
                return tcp_error::none;
            default:
                return tcp_error::undefined_error;
            }
    }

    static_assert(sizeof(native_state) <= sizeof(opaque_network_state::data), "opaque_network_state buffer is too small for native_state!");

    class tcp_socket::manager : public util::native_worker_manager {
        SOCKET sock = INVALID_SOCKET;

    public:
        manager(SOCKET s) : sock(s) {
            if (sock != INVALID_SOCKET) {
                init_win_fns(sock);
                HANDLE hSock = reinterpret_cast<HANDLE>(sock);
                util::native_workers_singleton::register_handle(hSock, this);
                ::SetFileCompletionNotificationModes(hSock, FILE_SKIP_COMPLETION_PORT_ON_SUCCESS | FILE_SKIP_SET_EVENT_ON_HANDLE);
            }
        }

        ~manager() override {
            if (sock != INVALID_SOCKET) {
                closesocket(sock);
                sock = INVALID_SOCKET;
            }
        }

        manager(const manager&) = delete;
        manager& operator=(const manager&) = delete;
        manager(manager&&) = delete;
        manager& operator=(manager&&) = delete;

        SOCKET get_socket() const noexcept {
            return sock;
        }

        void handle(void* data, util::native_worker_handle* overlap, unsigned long dwBytesTransferred) override {
            auto state = static_cast<native_state*>(overlap);
            DWORD dwFlags = 0;
            DWORD cbTransfer = 0;
            if (!::WSAGetOverlappedResult(sock, &state->overlapped, &cbTransfer, FALSE, &dwFlags)) {
                state->error = ::WSAGetLastError();
            } else
                state->error = 0;

            if (state->awaiting_task) {
                if (state->out_processed_bytes)
                    if (state->error)
                        *state->out_processed_bytes = -1;
                    else
                        *state->out_processed_bytes = dwBytesTransferred;
                if (state->on_complete)
                    state->on_complete(static_cast<void*>(state));
                {
                    std::lock_guard guard(get_data(state->awaiting_task).no_race);
                    transfer_task(std::move(state->awaiting_task));
                }
            }
        }

        bool set_configuration(const tcp_configuration& config) {
            int cfg = !config.allow_ip4;

            if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&cfg, sizeof(cfg)) == -1)
                return false;
            //cfg = !config.enable_timestamps;
            //if (setsockopt(sock, IPPROTO_TCP, TCP_TIMESTAMPS, (char*)&cfg, sizeof(cfg)) == -1)
            //    return false;
            cfg = !config.enable_delay;
            if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char*)&cfg, sizeof(cfg)) == -1)
                return false;
            cfg = config.recv_timeout_ms;
            if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&cfg, sizeof(cfg)) == -1)
                return false;
            cfg = config.send_timeout_ms;
            if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&cfg, sizeof(cfg)) == -1)
                return false;
            cfg = config.enable_keep_alive;
            if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (char*)&cfg, sizeof(cfg)) == -1)
                return false;
            if (config.enable_keep_alive) {
                cfg = config.keep_alive_settings.idle_ms;
                if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, (char*)&cfg, sizeof(cfg)) == -1)
                    return false;
                cfg = config.keep_alive_settings.interval_ms;
                if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, (char*)&cfg, sizeof(cfg)) == -1)
                    return false;
                cfg = config.keep_alive_settings.retry_count;
                if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, (char*)&cfg, sizeof(cfg)) == -1)
                    return false;
    #ifdef TCP_MAXRTMS
                cfg = config.keep_alive_settings.user_timeout_ms;
                if (setsockopt(sock, IPPROTO_TCP, TCP_MAXRTMS, (char*)&cfg, sizeof(cfg)) == -1)
                    return false;
    #else
                cfg = config.keep_alive_settings.user_timeout_ms / 1000;
                if (setsockopt(sock, IPPROTO_TCP, TCP_MAXRT, (char*)&cfg, sizeof(cfg)) == -1)
                    return false;
    #endif
            }
            DWORD argp = 1;
            if (ioctlsocket(sock, FIONBIO, &argp) == SOCKET_ERROR)
                return false;

            return true;
        }
    };

    tcp_socket::tcp_socket() = default;
    tcp_socket::tcp_socket(tcp_socket&&) = default;
    tcp_socket& tcp_socket::operator=(tcp_socket&&) = default;
    tcp_socket::~tcp_socket() = default;

    std::optional<tcp_socket> tcp_socket::connect(const address& ip_port, const tcp_configuration& config) {
        std::optional<tcp_socket> res;
        opaque_network_state state;

        if (loc.is_task_thread) {
            mutex_unify mut(get_data(loc.curr_task).no_race);
            std::lock_guard guard(mut);
            if (!tcp_socket::enter_connect(loc.curr_task, state, res, ip_port, config))
                swapCtxRelock(mut);
        } else {
            std::mutex mtx;
            std::condition_variable cv;
            bool done = false;

            auto t = task::create([&] {
                std::lock_guard lock(mtx);
                done = true;
                cv.notify_one();
            });

            if (!tcp_socket::enter_connect(t, state, res, ip_port, config)) {
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
        return res;
    }

    std::optional<tcp_socket> tcp_socket::connect(const address& ip_port, char* data, int32_t& size, const tcp_configuration& config) {
        std::optional<tcp_socket> res;
        opaque_network_state state;

        if (loc.is_task_thread) {
            mutex_unify mut(get_data(loc.curr_task).no_race);
            std::lock_guard guard(mut);
            if (!tcp_socket::enter_connect(loc.curr_task, state, res, ip_port, data, size, config))
                swapCtxRelock(mut);
        } else {
            std::mutex mtx;
            std::condition_variable cv;
            bool done = false;

            auto t = task::create([&] {
                std::lock_guard lock(mtx);
                done = true;
                cv.notify_one();
            });

            if (!tcp_socket::enter_connect(t, state, res, ip_port, data, size, config)) {
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
        return res;
    }

    int32_t tcp_socket::recv(std::span<char> data) {
        opaque_network_state state;
        int32_t bytes_read = 0;

        if (loc.is_task_thread) {
            mutex_unify mut(get_data(loc.curr_task).no_race);
            std::lock_guard guard(mut);
            if (!tcp_socket::enter_recv(loc.curr_task, state, bytes_read, data))
                swapCtxRelock(mut);
        } else {
            std::mutex mtx;
            std::condition_variable cv;
            bool done = false;

            auto t = task::create([&] {
                std::lock_guard lock(mtx);
                done = true;
                cv.notify_one();
            });

            if (!tcp_socket::enter_recv(t, state, bytes_read, data)) {
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
        return bytes_read;
    }

    int32_t tcp_socket::send(std::span<const uint8_t> data) {
        opaque_network_state state;
        int32_t res = 0;

        if (loc.is_task_thread) {
            mutex_unify mut(get_data(loc.curr_task).no_race);
            std::lock_guard guard(mut);
            if (!tcp_socket::enter_send(loc.curr_task, state, res, data))
                swapCtxRelock(mut);
        } else {
            std::mutex mtx;
            std::condition_variable cv;
            bool done = false;

            auto t = task::create([&] {
                std::lock_guard lock(mtx);
                done = true;
                cv.notify_one();
            });

            if (!tcp_socket::enter_send(t, state, res, data)) {
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
        return res;
    }

    int32_t tcp_socket::sendv(std::span<const std::span<const uint8_t>> data) {
        opaque_network_state state;
        int32_t res = 0;

        if (loc.is_task_thread) {
            mutex_unify mut(get_data(loc.curr_task).no_race);
            std::lock_guard guard(mut);
            if (!tcp_socket::enter_sendv(loc.curr_task, state, res, data))
                swapCtxRelock(mut);
        } else {
            std::mutex mtx;
            std::condition_variable cv;
            bool done = false;
            auto t = task::create([&] {
                std::lock_guard lock(mtx);
                done = true;
                cv.notify_one();
            });

            if (!tcp_socket::enter_sendv(t, state, res, data)) {
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
        return res;
    }

    int32_t tcp_socket::send_file(const char* file_path, size_t file_path_len, uint32_t data_len, uint64_t offset, uint32_t chunks_size) {
        opaque_network_state state;
        int32_t res = 0;

        if (loc.is_task_thread) {
            mutex_unify mut(get_data(loc.curr_task).no_race);
            std::lock_guard guard(mut);
            if (!tcp_socket::enter_send_file(loc.curr_task, state, res, file_path, file_path_len, data_len, offset, chunks_size))
                swapCtxRelock(mut);
        } else {
            std::mutex mtx;
            std::condition_variable cv;
            bool done = false;
            auto t = task::create([&] {
                std::lock_guard lock(mtx);
                done = true;
                cv.notify_one();
            });

            if (!tcp_socket::enter_send_file(t, state, res, file_path, file_path_len, data_len, offset, chunks_size)) {
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
        return res;
    }

    int32_t tcp_socket::send_file(class fast_task::file::file_handle& file, uint32_t data_len, uint64_t offset, uint32_t chunks_size) {
        opaque_network_state state;
        int32_t res = 0;

        if (loc.is_task_thread) {
            mutex_unify mut(get_data(loc.curr_task).no_race);
            std::lock_guard guard(mut);
            if (!tcp_socket::enter_send_file(loc.curr_task, state, res, file, data_len, offset, chunks_size))
                swapCtxRelock(mut);
        } else {
            std::mutex mtx;
            std::condition_variable cv;
            bool done = false;
            auto t = task::create([&] {
                std::lock_guard lock(mtx);
                done = true;
                cv.notify_one();
            });

            if (!tcp_socket::enter_send_file(t, state, res, file, data_len, offset, chunks_size)) {
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
        return res;
    }

    int32_t tcp_socket::sendv_file(const std::span<const uint8_t> prefix, const std::span<const uint8_t> postfix, const char* file_path, size_t file_path_len, uint32_t data_len, uint64_t offset, uint32_t chunks_size) {
        opaque_network_state state;
        int32_t res = 0;

        if (loc.is_task_thread) {
            mutex_unify mut(get_data(loc.curr_task).no_race);
            std::lock_guard guard(mut);
            if (!tcp_socket::enter_sendv_file(loc.curr_task, state, res, prefix, postfix, file_path, file_path_len, data_len, offset, chunks_size))
                swapCtxRelock(mut);
        } else {
            std::mutex mtx;
            std::condition_variable cv;
            bool done = false;
            auto t = task::create([&] {
                std::lock_guard lock(mtx);
                done = true;
                cv.notify_one();
            });

            if (!tcp_socket::enter_sendv_file(t, state, res, prefix, postfix, file_path, file_path_len, data_len, offset, chunks_size)) {
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
        return res;
    }

    int32_t tcp_socket::sendv_file(const std::span<const uint8_t> prefix, const std::span<const uint8_t> postfix, class fast_task::file::file_handle& file, uint32_t data_len, uint64_t offset, uint32_t chunks_size) {
        opaque_network_state state;
        int32_t res = 0;

        if (loc.is_task_thread) {
            mutex_unify mut(get_data(loc.curr_task).no_race);
            std::lock_guard guard(mut);
            if (!tcp_socket::enter_sendv_file(loc.curr_task, state, res, prefix, postfix, file, data_len, offset, chunks_size))
                swapCtxRelock(mut);
        } else {
            std::mutex mtx;
            std::condition_variable cv;
            bool done = false;
            auto t = task::create([&] {
                std::lock_guard lock(mtx);
                done = true;
                cv.notify_one();
            });

            if (!tcp_socket::enter_sendv_file(t, state, res, prefix, postfix, file, data_len, offset, chunks_size)) {
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
        return res;
    }

    void tcp_socket::shutdown(shutdown_mode mode) {
        opaque_network_state state;

        if (loc.is_task_thread) {
            mutex_unify mut(get_data(loc.curr_task).no_race);
            std::lock_guard guard(mut);
            if (!tcp_socket::enter_shutdown(loc.curr_task, state, mode))
                swapCtxRelock(mut);
        } else {
            std::mutex mtx;
            std::condition_variable cv;
            bool done = false;
            auto t = task::create([&] {
                std::lock_guard lock(mtx);
                done = true;
                cv.notify_one();
            });

            if (!tcp_socket::enter_shutdown(t, state, mode)) {
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
    }

    void tcp_socket::reset() {
        opaque_network_state state;

        if (loc.is_task_thread) {
            mutex_unify mut(get_data(loc.curr_task).no_race);
            std::lock_guard guard(mut);
            if (!tcp_socket::enter_reset(loc.curr_task, state))
                swapCtxRelock(mut);
        } else {
            std::mutex mtx;
            std::condition_variable cv;
            bool done = false;
            auto t = task::create([&] {
                std::lock_guard lock(mtx);
                done = true;
                cv.notify_one();
            });

            if (!tcp_socket::enter_reset(t, state)) {
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
    }

    void tcp_socket::close() {
        opaque_network_state state;

        if (loc.is_task_thread) {
            mutex_unify mut(get_data(loc.curr_task).no_race);
            std::lock_guard guard(mut);
            if (!tcp_socket::enter_close(loc.curr_task, state))
                swapCtxRelock(mut);
        } else {
            std::mutex mtx;
            std::condition_variable cv;
            bool done = false;
            auto t = task::create([&] {
                std::lock_guard lock(mtx);
                done = true;
                cv.notify_one();
            });

            if (!tcp_socket::enter_close(t, state)) {
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
    }

    void tcp_socket::set_configuration(const tcp_configuration& config) {
        if (handle)
            handle->set_configuration(config);
    }

    uint32_t tcp_socket::available_bytes() const noexcept {
        if (!handle || handle->get_socket() == INVALID_SOCKET)
            return 0;
        u_long bytes = 0;
        if (ioctlsocket(handle->get_socket(), FIONREAD, &bytes) == SOCKET_ERROR)
            return 0;
        return bytes;
    }

    bool tcp_socket::is_open() const noexcept {
        return handle && handle->get_socket() != INVALID_SOCKET;
    }

    address tcp_socket::local_address() const noexcept {
        if (!handle || handle->get_socket() == INVALID_SOCKET)
            return address();

        sockaddr_storage addr;
        socklen_t addr_len = sizeof(addr);
        if (getsockname(handle->get_socket(), (sockaddr*)&addr, &addr_len) == -1)
            return address();
        return to_address(&addr);
    }

    address tcp_socket::remote_address() const noexcept {
        if (!handle || handle->get_socket() == INVALID_SOCKET)
            return address();

        sockaddr_storage addr;
        socklen_t addr_len = sizeof(addr);
        if (getpeername(handle->get_socket(), (sockaddr*)&addr, &addr_len) == -1)
            return address();
        return to_address(&addr);
    }

    bool tcp_socket::enter_connect(const std::shared_ptr<task>& t, opaque_network_state& state, std::optional<tcp_socket>& res, const address& ip_port, const tcp_configuration& config) {
        SOCKET sock = ::WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
        if (sock == INVALID_SOCKET)
            return true;

        sockaddr_in bind_addr{};
        bind_addr.sin_family = AF_INET;
        bind_addr.sin_addr.s_addr = INADDR_ANY;
        bind_addr.sin_port = 0;
        ::bind(sock, (SOCKADDR*)&bind_addr, sizeof(bind_addr));

        auto mgr = std::make_unique<manager>(sock);

        auto& n_state = *new (&state) native_state(mgr.get());
        n_state.awaiting_task = t;

        // 5. Issue ConnectEx
        DWORD bytesSent = 0;
        if (!_ConnectEx(sock, (sockaddr*)ip_port.get_data(), ip_port.data_size(), nullptr, 0, &bytesSent, &n_state.overlapped)) {
            int err = ::WSAGetLastError();
            if (err != ERROR_IO_PENDING) {
                n_state.error = err;
                return true; // Synchronous failure
            }

            n_state.error = WSA_IO_PENDING;
            tcp_socket new_sock;
            new_sock.handle = std::move(mgr);
            res = std::move(new_sock);
            return false; // Asynchronous pending
        }

        n_state.error = 0;
        tcp_socket new_sock;
        new_sock.handle = std::move(mgr);
        res = std::move(new_sock);
        return true;
    }

    bool tcp_socket::enter_connect(const std::shared_ptr<task>& t, opaque_network_state& state, std::optional<tcp_socket>& res, const address& ip_port, char* data, int32_t& size, const tcp_configuration& config) {
        SOCKET sock = ::WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
        if (sock == INVALID_SOCKET)
            return true;

        sockaddr_in bind_addr{};
        bind_addr.sin_family = AF_INET;
        bind_addr.sin_addr.s_addr = INADDR_ANY;
        bind_addr.sin_port = 0;
        ::bind(sock, (SOCKADDR*)&bind_addr, sizeof(bind_addr));

        auto mgr = std::make_unique<manager>(sock);

        auto& n_state = *new (&state) native_state(mgr.get());
        n_state.awaiting_task = t;
        n_state.out_processed_bytes = &size;

        if (!_ConnectEx(sock, (sockaddr*)ip_port.get_data(), ip_port.data_size(), data, 0, (PDWORD)&size, &n_state.overlapped)) {
            int err = ::WSAGetLastError();
            if (err != ERROR_IO_PENDING) {
                n_state.error = err;
                return true; // Synchronous failure
            }

            n_state.error = WSA_IO_PENDING;
            tcp_socket new_sock;
            new_sock.handle = std::move(mgr);
            res = std::move(new_sock);
            return false; // Asynchronous pending
        }

        n_state.error = 0;
        tcp_socket new_sock;
        new_sock.handle = std::move(mgr);
        res = std::move(new_sock);
        return true;
    }

    bool tcp_socket::enter_recv(const std::shared_ptr<task>& t, opaque_network_state& state, int32_t& bytes_read, std::span<char> data) {
        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            bytes_read = -1;
            return true;
        }

        auto& n_state = *new (&state) native_state(handle.get());
        n_state.awaiting_task = t;
        n_state.out_processed_bytes = &bytes_read;

        WSABUF wsaBuf;
        wsaBuf.buf = data.data();
        wsaBuf.len = static_cast<ULONG>(data.size());

        DWORD flags = 0;

        if (::WSARecv(handle->get_socket(), &wsaBuf, 1, (PDWORD)&bytes_read, &flags, &n_state.overlapped, NULL) == SOCKET_ERROR) {
            int err = ::WSAGetLastError();
            if (err != WSA_IO_PENDING) {
                n_state.error = err;
                bytes_read = -1;
                return true;
            }

            n_state.error = WSA_IO_PENDING;
            return false;
        }

        n_state.error = 0;
        return true;
    }

    struct send_state : public native_state {
        WSABUF buf;

        send_state(util::native_worker_manager* mgr) : native_state(mgr) {}
    };

    bool tcp_socket::enter_send(const std::shared_ptr<task>& t, opaque_network_state& state, int32_t& bytes_sent, std::span<const uint8_t> data) {
        auto& ns = *new (&state) send_state(handle.get());
        ns.awaiting_task = t;
        ns.out_processed_bytes = &bytes_sent;
        ns.buf.buf = (CHAR*)data.data();
        ns.buf.len = (ULONG)data.size();

        int res = ::WSASend(handle->get_socket(), &ns.buf, 1, (PDWORD)&bytes_sent, 0, &ns.overlapped, NULL);

        if (res == 0)
            return true;

        int err = ::WSAGetLastError();
        if (err == WSA_IO_PENDING)
            return false;

        bytes_sent = -1;
        ns.error = err;
        return true;
    }

    struct sendv_state : public native_state {
        static constexpr inline size_t max_inline_buffers = (sizeof(opaque_network_state::data) - sizeof(native_state) - sizeof(WSABUF*) - sizeof(bool)) / sizeof(WSABUF);
        WSABUF inline_bufs[max_inline_buffers];
        WSABUF* bufs = nullptr;
        bool uses_heap = false;

        sendv_state(util::native_worker_manager* mgr) : native_state(mgr) {
            on_complete = [](void* base) {
                auto s = static_cast<sendv_state*>(base);
                if (s->uses_heap) {
                    delete[] s->bufs;
                    s->uses_heap = false;
                }
            };
        }
    };

    bool tcp_socket::enter_sendv(const std::shared_ptr<task>& t, opaque_network_state& state, int32_t& bytes_sent, std::span<const std::span<const uint8_t>> data) {
        auto& ns = *new (&state) sendv_state(handle.get());
        ns.awaiting_task = t;
        ns.out_processed_bytes = &bytes_sent;

        if (data.size() <= sendv_state::max_inline_buffers)
            ns.bufs = ns.inline_bufs;
        else {
            ns.bufs = new WSABUF[data.size()];
            ns.uses_heap = true;
        }

        DWORD buf_count = 0;
        for (const auto& span : data) {
            if (!span.empty()) {
                ns.bufs[buf_count].buf = (CHAR*)span.data();
                ns.bufs[buf_count].len = (ULONG)span.size();
                buf_count++;
            }
        }

        int res = ::WSASend(handle->get_socket(), ns.bufs, buf_count, (PDWORD)&bytes_sent, 0, &ns.overlapped, NULL);

        if (res == 0)
            return false;

        int err = ::WSAGetLastError();
        if (err == WSA_IO_PENDING)
            return true;

        bytes_sent = -1;
        ns.error = err;
        return false;
    }

    struct transmit_file_state : public native_state {
        HANDLE file_handle = INVALID_HANDLE_VALUE;
        bool close_file_on_complete = false;

        transmit_file_state(util::native_worker_manager* mgr) : native_state(mgr) {
            on_complete = [](void* base) {
                auto s = static_cast<transmit_file_state*>(base);
                if (s->close_file_on_complete && s->file_handle != INVALID_HANDLE_VALUE) {
                    ::CloseHandle(s->file_handle);
                }
            };
        }
    };

    struct transmit_file_state : public native_state {
        HANDLE file_handle = INVALID_HANDLE_VALUE;
        bool close_file_on_complete = false;

        transmit_file_state(util::native_worker_manager* mgr) : native_state(mgr) {
            on_complete = [](void* base) {
                auto s = static_cast<transmit_file_state*>(base);
                if (s->close_file_on_complete && s->file_handle != INVALID_HANDLE_VALUE)
                    ::CloseHandle(s->file_handle);
            };
        }
    };

    bool tcp_socket::enter_send_file(const std::shared_ptr<task>& t, opaque_network_state& state, int32_t& bytes_sent, const char* file_path, size_t file_path_len, uint32_t data_len, uint64_t offset, uint32_t chunks_size) {
        auto& ns = *new (&state) transmit_file_state(handle.get());
        ns.awaiting_task = t;
        ns.out_processed_bytes = &bytes_sent;

        ns.file_handle = ::CreateFileA(file_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
        if (ns.file_handle == INVALID_HANDLE_VALUE) {
            bytes_sent = 0;
            ns.error = ::GetLastError();
            return true;
        }
        ns.close_file_on_complete = true;

        ns.overlapped.Offset = static_cast<DWORD>(offset & 0xFFFFFFFF);
        ns.overlapped.OffsetHigh = static_cast<DWORD>((offset >> 32) & 0xFFFFFFFF);

        BOOL res = _TransmitFile(handle->get_socket(), ns.file_handle, data_len, chunks_size, &ns.overlapped, NULL, 0);

        if (res == TRUE) {
            bytes_sent = static_cast<int32_t>(data_len);
            return true;
        }
        int err = ::WSAGetLastError();
        if (err == ERROR_IO_PENDING || err == WSA_IO_PENDING)
            return false;

        ::CloseHandle(ns.file_handle);
        ns.file_handle = INVALID_HANDLE_VALUE;
        ns.close_file_on_complete = false;
        bytes_sent = -1;
        ns.error = err;
        return true;
    }

    bool tcp_socket::enter_send_file(const std::shared_ptr<task>& t, opaque_network_state& state, int32_t& bytes_sent, class fast_task::file::file_handle& file_path, uint32_t data_len, uint64_t offset, uint32_t chunks_size) {
        auto& ns = *new (&state) transmit_file_state(handle.get());
        ns.awaiting_task = t;
        ns.out_processed_bytes = &bytes_sent;

        ns.file_handle = (HANDLE)file_path.internal_get_handle();
        ns.close_file_on_complete = false;

        ns.overlapped.Offset = static_cast<DWORD>(offset & 0xFFFFFFFF);
        ns.overlapped.OffsetHigh = static_cast<DWORD>((offset >> 32) & 0xFFFFFFFF);

        BOOL res = _TransmitFile(handle->get_socket(), ns.file_handle, data_len, chunks_size, &ns.overlapped, NULL, 0);

        if (res == TRUE) {
            bytes_sent = static_cast<int32_t>(data_len);
            return true;
        }
        int err = ::WSAGetLastError();
        if (err == ERROR_IO_PENDING || err == WSA_IO_PENDING)
            return false;

        bytes_sent = -1;
        ns.error = err;
        return true;
    }

    struct transmit_filev_state : public transmit_file_state {
        TRANSMIT_FILE_BUFFERS tfb{};

        transmit_filev_state(util::native_worker_manager* mgr) : transmit_file_state(mgr) {}
    };

    bool tcp_socket::enter_sendv_file(const std::shared_ptr<task>& t, opaque_network_state& state, int32_t& bytes_sent, const std::span<const uint8_t> prefix, const std::span<const uint8_t> postfix, const char* file_path, size_t file_path_len, uint32_t data_len, uint64_t offset, uint32_t chunks_size) {
        if (prefix.size() > 0xFFFFFFFF || postfix.size() > 0xFFFFFFFF)
            throw std::invalid_argument("Prefix or postfix too large for TransmitFile");

        auto& ns = *new (&state) transmit_filev_state(handle.get());
        ns.awaiting_task = t;
        ns.out_processed_bytes = &bytes_sent;

        ns.file_handle = ::CreateFileA(file_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
        if (ns.file_handle == INVALID_HANDLE_VALUE) {
            bytes_sent = -1;
            ns.error = ::GetLastError();
            return true;
        }
        ns.close_file_on_complete = true;

        if (!prefix.empty()) {
            ns.tfb.Head = (PVOID)prefix.data();
            ns.tfb.HeadLength = static_cast<DWORD>(prefix.size());
        }
        if (!postfix.empty()) {
            ns.tfb.Tail = (PVOID)postfix.data();
            ns.tfb.TailLength = static_cast<DWORD>(postfix.size());
        }

        ns.overlapped.Offset = static_cast<DWORD>(offset & 0xFFFFFFFF);
        ns.overlapped.OffsetHigh = static_cast<DWORD>((offset >> 32) & 0xFFFFFFFF);

        BOOL res = _TransmitFile(handle->get_socket(), ns.file_handle, data_len, chunks_size, &ns.overlapped, (ns.tfb.HeadLength || ns.tfb.TailLength) ? &ns.tfb : NULL, 0);

        if (res == TRUE) {
            bytes_sent = static_cast<int32_t>(data_len) + static_cast<int32_t>(prefix.size()) + static_cast<int32_t>(postfix.size());
            return true;
        }
        int err = ::WSAGetLastError();
        if (err == ERROR_IO_PENDING || err == WSA_IO_PENDING)
            return false;

        ::CloseHandle(ns.file_handle);
        ns.file_handle = INVALID_HANDLE_VALUE;
        ns.close_file_on_complete = false;

        bytes_sent = -1;
        ns.error = err;
        return true;
    }

    bool tcp_socket::enter_sendv_file(const std::shared_ptr<task>& t, opaque_network_state& state, int32_t& bytes_sent, const std::span<const uint8_t> prefix, const std::span<const uint8_t> postfix, class fast_task::file::file_handle& file_path, uint32_t data_len, uint64_t offset, uint32_t chunks_size) {
        if (prefix.size() > 0xFFFFFFFF || postfix.size() > 0xFFFFFFFF)
            throw std::invalid_argument("Prefix or postfix too large for TransmitFile");
        auto& ns = *new (&state) transmit_filev_state(handle.get());
        ns.awaiting_task = t;
        ns.out_processed_bytes = &bytes_sent;

        ns.file_handle = (HANDLE)file_path.internal_get_handle();
        ns.close_file_on_complete = false;

        if (!prefix.empty()) {
            ns.tfb.Head = (PVOID)prefix.data();
            ns.tfb.HeadLength = static_cast<DWORD>(prefix.size());
        }
        if (!postfix.empty()) {
            ns.tfb.Tail = (PVOID)postfix.data();
            ns.tfb.TailLength = static_cast<DWORD>(postfix.size());
        }

        ns.overlapped.Offset = static_cast<DWORD>(offset & 0xFFFFFFFF);
        ns.overlapped.OffsetHigh = static_cast<DWORD>((offset >> 32) & 0xFFFFFFFF);

        BOOL res = _TransmitFile(handle->get_socket(), ns.file_handle, data_len, chunks_size, &ns.overlapped, (ns.tfb.HeadLength || ns.tfb.TailLength) ? &ns.tfb : NULL, 0);

        if (res == TRUE) {
            bytes_sent = static_cast<int32_t>(data_len) + static_cast<int32_t>(prefix.size()) + static_cast<int32_t>(postfix.size());
            return true;
        }
        int err = ::WSAGetLastError();
        if (err == ERROR_IO_PENDING || err == WSA_IO_PENDING)
            return false;

        bytes_sent = -1;
        ns.error = err;
        return true;
    }

    bool tcp_socket::enter_shutdown(const std::shared_ptr<task>& t, opaque_network_state& state, shutdown_mode mode) {
        int how = SD_BOTH;
        switch (mode) {
        case shutdown_mode::read:
            how = SD_RECEIVE;
            break;
        case shutdown_mode::write:
            how = SD_SEND;
            break;
        case shutdown_mode::read_write:
            how = SD_BOTH;
            break;
        }

        int res = ::shutdown(handle->get_socket(), how);

        auto& ns = *new (&state) native_state(handle.get());
        ns.awaiting_task = nullptr;

        if (res == SOCKET_ERROR)
            ns.error = ::WSAGetLastError();

        return true;
    }

    bool tcp_socket::enter_reset(const std::shared_ptr<task>& t, opaque_network_state& state) {
        LINGER lingerStruct;
        lingerStruct.l_onoff = 1;
        lingerStruct.l_linger = 0;
        ::setsockopt(handle->get_socket(), SOL_SOCKET, SO_LINGER, (char*)&lingerStruct, sizeof(lingerStruct));

        auto& ns = *new (&state) native_state(handle.get());
        ns.awaiting_task = t;

        BOOL res = _DisconnectEx(handle->get_socket(), &ns.overlapped, 0, 0);

        if (res == TRUE)
            return true;

        int err = ::WSAGetLastError();
        if (err == WSA_IO_PENDING)
            return false;

        ns.error = err;
        return true;
    }

    bool tcp_socket::enter_close(const std::shared_ptr<task>& t, opaque_network_state& state) {
        auto& ns = *new (&state) native_state(handle.get());
        ns.awaiting_task = t;

        BOOL res = _DisconnectEx(handle->get_socket(), &ns.overlapped, 0, 0);

        if (res == TRUE)
            return true;

        int err = ::WSAGetLastError();
        if (err == WSA_IO_PENDING)
            return false;

        ns.error = err;
        return true;
    }

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
}
#endif