
// Copyright Danyil Melnytskyi 2022-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)
#ifdef _WIN64
    #include "net_shared.hpp"

    #include "tasks/_internal.hpp"
    #include "tasks/util/native_workers_singleton.hpp"
    #include <fast_task/file.hpp>
    #include <fast_task/net.hpp>
    #include <span>

namespace fast_task::net {
    static_assert(sizeof(universal_address) <= sizeof(address), "address buffer is too small for universal_address!");
    address address::any() {
        address res;
        internal_makeIP6(*(universal_address*)res.data, "::", 0);
        return res;
    }

    address address::any(uint16_t port) {
        address res;
        internal_makeIP6(*(universal_address*)res.data, "::", port);
        return res;
    }

    address::address(void* ip) {
        memset(data, 0, sizeof(data));
        if (!ip)
            return;
        const auto* sa = reinterpret_cast<const sockaddr*>(ip);
        if (sa->sa_family == AF_INET) {
            const auto* sin = reinterpret_cast<const sockaddr_in*>(ip);
            sockaddr_in6 sin6{};
            sin6.sin6_family = AF_INET6;
            sin6.sin6_port = sin->sin_port;
            sin6.sin6_addr.s6_addr[10] = 0xFF;
            sin6.sin6_addr.s6_addr[11] = 0xFF;
            memcpy(&sin6.sin6_addr.s6_addr[12], &sin->sin_addr, sizeof(sin->sin_addr));
            memcpy(data, &sin6, sizeof(sin6));
        } else if (sa->sa_family == AF_INET6) {
            memcpy(data, ip, sizeof(sockaddr_in6));
        } else {
            memcpy(data, ip, sizeof(sockaddr));
        }
    }

    address::address() {
    }

    address::address(std::string_view ip_port) {
        if (ip_port.empty())
            ip_port = "[::]:0";
        std::string ip_port_str(ip_port);
        internal_makeIP_port(*((universal_address*)data), ip_port_str.c_str());
    }

    address::address(std::string_view ip, uint16_t port) {
        if (ip.empty())
            ip = "::";
        std::string ip_str(ip);
        internal_makeIP(*((universal_address*)data), ip_str.c_str(), port);
    }

    address::address(const address& ip) {
        memcpy(data, ip.data, sizeof(universal_address));
    }

    address::address(address&& ip) noexcept {
        memcpy(data, ip.data, sizeof(universal_address));
        memset(ip.data, 0, sizeof(universal_address));
    }

    address::~address() {
    }

    address& address::operator=(const address& ip) {
        memcpy(data, ip.data, sizeof(universal_address));
        return *this;
    }

    address& address::operator=(address&& ip) noexcept {
        if (&ip == this)
            return *this;
        memcpy(data, ip.data, sizeof(universal_address));
        memset(ip.data, 0, sizeof(universal_address));
        return *this;
    }

    address::family address::get_family() const noexcept {
        for (size_t i = 0; i < sizeof(universal_address); i++) {
            if (data[i] != 0)
                goto non_zero_found;
        }
        return family::none;
    non_zero_found:
        universal_address* addr = (universal_address*)data;
        if (addr->ss_family == AF_INET)
            return family::ipv4;
        else if (addr->ss_family == AF_INET6) {
            if (IN6_IS_ADDR_V4MAPPED(&((sockaddr_in6*)addr)->sin6_addr))
                return family::ipv4;
            return family::ipv6;
        } else
            return family::other;
    }

    uint16_t address::port() const noexcept {
        universal_address* addr = (universal_address*)data;
        if (addr->ss_family == AF_INET) {
            return ntohs(((sockaddr_in*)addr)->sin_port);
        } else if (addr->ss_family == AF_INET6) {
            return ntohs(((sockaddr_in6*)addr)->sin6_port);
        } else
            return 0;
    }

    std::string address::to_string() const {
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

    bool address::operator==(const address& other) const noexcept {
        return memcmp(data, other.data, sizeof(universal_address)) == 0;
    }

    bool address::operator!=(const address& other) const noexcept {
        return !(*this == other);
    }

    bool address::is_loopback() const noexcept {
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

    size_t address::data_size() noexcept {
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

    std::atomic<bool> inited{false};
    static std::mutex net_init_mutex;

    ::LPFN_ACCEPTEX _AcceptEx;
    ::LPFN_GETACCEPTEXSOCKADDRS _GetAcceptExSockaddrs;
    ::LPFN_CONNECTEX _ConnectEx;
    ::LPFN_TRANSMITFILE _TransmitFile;
    ::LPFN_DISCONNECTEX _DisconnectEx;
    ::WSADATA wsaData;

    void init_win_fns(SOCKET sock) {
        static std::once_flag win_fns_flag;
        std::call_once(win_fns_flag, [sock] {
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
        });
    }

    #pragma region TCP

    struct native_state : public util::native_worker_handle {
        task awaiting_task;
        int32_t* out_processed_bytes = nullptr;
        int error = 0;
        void (*on_complete)(void*) = nullptr;

        native_state(util::native_worker_manager* mgr)
            : util::native_worker_handle(mgr) {
        }
    };

    tcp_error opaque_network_state::get_error() const noexcept {
        if (!destruct)
            return tcp_error::none;
        auto& state = *reinterpret_cast<const native_state*>(this);
        if (state.error == 0 || WSA_IO_PENDING == state.error)
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

    std::error_code opaque_network_state::get_error_code() const noexcept {
        if (!destruct)
            return {};
        auto& state = *reinterpret_cast<const native_state*>(this);
        return std::error_code(state.error, std::system_category());
    }

    class tcp_socket::manager : public util::native_worker_manager {
        SOCKET sock = INVALID_SOCKET;
        bool ops_inited = false;

    public:
        enum class connection_method : bool {
            connect,
            accept,
        };

        const connection_method method;

        manager(SOCKET s, connection_method method) : sock(s), method(method) {
            if (sock != INVALID_SOCKET) {
                init_win_fns(sock);
                HANDLE hSock = reinterpret_cast<HANDLE>(sock);
                util::native_workers_singleton::register_handle(hSock, this);
                ::SetFileCompletionNotificationModes(hSock, FILE_SKIP_COMPLETION_PORT_ON_SUCCESS | FILE_SKIP_SET_EVENT_ON_HANDLE);
            }
        }

        ~manager() override {
            close_socket();
        }

        manager(const manager&) = delete;
        manager& operator=(const manager&) = delete;
        manager(manager&&) = delete;
        manager& operator=(manager&&) = delete;

        SOCKET get_socket() const noexcept {
            return sock;
        }

        void close_socket() noexcept {
            if (sock != INVALID_SOCKET) {
                closesocket(sock);
                sock = INVALID_SOCKET;
            }
        }

        SOCKET get_socket_for_ops() noexcept {
            if (ops_inited)
                return sock;
            else if (sock != INVALID_SOCKET) {
                if (method == connection_method::connect)
                    if (auto res = setsockopt(sock, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0); res != NO_ERROR)
                        return INVALID_SOCKET;
            }
            ops_inited = true;
            return sock;
        }

        void handle([[maybe_unused]] void*, util::native_worker_handle* overlap, unsigned long dwBytesTransferred) override {
            auto state = static_cast<native_state*>(overlap);
            DWORD dwFlags = 0;
            DWORD cbTransfer = 0;
            if (!::WSAGetOverlappedResult(sock, &state->overlapped, &cbTransfer, FALSE, &dwFlags)) {
                state->error = ::WSAGetLastError();
            } else
                state->error = 0;

            if (state->on_complete)
                state->on_complete(static_cast<void*>(state));
            if (state->awaiting_task) {
                if (state->out_processed_bytes) {
                    if (state->error)
                        *state->out_processed_bytes = -1;
                    else
                        *state->out_processed_bytes = dwBytesTransferred;
                }
                fast_task::lock_guard guard(get_data(state->awaiting_task));
                transfer_task(std::move(state->awaiting_task));
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
                cfg = static_cast<int>(std::max<uint32_t>(1, config.keep_alive_settings.idle_ms / 1000));
                if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, (char*)&cfg, sizeof(cfg)) == -1)
                    return false;
                cfg = static_cast<int>(std::max<uint32_t>(1, config.keep_alive_settings.interval_ms / 1000));
                if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, (char*)&cfg, sizeof(cfg)) == -1)
                    return false;
                cfg = config.keep_alive_settings.retry_count == 0 ? 3 : config.keep_alive_settings.retry_count;
                if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, (char*)&cfg, sizeof(cfg)) == -1)
                    return false;
    #ifdef TCP_MAXRTMS
                cfg = static_cast<int>(config.keep_alive_settings.user_timeout_ms);
                if (setsockopt(sock, IPPROTO_TCP, TCP_MAXRTMS, (char*)&cfg, sizeof(cfg)) == -1)
                    return false;
    #else
                cfg = static_cast<int>(std::max<uint32_t>(1, config.keep_alive_settings.user_timeout_ms / 1000));
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

        auto* loc = get_loc();
        if (loc && loc->is_task_thread) {
            mutex_unify mut(get_data(loc->curr_task).get_self_unify());
            std::unique_lock guard(mut);
            if (!tcp_socket::enter_connect(loc->curr_task, state, res, ip_port, config)) {
                guard.release();
                swapCtxUnlock(mut);
            }
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
                scheduler::ensure_global_worker();
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
        return res;
    }

    std::optional<tcp_socket> tcp_socket::connect(const address& ip_port, uint8_t* data, int32_t& size, const tcp_configuration& config) {
        std::optional<tcp_socket> res;
        opaque_network_state state;

        auto* loc = get_loc();
        if (loc && loc->is_task_thread) {
            mutex_unify mut(get_data(loc->curr_task).get_self_unify());
            std::unique_lock guard(mut);
            if (!tcp_socket::enter_connect(loc->curr_task, state, res, ip_port, data, size, config)) {
                guard.release();
                swapCtxUnlock(mut);
            }
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
                scheduler::ensure_global_worker();
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
        return res;
    }

    int32_t tcp_socket::recv(std::span<uint8_t> data) {
        opaque_network_state state;
        int32_t bytes_read = 0;

        auto* loc = get_loc();
        if (loc && loc->is_task_thread) {
            mutex_unify mut(get_data(loc->curr_task).get_self_unify());
            std::unique_lock guard(mut);
            if (!tcp_socket::enter_recv(loc->curr_task, state, bytes_read, data)) {
                guard.release();
                swapCtxUnlock(mut);
            }
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
                scheduler::ensure_global_worker();
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
        return bytes_read;
    }

    int32_t tcp_socket::recvv(std::span<std::span<uint8_t>> data) {
        opaque_network_state state;
        int32_t bytes_read = 0;

        auto* loc = get_loc();
        if (loc && loc->is_task_thread) {
            mutex_unify mut(get_data(loc->curr_task).get_self_unify());
            std::unique_lock guard(mut);
            if (!tcp_socket::enter_recvv(loc->curr_task, state, bytes_read, data)) {
                guard.release();
                swapCtxUnlock(mut);
            }
        } else {
            std::mutex mtx;
            std::condition_variable cv;
            bool done = false;

            auto t = task::create([&] {
                std::lock_guard lock(mtx);
                done = true;
                cv.notify_one();
            });

            if (!tcp_socket::enter_recvv(t, state, bytes_read, data)) {
                scheduler::ensure_global_worker();
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
        return bytes_read;
    }

    int32_t tcp_socket::send(std::span<const uint8_t> data) {
        opaque_network_state state;
        int32_t res = 0;

        auto* loc = get_loc();
        if (loc && loc->is_task_thread) {
            mutex_unify mut(get_data(loc->curr_task).get_self_unify());
            std::unique_lock guard(mut);
            if (!tcp_socket::enter_send(loc->curr_task, state, res, data)) {
                guard.release();
                swapCtxUnlock(mut);
            }
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
                scheduler::ensure_global_worker();
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
        return res;
    }

    int32_t tcp_socket::sendv(std::span<const std::span<const uint8_t>> data) {
        opaque_network_state state;
        int32_t res = 0;

        auto* loc = get_loc();
        if (loc && loc->is_task_thread) {
            mutex_unify mut(get_data(loc->curr_task).get_self_unify());
            std::unique_lock guard(mut);
            if (!tcp_socket::enter_sendv(loc->curr_task, state, res, data)) {
                guard.release();
                swapCtxUnlock(mut);
            }
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
                scheduler::ensure_global_worker();
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
        return res;
    }

    int32_t tcp_socket::send_file(const char* file_path, size_t file_path_len, uint32_t data_len, uint64_t offset, uint32_t chunks_size) {
        opaque_network_state state;
        int32_t res = 0;

        auto* loc = get_loc();
        if (loc && loc->is_task_thread) {
            mutex_unify mut(get_data(loc->curr_task).get_self_unify());
            std::unique_lock guard(mut);
            if (!tcp_socket::enter_send_file(loc->curr_task, state, res, file_path, file_path_len, data_len, offset, chunks_size)) {
                guard.release();
                swapCtxUnlock(mut);
            }
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
                scheduler::ensure_global_worker();
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
        return res;
    }

    int32_t tcp_socket::send_file(class fast_task::file::file_handle& file, uint32_t data_len, uint64_t offset, uint32_t chunks_size) {
        opaque_network_state state;
        int32_t res = 0;

        auto* loc = get_loc();
        if (loc && loc->is_task_thread) {
            mutex_unify mut(get_data(loc->curr_task).get_self_unify());
            std::unique_lock guard(mut);
            if (!tcp_socket::enter_send_file(loc->curr_task, state, res, file, data_len, offset, chunks_size)) {
                guard.release();
                swapCtxUnlock(mut);
            }
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
                scheduler::ensure_global_worker();
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
        return res;
    }

    int32_t tcp_socket::sendv_file(const std::span<const uint8_t> prefix, const std::span<const uint8_t> postfix, const char* file_path, size_t file_path_len, uint32_t data_len, uint64_t offset, uint32_t chunks_size) {
        opaque_network_state state;
        int32_t res = 0;

        auto* loc = get_loc();
        if (loc && loc->is_task_thread) {
            mutex_unify mut(get_data(loc->curr_task).get_self_unify());
            std::unique_lock guard(mut);
            if (!tcp_socket::enter_sendv_file(loc->curr_task, state, res, prefix, postfix, file_path, file_path_len, data_len, offset, chunks_size)) {
                guard.release();
                swapCtxUnlock(mut);
            }
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
                scheduler::ensure_global_worker();
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
        return res;
    }

    int32_t tcp_socket::sendv_file(const std::span<const uint8_t> prefix, const std::span<const uint8_t> postfix, class fast_task::file::file_handle& file, uint32_t data_len, uint64_t offset, uint32_t chunks_size) {
        opaque_network_state state;
        int32_t res = 0;

        auto* loc = get_loc();
        if (loc && loc->is_task_thread) {
            mutex_unify mut(get_data(loc->curr_task).get_self_unify());
            std::unique_lock guard(mut);
            if (!tcp_socket::enter_sendv_file(loc->curr_task, state, res, prefix, postfix, file, data_len, offset, chunks_size)) {
                guard.release();
                swapCtxUnlock(mut);
            }
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
                scheduler::ensure_global_worker();
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
        return res;
    }

    void tcp_socket::shutdown(shutdown_mode mode) {
        opaque_network_state state;

        auto* loc = get_loc();
        if (loc && loc->is_task_thread) {
            mutex_unify mut(get_data(loc->curr_task).get_self_unify());
            std::unique_lock guard(mut);
            if (!tcp_socket::enter_shutdown(loc->curr_task, state, mode)) {
                guard.release();
                swapCtxUnlock(mut);
            }
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
                scheduler::ensure_global_worker();
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
    }

    void tcp_socket::reset() {
        opaque_network_state state;

        auto* loc = get_loc();
        if (loc && loc->is_task_thread) {
            mutex_unify mut(get_data(loc->curr_task).get_self_unify());
            std::unique_lock guard(mut);
            if (!tcp_socket::enter_reset(loc->curr_task, state)) {
                guard.release();
                swapCtxUnlock(mut);
            }
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
                scheduler::ensure_global_worker();
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
    }

    void tcp_socket::close() {
        opaque_network_state state;

        auto* loc = get_loc();
        if (loc && loc->is_task_thread) {
            mutex_unify mut(get_data(loc->curr_task).get_self_unify());
            std::unique_lock guard(mut);
            if (!tcp_socket::enter_close(loc->curr_task, state)) {
                guard.release();
                swapCtxUnlock(mut);
            }
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
                scheduler::ensure_global_worker();
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
        if (!handle)
            return address();
        auto socket = handle->get_socket_for_ops();
        if (socket == INVALID_SOCKET)
            return address();

        sockaddr_storage addr{};
        socklen_t addr_len = sizeof(addr);
        if (getsockname(socket, (sockaddr*)&addr, &addr_len) == -1)
            return address();
        return to_address(&addr);
    }

    address tcp_socket::remote_address() const noexcept {
        if (!handle)
            return address();
        auto socket = handle->get_socket_for_ops();
        if (socket == INVALID_SOCKET)
            return address();

        sockaddr_storage addr{};
        socklen_t addr_len = sizeof(addr);
        if (getpeername(socket, (sockaddr*)&addr, &addr_len) == -1)
            return address();
        return to_address(&addr);
    }

    struct connect_state : public native_state {
        std::optional<tcp_socket>* out_socket = nullptr;
        SOCKET sock = INVALID_SOCKET;

        connect_state(util::native_worker_manager* mgr, std::optional<tcp_socket>* out, SOCKET s)
            : native_state(mgr), out_socket(out), sock(s) {
            on_complete = [](void* base) {
                auto* st = static_cast<connect_state*>(base);
                if (st->error != 0) {
                    if (st->out_socket)
                        *st->out_socket = std::nullopt;
                } else if (st->sock != INVALID_SOCKET) {
                    ::setsockopt(st->sock, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0);
                }
            };
        }
    };

    bool tcp_socket::enter_connect(const task& t, opaque_network_state& state, std::optional<tcp_socket>& res, const address& ip_port, const tcp_configuration& config) {
        SOCKET sock = ::WSASocketW(AF_INET6, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
        if (sock == INVALID_SOCKET)
            return true;

        auto mgr = std::make_unique<manager>(sock, tcp_socket::manager::connection_method::connect);
        if (!mgr->set_configuration(config))
            return true;

        sockaddr_in6 bind_addr{0};
        bind_addr.sin6_family = AF_INET6;
        bind_addr.sin6_addr = IN6ADDR_ANY_INIT;
        bind_addr.sin6_port = 0;
        if (::bind(sock, (SOCKADDR*)&bind_addr, sizeof(bind_addr)) == SOCKET_ERROR) {
            state.use<native_state>(nullptr)->error = ::WSAGetLastError();
            return true;
        }

        auto& n_state = *state.use<connect_state>(mgr.get(), &res, sock);
        n_state.awaiting_task = t;

        DWORD bytesSent = 0;
        if (!_ConnectEx(sock, (sockaddr*)ip_port.get_data(), (int)ip_port.data_size(), nullptr, 0, &bytesSent, &n_state.overlapped)) {
            int err = ::WSAGetLastError();
            if (err != ERROR_IO_PENDING) {
                res = std::nullopt;
                n_state.error = err;
                return true;
            }

            n_state.error = WSA_IO_PENDING;
            tcp_socket new_sock;
            new_sock.handle = std::move(mgr);
            res = std::move(new_sock);
            return false;
        }

        ::setsockopt(sock, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0);
        n_state.error = 0;
        tcp_socket new_sock;
        new_sock.handle = std::move(mgr);
        res = std::move(new_sock);
        return true;
    }

    bool tcp_socket::enter_connect(const task& t, opaque_network_state& state, std::optional<tcp_socket>& res, const address& ip_port, uint8_t* data, int32_t& size, const tcp_configuration& config) {
        SOCKET sock = ::WSASocketW(AF_INET6, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
        if (sock == INVALID_SOCKET)
            return true;

        auto mgr = std::make_unique<manager>(sock, tcp_socket::manager::connection_method::connect);
        if (!mgr->set_configuration(config))
            return true;

        sockaddr_in6 bind_addr{0};
        bind_addr.sin6_family = AF_INET6;
        bind_addr.sin6_addr = IN6ADDR_ANY_INIT;
        bind_addr.sin6_port = 0;
        if (::bind(sock, (SOCKADDR*)&bind_addr, sizeof(bind_addr)) == SOCKET_ERROR) {
            state.use<native_state>(nullptr)->error = ::WSAGetLastError();
            return true;
        }

        auto& n_state = *state.use<connect_state>(mgr.get(), &res, sock);
        n_state.awaiting_task = t;
        n_state.out_processed_bytes = &size;

        DWORD bytesSent = 0;
        DWORD sendLen = (data && size > 0) ? static_cast<DWORD>(size) : 0;
        if (!_ConnectEx(sock, (sockaddr*)ip_port.get_data(), (int)ip_port.data_size(), data, sendLen, &bytesSent, &n_state.overlapped)) {
            int err = ::WSAGetLastError();
            if (err != ERROR_IO_PENDING) {
                res = std::nullopt;
                n_state.error = err;
                return true;
            }

            n_state.error = WSA_IO_PENDING;
            tcp_socket new_sock;
            new_sock.handle = std::move(mgr);
            res = std::move(new_sock);
            return false;
        }

        ::setsockopt(sock, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0);
        size = static_cast<int32_t>(bytesSent);
        n_state.error = 0;
        tcp_socket new_sock;
        new_sock.handle = std::move(mgr);
        res = std::move(new_sock);
        return true;
    }

    bool tcp_socket::enter_recv(const task& t, opaque_network_state& state, int32_t& bytes_read, std::span<uint8_t> data) {
        struct recv_state : public native_state {
            WSABUF buf{};
            DWORD flags = 0;

            recv_state(util::native_worker_manager* mgr) : native_state(mgr) {}
        };

        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            bytes_read = -1;
            state.use<native_state>(nullptr)->error = WSAENOTSOCK;
            return true;
        }

        auto& n_state = *state.use<recv_state>(handle.get());
        n_state.awaiting_task = t;
        n_state.out_processed_bytes = &bytes_read;
        n_state.buf.buf = reinterpret_cast<CHAR*>(data.data());
        n_state.buf.len = static_cast<ULONG>(data.size());
        n_state.flags = 0;

        if (::WSARecv(handle->get_socket(), &n_state.buf, 1, (PDWORD)&bytes_read, &n_state.flags, &n_state.overlapped, NULL) == SOCKET_ERROR) {
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

    bool tcp_socket::enter_recvv(const task& t, opaque_network_state& state, int32_t& bytes_read, std::span<std::span<uint8_t>> data) {
        static constexpr size_t max_inline_buffers = (sizeof(opaque_network_state::data) - sizeof(native_state) - sizeof(WSABUF*) - sizeof(DWORD) - sizeof(bool) - alignof(WSABUF)) / sizeof(WSABUF);

        struct recvv_state : public native_state {
            WSABUF inline_bufs[max_inline_buffers];
            WSABUF* bufs = nullptr;
            DWORD flags = 0;
            bool uses_heap = false;

            recvv_state(util::native_worker_manager* mgr) : native_state(mgr) {
                on_complete = [](void* base) {
                    auto s = static_cast<recvv_state*>(base);
                    if (s->uses_heap) {
                        delete[] s->bufs;
                        s->uses_heap = false;
                    }
                };
            }

            ~recvv_state() {
                if (uses_heap) {
                    delete[] bufs;
                    uses_heap = false;
                }
            }
        };

        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            bytes_read = -1;
            state.use<native_state>(nullptr)->error = WSAENOTSOCK;
            return true;
        }

        auto& ns = *state.use<recvv_state>(handle.get());
        ns.awaiting_task = t;
        ns.out_processed_bytes = &bytes_read;

        if (data.size() <= max_inline_buffers)
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

        ns.flags = 0;
        if (::WSARecv(handle->get_socket(), ns.bufs, buf_count, (PDWORD)&bytes_read, &ns.flags, &ns.overlapped, NULL) == SOCKET_ERROR) {
            int err = ::WSAGetLastError();
            if (err != WSA_IO_PENDING) {
                ns.error = err;
                bytes_read = -1;
                return true;
            }

            ns.error = WSA_IO_PENDING;
            return false;
        }

        ns.error = 0;
        return true;
    }

    bool tcp_socket::enter_send(const task& t, opaque_network_state& state, int32_t& bytes_sent, std::span<const uint8_t> data) {
        struct send_state : public native_state {
            WSABUF buf{};

            send_state(util::native_worker_manager* mgr) : native_state(mgr) {}
        };

        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            bytes_sent = -1;
            state.use<native_state>(nullptr)->error = WSAENOTSOCK;
            return true;
        }

        auto& ns = *state.use<send_state>(handle.get());
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

    bool tcp_socket::enter_sendv(const task& t, opaque_network_state& state, int32_t& bytes_sent, std::span<const std::span<const uint8_t>> data) {
        static constexpr size_t max_inline_buffers = (sizeof(opaque_network_state::data) - sizeof(native_state) - sizeof(WSABUF*) - sizeof(bool) - alignof(WSABUF)) / sizeof(WSABUF);

        struct sendv_state : public native_state {
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

            ~sendv_state() {
                if (uses_heap) {
                    delete[] bufs;
                    uses_heap = false;
                }
            }
        };

        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            bytes_sent = -1;
            state.use<native_state>(nullptr)->error = WSAENOTSOCK;
            return true;
        }

        auto& ns = *state.use<sendv_state>(handle.get());
        ns.awaiting_task = t;
        ns.out_processed_bytes = &bytes_sent;

        if (data.size() <= max_inline_buffers)
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
            return true;

        int err = ::WSAGetLastError();
        if (err == WSA_IO_PENDING)
            return false;

        bytes_sent = -1;
        ns.error = err;
        return true;
    }

    struct transmit_file_state : public native_state {
        HANDLE file_handle = INVALID_HANDLE_VALUE;
        bool close_file_on_complete = false;

        transmit_file_state(util::native_worker_manager* mgr) : native_state(mgr) {
            on_complete = [](void* base) {
                auto s = static_cast<transmit_file_state*>(base);
                if (s->close_file_on_complete && s->file_handle != INVALID_HANDLE_VALUE) {
                    ::CloseHandle(s->file_handle);
                    s->file_handle = INVALID_HANDLE_VALUE;
                    s->close_file_on_complete = false;
                }
            };
        }

        ~transmit_file_state() {
            if (close_file_on_complete && file_handle != INVALID_HANDLE_VALUE) {
                ::CloseHandle(file_handle);
                file_handle = INVALID_HANDLE_VALUE;
                close_file_on_complete = false;
            }
        }
    };

    bool tcp_socket::enter_send_file(const task& t, opaque_network_state& state, int32_t& bytes_sent, const char* file_path, size_t file_path_len, uint32_t data_len, uint64_t offset, uint32_t chunks_size) {
        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            bytes_sent = -1;
            state.use<native_state>(nullptr)->error = WSAENOTSOCK;
            return true;
        }

        auto& ns = *state.use<transmit_file_state>(handle.get());
        ns.awaiting_task = t;
        ns.out_processed_bytes = &bytes_sent;

        if (!file_path) {
            bytes_sent = -1;
            ns.error = ERROR_INVALID_PARAMETER;
            return true;
        }
        std::string path_str(file_path, file_path_len);
        ns.file_handle = ::CreateFileA(path_str.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
        if (ns.file_handle == INVALID_HANDLE_VALUE) {
            bytes_sent = -1;
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

        bytes_sent = -1;
        ns.error = err;
        return true;
    }

    bool tcp_socket::enter_send_file(const task& t, opaque_network_state& state, int32_t& bytes_sent, class fast_task::file::file_handle& file_path, uint32_t data_len, uint64_t offset, uint32_t chunks_size) {
        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            bytes_sent = -1;
            state.use<native_state>(nullptr)->error = WSAENOTSOCK;
            return true;
        }

        auto& ns = *state.use<transmit_file_state>(handle.get());
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

    bool tcp_socket::enter_sendv_file(const task& t, opaque_network_state& state, int32_t& bytes_sent, const std::span<const uint8_t> prefix, const std::span<const uint8_t> postfix, const char* file_path, size_t file_path_len, uint32_t data_len, uint64_t offset, uint32_t chunks_size) {
        if (prefix.size() > 0xFFFFFFFF || postfix.size() > 0xFFFFFFFF)
            throw std::invalid_argument("Prefix or postfix too large for TransmitFile");

        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            bytes_sent = -1;
            state.use<native_state>(nullptr)->error = WSAENOTSOCK;
            return true;
        }

        auto& ns = *state.use<transmit_filev_state>(handle.get());
        ns.awaiting_task = t;
        ns.out_processed_bytes = &bytes_sent;

        if (!file_path) {
            bytes_sent = -1;
            ns.error = ERROR_INVALID_PARAMETER;
            return true;
        }
        std::string path_str(file_path, file_path_len);
        ns.file_handle = ::CreateFileA(path_str.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
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

        bytes_sent = -1;
        ns.error = err;
        return true;
    }

    bool tcp_socket::enter_sendv_file(const task& t, opaque_network_state& state, int32_t& bytes_sent, const std::span<const uint8_t> prefix, const std::span<const uint8_t> postfix, class fast_task::file::file_handle& file_path, uint32_t data_len, uint64_t offset, uint32_t chunks_size) {
        if (prefix.size() > 0xFFFFFFFF || postfix.size() > 0xFFFFFFFF)
            throw std::invalid_argument("Prefix or postfix too large for TransmitFile");

        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            bytes_sent = -1;
            state.use<native_state>(nullptr)->error = WSAENOTSOCK;
            return true;
        }

        auto& ns = *state.use<transmit_filev_state>(handle.get());
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

    bool tcp_socket::enter_shutdown([[maybe_unused]] const task& t, opaque_network_state& state, shutdown_mode mode) {
        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            state.use<native_state>(nullptr)->error = WSAENOTSOCK;
            return true;
        }

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

        int res = ::shutdown(handle->get_socket_for_ops(), how);

        auto& ns = *state.use<native_state>(handle.get());
        ns.awaiting_task = nullptr;

        if (res == SOCKET_ERROR)
            ns.error = ::WSAGetLastError();

        return true;
    }

    bool tcp_socket::enter_reset(const task&, opaque_network_state& state) {
        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            state.use<native_state>(nullptr)->error = WSAENOTSOCK;
            return true;
        }

        LINGER lingerStruct;
        lingerStruct.l_onoff = 1;
        lingerStruct.l_linger = 0;
        ::setsockopt(handle->get_socket(), SOL_SOCKET, SO_LINGER, (char*)&lingerStruct, sizeof(lingerStruct));

        handle->close_socket();
        return true;
    }

    bool tcp_socket::enter_close(const task& t, opaque_network_state& state) {
        if (!handle || handle->get_socket() == INVALID_SOCKET)
            return true;

        struct close_state : public native_state {
            tcp_socket::manager* mgr;

            close_state(tcp_socket::manager* m) : native_state(m), mgr(m) {
                on_complete = [](void* base) {
                    auto* s = static_cast<close_state*>(base);
                    if (s->mgr)
                        s->mgr->close_socket();
                };
            }
        };

        auto& ns = *state.use<close_state>(handle.get());
        ns.awaiting_task = t;

        BOOL res = _DisconnectEx(handle->get_socket(), &ns.overlapped, 0, 0);

        if (res == TRUE) {
            handle->close_socket();
            return true;
        }

        int err = ::WSAGetLastError();
        if (err == WSA_IO_PENDING)
            return false;

        handle->close_socket();
        ns.error = err;
        return true;
    }

    #pragma endregion

    #pragma region TCP Listener

    class tcp_listener::manager : public util::native_worker_manager {
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
            close_socket();
        }

        manager(const manager&) = delete;
        manager& operator=(const manager&) = delete;
        manager(manager&&) = delete;
        manager& operator=(manager&&) = delete;

        SOCKET get_socket() const noexcept {
            return sock;
        }

        void close_socket() noexcept {
            if (sock != INVALID_SOCKET) {
                closesocket(sock);
                sock = INVALID_SOCKET;
            }
        }

        void handle(void* /*data*/, util::native_worker_handle* overlap, unsigned long dwBytesTransferred) override {
            auto state = static_cast<native_state*>(overlap);
            DWORD dwFlags = 0;
            DWORD cbTransfer = 0;
            if (!::WSAGetOverlappedResult(sock, &state->overlapped, &cbTransfer, FALSE, &dwFlags)) {
                state->error = ::WSAGetLastError();
            } else
                state->error = 0;

            if (state->on_complete)
                state->on_complete(static_cast<void*>(state));
            if (state->awaiting_task) {
                if (state->out_processed_bytes) {
                    if (state->error)
                        *state->out_processed_bytes = -1;
                    else
                        *state->out_processed_bytes = static_cast<int32_t>(dwBytesTransferred);
                }
                fast_task::lock_guard guard(get_data(state->awaiting_task));
                transfer_task(std::move(state->awaiting_task));
            }
        }

        bool set_configuration(const tcp_configuration& config) {
            int cfg = !config.allow_ip4;
            if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&cfg, sizeof(cfg)) == SOCKET_ERROR)
                return false;
            cfg = !config.enable_delay;
            if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char*)&cfg, sizeof(cfg)) == SOCKET_ERROR)
                return false;
            cfg = config.recv_timeout_ms;
            if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&cfg, sizeof(cfg)) == SOCKET_ERROR)
                return false;
            cfg = config.send_timeout_ms;
            if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&cfg, sizeof(cfg)) == SOCKET_ERROR)
                return false;
            cfg = config.enable_keep_alive;
            if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (char*)&cfg, sizeof(cfg)) == SOCKET_ERROR)
                return false;
            if (config.enable_keep_alive) {
                cfg = static_cast<int>(std::max<uint32_t>(1, config.keep_alive_settings.idle_ms / 1000));
                if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, (char*)&cfg, sizeof(cfg)) == SOCKET_ERROR)
                    return false;
                cfg = static_cast<int>(std::max<uint32_t>(1, config.keep_alive_settings.interval_ms / 1000));
                if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, (char*)&cfg, sizeof(cfg)) == SOCKET_ERROR)
                    return false;
                cfg = config.keep_alive_settings.retry_count == 0 ? 3 : config.keep_alive_settings.retry_count;
                if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, (char*)&cfg, sizeof(cfg)) == SOCKET_ERROR)
                    return false;
    #ifdef TCP_MAXRTMS
                cfg = static_cast<int>(config.keep_alive_settings.user_timeout_ms);
                if (setsockopt(sock, IPPROTO_TCP, TCP_MAXRTMS, (char*)&cfg, sizeof(cfg)) == SOCKET_ERROR)
                    return false;
    #else
                cfg = static_cast<int>(std::max<uint32_t>(1, config.keep_alive_settings.user_timeout_ms / 1000));
                if (setsockopt(sock, IPPROTO_TCP, TCP_MAXRT, (char*)&cfg, sizeof(cfg)) == SOCKET_ERROR)
                    return false;
    #endif
            }
            DWORD argp = 1;
            if (ioctlsocket(sock, FIONBIO, &argp) == SOCKET_ERROR)
                return false;
            return true;
        }
    };

    static constexpr DWORD accept_addr_buf_len = sizeof(SOCKADDR_IN6) + 16;

    struct accept_state : public native_state {
        SOCKET accept_socket = INVALID_SOCKET;
        SOCKET listen_socket = INVALID_SOCKET;
        std::optional<tcp_socket>* out_socket = nullptr;
        char addr_buf[accept_addr_buf_len * 2];

        accept_state(util::native_worker_manager* mgr, SOCKET ls) : native_state(mgr), listen_socket(ls) {}
    };

    tcp_listener::tcp_listener() = default;
    tcp_listener::tcp_listener(tcp_listener&&) = default;
    tcp_listener& tcp_listener::operator=(tcp_listener&&) = default;
    tcp_listener::~tcp_listener() = default;

    std::optional<tcp_listener> tcp_listener::bind(const address& ip_port, const tcp_configuration& config) {
        SOCKET listenSocket = ::WSASocketW(AF_INET6, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
        if (listenSocket == INVALID_SOCKET)
            return std::nullopt;
        auto mgr = std::make_unique<manager>(listenSocket);
        if (!mgr->set_configuration(config))
            return std::nullopt;
        if (::bind(listenSocket, (sockaddr*)ip_port.get_data(), (int)ip_port.data_size()) == SOCKET_ERROR)
            return std::nullopt;
        if (::listen(listenSocket, SOMAXCONN) == SOCKET_ERROR)
            return std::nullopt;
        tcp_listener new_listener;
        new_listener.handle = std::move(mgr);
        return new_listener;
    }

    std::optional<tcp_socket> tcp_listener::accept() {
        std::optional<tcp_socket> res;
        opaque_network_state state;

        auto* loc = get_loc();
        if (loc && loc->is_task_thread) {
            mutex_unify mut(get_data(loc->curr_task).get_self_unify());
            std::unique_lock guard(mut);
            if (!enter_accept(loc->curr_task, state, res)) {
                guard.release();
                swapCtxUnlock(mut);
            }
        } else {
            std::mutex mtx;
            std::condition_variable cv;
            bool done = false;
            auto t = task::create([&] {
                std::lock_guard lock(mtx);
                done = true;
                cv.notify_one();
            });
            if (!enter_accept(t, state, res)) {
                scheduler::ensure_global_worker();
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
        return res;
    }

    void tcp_listener::close() {
        opaque_network_state state;

        auto* loc = get_loc();
        if (loc && loc->is_task_thread) {
            mutex_unify mut(get_data(loc->curr_task).get_self_unify());
            std::unique_lock guard(mut);
            if (!enter_close(loc->curr_task, state)) {
                guard.release();
                swapCtxUnlock(mut);
            }
        } else {
            std::mutex mtx;
            std::condition_variable cv;
            bool done = false;
            auto t = task::create([&] {
                std::lock_guard lock(mtx);
                done = true;
                cv.notify_one();
            });
            if (!enter_close(t, state)) {
                scheduler::ensure_global_worker();
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
    }

    bool tcp_listener::is_open() const noexcept {
        return handle && handle->get_socket() != INVALID_SOCKET;
    }

    address tcp_listener::local_address() const noexcept {
        if (!handle || handle->get_socket() == INVALID_SOCKET)
            return address();
        sockaddr_storage addr{};
        socklen_t addr_len = sizeof(addr);
        if (getsockname(handle->get_socket(), (sockaddr*)&addr, &addr_len) == SOCKET_ERROR)
            return address();
        return to_address(&addr);
    }

    address tcp_listener::remote_address() const noexcept {
        return address();
    }

    bool tcp_listener::enter_close([[maybe_unused]] const task& t, [[maybe_unused]] opaque_network_state& state) {
        if (!handle || handle->get_socket() == INVALID_SOCKET)
            return true;
        handle->close_socket();
        return true;
    }

    bool tcp_listener::enter_accept(const task& t, opaque_network_state& state, std::optional<tcp_socket>& res) {
        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            res = std::nullopt;
            return true;
        }
        SOCKET accept_sock = ::WSASocketW(AF_INET6, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
        if (accept_sock == INVALID_SOCKET) {
            res = std::nullopt;
            return true;
        }
        auto& ns = *state.use<accept_state>(handle.get(), handle->get_socket());
        ns.awaiting_task = t;
        ns.accept_socket = accept_sock;
        ns.out_socket = &res;
        ns.on_complete = [](void* base) {
            auto s = static_cast<accept_state*>(base);
            if (s->error == 0 && s->out_socket) {
                ::setsockopt(s->accept_socket, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char*)&s->listen_socket, sizeof(s->listen_socket));
                tcp_socket new_sock;
                new_sock.handle = std::make_unique<tcp_socket::manager>(s->accept_socket, tcp_socket::manager::connection_method::accept);
                *s->out_socket = std::move(new_sock);
                s->accept_socket = INVALID_SOCKET;
            } else {
                if (s->accept_socket != INVALID_SOCKET) {
                    closesocket(s->accept_socket);
                    s->accept_socket = INVALID_SOCKET;
                }
                if (s->out_socket)
                    *s->out_socket = std::nullopt;
            }
        };

        DWORD bytes_received = 0;
        if (!_AcceptEx(handle->get_socket(), accept_sock, ns.addr_buf, 0, accept_addr_buf_len, accept_addr_buf_len, &bytes_received, &ns.overlapped)) {
            int err = ::WSAGetLastError();
            if (err != ERROR_IO_PENDING) {
                closesocket(accept_sock);
                ns.accept_socket = INVALID_SOCKET;
                res = std::nullopt;
                ns.error = err;
                return true;
            }
            return false;
        }
        ns.error = 0;
        ns.on_complete(static_cast<void*>(&ns));
        return true;
    }

    #pragma endregion

    class udp_handle : public util::native_worker_manager {
        SOCKET sock = INVALID_SOCKET;

    public:
        udp_handle(SOCKET s) : sock(s) {
            if (s != INVALID_SOCKET)
                util::native_workers_singleton::register_handle(reinterpret_cast<HANDLE>(s), this);
        }

        ~udp_handle() override {
            close_socket();
        }

        udp_handle(const udp_handle&) = delete;
        udp_handle& operator=(const udp_handle&) = delete;

        SOCKET get_socket() const noexcept {
            return sock;
        }

        void handle(void* /*data*/, util::native_worker_handle* overlap, unsigned long dwBytesTransferred) override {
            auto state = static_cast<native_state*>(overlap);
            DWORD dwFlags = 0, cbTransfer = 0;
            if (!::WSAGetOverlappedResult(sock, &state->overlapped, &cbTransfer, FALSE, &dwFlags))
                state->error = ::WSAGetLastError();
            else
                state->error = 0;
            if (state->out_processed_bytes) {
                if (state->error)
                    *state->out_processed_bytes = -1;
                else
                    *state->out_processed_bytes = (int32_t)dwBytesTransferred;
            }
            if (state->on_complete)
                state->on_complete(static_cast<void*>(state));
            if (state->awaiting_task) {
                fast_task::lock_guard guard(get_data(state->awaiting_task));
                transfer_task(std::move(state->awaiting_task));
            }
        }

        bool set_configuration(const udp_configuration& config) {
            int cfg = !config.allow_ip4;
            if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&cfg, sizeof(cfg)) == SOCKET_ERROR)
                return false;

            cfg = config.reuse_address ? 1 : 0;
            if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&cfg, sizeof(cfg)) == SOCKET_ERROR)
                return false;

            cfg = config.enable_broadcast ? 1 : 0;
            if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (char*)&cfg, sizeof(cfg)) == SOCKET_ERROR)
                return false;

            cfg = (int)config.recv_timeout_ms;
            if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&cfg, sizeof(cfg)) == SOCKET_ERROR)
                return false;

            cfg = (int)config.send_timeout_ms;
            if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&cfg, sizeof(cfg)) == SOCKET_ERROR)
                return false;

            if (config.recv_buffer_size > 0) {
                cfg = (int)config.recv_buffer_size;
                if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char*)&cfg, sizeof(cfg)) == SOCKET_ERROR)
                    return false;
            }

            if (config.send_buffer_size > 0) {
                cfg = (int)config.send_buffer_size;
                if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char*)&cfg, sizeof(cfg)) == SOCKET_ERROR)
                    return false;
            }

            if (config.dont_fragment) {
                cfg = 1;
                if (setsockopt(sock, IPPROTO_IPV6, IPV6_DONTFRAG, (char*)&cfg, sizeof(cfg)) == SOCKET_ERROR)
                    return false;
                if (config.allow_ip4) {
                    if (setsockopt(sock, IPPROTO_IP, IP_DONTFRAGMENT, (char*)&cfg, sizeof(cfg)) == SOCKET_ERROR)
                        return false;
                }
            }

            cfg = config.multicast_loopback ? 1 : 0;
            if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, (char*)&cfg, sizeof(cfg)) == SOCKET_ERROR)
                return false;

            cfg = config.multicast_ttl;
            if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, (char*)&cfg, sizeof(cfg)) == SOCKET_ERROR)
                return false;

            DWORD argp = 1;
            if (ioctlsocket(sock, FIONBIO, &argp) == SOCKET_ERROR)
                return false;

            return true;
        }

        void close_socket() {
            if (sock != INVALID_SOCKET) {
                closesocket(sock);
                sock = INVALID_SOCKET;
            }
        }

        address local_address() {
            if (sock == INVALID_SOCKET)
                return {};
            universal_address addr{};
            int socklen = sizeof(universal_address);
            if (::getsockname(sock, (sockaddr*)&addr, &socklen) == SOCKET_ERROR)
                return {};
            return to_address(addr);
        }

        address remote_address() {
            if (sock == INVALID_SOCKET)
                return {};
            universal_address addr{};
            int socklen = sizeof(universal_address);
            if (::getpeername(sock, (sockaddr*)&addr, &socklen) == SOCKET_ERROR)
                return {};
            return to_address(addr);
        }
    };

    struct udp_recv_state : public native_state {
        address* out_sender;
        uint32_t* out_bytes;
        int32_t bytes_io = 0;
        DWORD flags = 0;
        WSABUF buf{};
        sockaddr_storage sender_addr{};
        INT sender_len = sizeof(sockaddr_storage);

        udp_recv_state(udp_handle* h, address* sender, uint32_t* bytes, uint8_t* data, uint32_t size)
            : native_state(h), out_sender(sender), out_bytes(bytes) {
            out_processed_bytes = &bytes_io;
            buf.buf = reinterpret_cast<char*>(data);
            buf.len = size;
            on_complete = [](void* base) {
                auto s = static_cast<udp_recv_state*>(base);
                if (s->out_bytes)
                    *s->out_bytes = s->bytes_io >= 0 ? static_cast<uint32_t>(s->bytes_io) : 0;
                if (s->out_sender && s->error == 0)
                    *s->out_sender = to_address((void*)&s->sender_addr);
            };
        }
    };

    struct udp_send_state : public native_state {
        uint32_t* out_bytes;
        int32_t bytes_io = 0;
        WSABUF buf{};
        sockaddr_storage dest_addr{};

        udp_send_state(udp_handle* h, uint32_t* bytes, const uint8_t* data, uint32_t size, const address* to = nullptr)
            : native_state(h), out_bytes(bytes) {
            out_processed_bytes = &bytes_io;
            buf.buf = const_cast<char*>(reinterpret_cast<const char*>(data));
            buf.len = size;
            if (to)
                memcpy(&dest_addr, to->get_data(), address::data_size());
            on_complete = [](void* base) {
                auto s = static_cast<udp_send_state*>(base);
                if (s->out_bytes)
                    *s->out_bytes = s->bytes_io >= 0 ? static_cast<uint32_t>(s->bytes_io) : 0;
            };
        }
    };

    struct udp_recvv_state : public native_state {
        address* out_sender;
        uint32_t* out_bytes;
        int32_t bytes_io = 0;
        DWORD flags = 0;
        WSABUF* bufs = nullptr;
        sockaddr_storage sender_addr{};
        INT sender_len = sizeof(sockaddr_storage);

        udp_recvv_state(udp_handle* h, address* sender, uint32_t* bytes)
            : native_state(h), out_sender(sender), out_bytes(bytes) {
            out_processed_bytes = &bytes_io;
            on_complete = [](void* base) {
                auto s = static_cast<udp_recvv_state*>(base);
                if (s->out_bytes)
                    *s->out_bytes = s->bytes_io >= 0 ? static_cast<uint32_t>(s->bytes_io) : 0;
                if (s->out_sender && s->error == 0)
                    *s->out_sender = to_address((void*)&s->sender_addr);
                delete[] s->bufs;
                s->bufs = nullptr;
            };
        }

        ~udp_recvv_state() {
            delete[] bufs;
            bufs = nullptr;
        }
    };

    struct udp_sendv_state : public native_state {
        uint32_t* out_bytes;
        int32_t bytes_io = 0;
        WSABUF* bufs = nullptr;
        sockaddr_storage dest_addr{};

        udp_sendv_state(udp_handle* h, uint32_t* bytes, const address* to = nullptr)
            : native_state(h), out_bytes(bytes) {
            out_processed_bytes = &bytes_io;
            if (to)
                memcpy(&dest_addr, to->get_data(), address::data_size());
            on_complete = [](void* base) {
                auto s = static_cast<udp_sendv_state*>(base);
                if (s->out_bytes)
                    *s->out_bytes = s->bytes_io >= 0 ? static_cast<uint32_t>(s->bytes_io) : 0;
                delete[] s->bufs;
                s->bufs = nullptr;
            };
        }

        ~udp_sendv_state() {
            delete[] bufs;
            bufs = nullptr;
        }
    };

    udp_socket::udp_socket() = default;
    udp_socket::udp_socket(udp_socket&&) = default;
    udp_socket& udp_socket::operator=(udp_socket&&) = default;
    udp_socket::~udp_socket() = default;

    std::optional<udp_socket> udp_socket::bind(const address& ip_port, const udp_configuration& config) {
        SOCKET sock = WSASocketW(AF_INET6, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, WSA_FLAG_OVERLAPPED);
        if (sock == INVALID_SOCKET)
            return std::nullopt;
        udp_socket s;
        s.handle = std::make_unique<udp_handle>(sock);
        if (!s.handle->set_configuration(config))
            return std::nullopt;
        if (::bind(sock, (const sockaddr*)ip_port.get_data(), (int)ip_port.data_size()) == SOCKET_ERROR)
            return std::nullopt;
        return s;
    }

    uint32_t udp_socket::recv(std::span<uint8_t> data, address& sender) {
        uint32_t bytes_read = 0;
        opaque_network_state state;

        auto* loc = get_loc();
        if (loc && loc->is_task_thread) {
            mutex_unify mut(get_data(loc->curr_task).get_self_unify());
            std::unique_lock guard(mut);
            if (!enter_recv(loc->curr_task, state, bytes_read, data, sender)) {
                guard.release();
                swapCtxUnlock(mut);
            }
        } else {
            std::mutex mtx;
            std::condition_variable cv;
            bool done = false;
            auto t = task::create([&] {
                std::lock_guard lock(mtx);
                done = true;
                cv.notify_one();
            });
            if (!enter_recv(t, state, bytes_read, data, sender)) {
                scheduler::ensure_global_worker();
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
        return bytes_read;
    }

    uint32_t udp_socket::send(std::span<const uint8_t> data, const address& to) {
        uint32_t bytes_sent = 0;
        opaque_network_state state;

        auto* loc = get_loc();
        if (loc && loc->is_task_thread) {
            mutex_unify mut(get_data(loc->curr_task).get_self_unify());
            std::unique_lock guard(mut);
            if (!enter_send(loc->curr_task, state, bytes_sent, data, to)) {
                guard.release();
                swapCtxUnlock(mut);
            }
        } else {
            std::mutex mtx;
            std::condition_variable cv;
            bool done = false;
            auto t = task::create([&] {
                std::lock_guard lock(mtx);
                done = true;
                cv.notify_one();
            });
            if (!enter_send(t, state, bytes_sent, data, to)) {
                scheduler::ensure_global_worker();
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
        return bytes_sent;
    }

    int32_t udp_socket::recvv(std::span<const std::span<uint8_t>> buffers, address& sender) {
        uint32_t bytes_read = 0;
        opaque_network_state state;
        std::span<std::span<uint8_t>> mbufs{const_cast<std::span<uint8_t>*>(buffers.data()), buffers.size()};

        auto* loc = get_loc();
        if (loc && loc->is_task_thread) {
            mutex_unify mut(get_data(loc->curr_task).get_self_unify());
            std::unique_lock guard(mut);
            if (!enter_recvv(loc->curr_task, state, bytes_read, mbufs, sender)) {
                guard.release();
                swapCtxUnlock(mut);
            }
        } else {
            std::mutex mtx;
            std::condition_variable cv;
            bool done = false;
            auto t = task::create([&] {
                std::lock_guard lock(mtx);
                done = true;
                cv.notify_one();
            });
            if (!enter_recvv(t, state, bytes_read, mbufs, sender)) {
                scheduler::ensure_global_worker();
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
        return (int32_t)bytes_read;
    }

    int32_t udp_socket::sendv(std::span<const std::span<const uint8_t>> data, const address& to) {
        uint32_t bytes_sent = 0;
        opaque_network_state state;

        auto* loc = get_loc();
        if (loc && loc->is_task_thread) {
            mutex_unify mut(get_data(loc->curr_task).get_self_unify());
            std::unique_lock guard(mut);
            if (!enter_sendv(loc->curr_task, state, bytes_sent, data, to)) {
                guard.release();
                swapCtxUnlock(mut);
            }
        } else {
            std::mutex mtx;
            std::condition_variable cv;
            bool done = false;
            auto t = task::create([&] {
                std::lock_guard lock(mtx);
                done = true;
                cv.notify_one();
            });
            if (!enter_sendv(t, state, bytes_sent, data, to)) {
                scheduler::ensure_global_worker();
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
        return (int32_t)bytes_sent;
    }

    address udp_socket::local_address() {
        if (!handle)
            return {};
        return handle->local_address();
    }

    bool udp_socket::join_multicast_group(const address& multicast_group) {
        if (!handle)
            return false;
        const auto* addr = reinterpret_cast<const universal_address*>(multicast_group.get_data());
        auto family = multicast_group.get_family();
        if (family == address::family::ipv4) {
            struct ip_mreq mreq{};
            if (addr->ss_family == AF_INET6 && IN6_IS_ADDR_V4MAPPED(&reinterpret_cast<const sockaddr_in6*>(addr)->sin6_addr)) {
                memcpy(&mreq.imr_multiaddr, &reinterpret_cast<const sockaddr_in6*>(addr)->sin6_addr.s6_addr[12], sizeof(mreq.imr_multiaddr));
            } else {
                const auto* sin = reinterpret_cast<const sockaddr_in*>(addr);
                mreq.imr_multiaddr = sin->sin_addr;
            }
            mreq.imr_interface.s_addr = INADDR_ANY;
            return setsockopt(handle->get_socket(), IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*)&mreq, sizeof(mreq)) == 0;
        } else if (family == address::family::ipv6) {
            struct ipv6_mreq mreq{};
            const auto* sin6 = reinterpret_cast<const sockaddr_in6*>(addr);
            mreq.ipv6mr_multiaddr = sin6->sin6_addr;
            mreq.ipv6mr_interface = 0;
            return setsockopt(handle->get_socket(), IPPROTO_IPV6, IPV6_JOIN_GROUP, (char*)&mreq, sizeof(mreq)) == 0;
        }
        return false;
    }

    bool udp_socket::leave_multicast_group(const address& multicast_group) {
        if (!handle)
            return false;
        const auto* addr = reinterpret_cast<const universal_address*>(multicast_group.get_data());
        auto family = multicast_group.get_family();
        if (family == address::family::ipv4) {
            struct ip_mreq mreq{};
            if (addr->ss_family == AF_INET6 && IN6_IS_ADDR_V4MAPPED(&reinterpret_cast<const sockaddr_in6*>(addr)->sin6_addr)) {
                memcpy(&mreq.imr_multiaddr, &reinterpret_cast<const sockaddr_in6*>(addr)->sin6_addr.s6_addr[12], sizeof(mreq.imr_multiaddr));
            } else {
                const auto* sin = reinterpret_cast<const sockaddr_in*>(addr);
                mreq.imr_multiaddr = sin->sin_addr;
            }
            mreq.imr_interface.s_addr = INADDR_ANY;
            return setsockopt(handle->get_socket(), IPPROTO_IP, IP_DROP_MEMBERSHIP, (char*)&mreq, sizeof(mreq)) == 0;
        } else if (family == address::family::ipv6) {
            struct ipv6_mreq mreq{};
            const auto* sin6 = reinterpret_cast<const sockaddr_in6*>(addr);
            mreq.ipv6mr_multiaddr = sin6->sin6_addr;
            mreq.ipv6mr_interface = 0;
            return setsockopt(handle->get_socket(), IPPROTO_IPV6, IPV6_LEAVE_GROUP, (char*)&mreq, sizeof(mreq)) == 0;
        }
        return false;
    }

    void udp_socket::close() {
        opaque_network_state state;
        auto* loc = get_loc();
        if (loc && loc->is_task_thread) {
            mutex_unify mut(get_data(loc->curr_task).get_self_unify());
            std::unique_lock guard(mut);
            if (!enter_close(loc->curr_task, state)) {
                guard.release();
                swapCtxUnlock(mut);
            }
        } else {
            std::mutex mtx;
            std::condition_variable cv;
            bool done = false;
            auto t = task::create([&] { std::lock_guard lock(mtx); done = true; cv.notify_one(); });
            if (!enter_close(t, state)) {
                scheduler::ensure_global_worker();
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
    }

    bool udp_socket::enter_recv(const task& t, opaque_network_state& state, uint32_t& bytes_read, std::span<uint8_t> data, address& sender) {
        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            bytes_read = 0;
            state.use<native_state>(nullptr)->error = WSAENOTSOCK;
            return true;
        }
        auto& ns = *state.use<udp_recv_state>(handle.get(), &sender, &bytes_read, data.data(), static_cast<uint32_t>(data.size()));
        ns.awaiting_task = t;
        if (WSARecvFrom(handle->get_socket(), &ns.buf, 1, nullptr, &ns.flags, reinterpret_cast<sockaddr*>(&ns.sender_addr), &ns.sender_len, &ns.overlapped, nullptr) == SOCKET_ERROR) {
            int err = ::WSAGetLastError();
            if (err != WSA_IO_PENDING) {
                ns.error = err;
                ns.awaiting_task.reset();
                bytes_read = 0;
                return true;
            }
        }
        return false;
    }

    bool udp_socket::enter_send(const task& t, opaque_network_state& state, uint32_t& bytes_sent, std::span<const uint8_t> data, const address& to) {
        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            bytes_sent = 0;
            state.use<native_state>(nullptr)->error = WSAENOTSOCK;
            return true;
        }
        auto& ns = *state.use<udp_send_state>(handle.get(), &bytes_sent, data.data(), static_cast<uint32_t>(data.size()), &to);
        ns.awaiting_task = t;
        if (WSASendTo(handle->get_socket(), &ns.buf, 1, nullptr, 0, reinterpret_cast<sockaddr*>(&ns.dest_addr), (int)address::data_size(), &ns.overlapped, nullptr) == SOCKET_ERROR) {
            int err = ::WSAGetLastError();
            if (err != WSA_IO_PENDING) {
                ns.error = err;
                ns.awaiting_task.reset();
                bytes_sent = 0;
                return true;
            }
        }
        return false;
    }

    bool udp_socket::enter_recvv(const task& t, opaque_network_state& state, uint32_t& bytes_read, std::span<std::span<uint8_t>> buffers, address& sender) {
        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            bytes_read = 0;
            state.use<native_state>(nullptr)->error = WSAENOTSOCK;
            return true;
        }
        auto& ns = *state.use<udp_recvv_state>(handle.get(), &sender, &bytes_read);
        ns.bufs = new WSABUF[buffers.size()];
        DWORD count = 0;
        for (const auto& span : buffers) {
            if (!span.empty()) {
                ns.bufs[count].buf = reinterpret_cast<CHAR*>(span.data());
                ns.bufs[count].len = static_cast<ULONG>(span.size());
                count++;
            }
        }
        ns.awaiting_task = t;
        if (WSARecvFrom(handle->get_socket(), ns.bufs, count, nullptr, &ns.flags, reinterpret_cast<sockaddr*>(&ns.sender_addr), &ns.sender_len, &ns.overlapped, nullptr) == SOCKET_ERROR) {
            int err = ::WSAGetLastError();
            if (err != WSA_IO_PENDING) {
                ns.error = err;
                delete[] ns.bufs;
                ns.bufs = nullptr;
                ns.awaiting_task.reset();
                bytes_read = 0;
                return true;
            }
        }
        return false;
    }

    bool udp_socket::enter_sendv(const task& t, opaque_network_state& state, uint32_t& bytes_sent, std::span<const std::span<const uint8_t>> data, const address& to) {
        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            bytes_sent = 0;
            state.use<native_state>(nullptr)->error = WSAENOTSOCK;
            return true;
        }
        auto& ns = *state.use<udp_sendv_state>(handle.get(), &bytes_sent, &to);
        ns.bufs = new WSABUF[data.size()];
        DWORD count = 0;
        for (const auto& span : data) {
            if (!span.empty()) {
                ns.bufs[count].buf = const_cast<CHAR*>(reinterpret_cast<const CHAR*>(span.data()));
                ns.bufs[count].len = static_cast<ULONG>(span.size());
                count++;
            }
        }
        ns.awaiting_task = t;
        if (WSASendTo(handle->get_socket(), ns.bufs, count, nullptr, 0, reinterpret_cast<sockaddr*>(&ns.dest_addr), (int)address::data_size(), &ns.overlapped, nullptr) == SOCKET_ERROR) {
            int err = ::WSAGetLastError();
            if (err != WSA_IO_PENDING) {
                ns.error = err;
                delete[] ns.bufs;
                ns.bufs = nullptr;
                ns.awaiting_task.reset();
                bytes_sent = 0;
                return true;
            }
        }
        return false;
    }

    bool udp_socket::enter_close([[maybe_unused]] const task& t, [[maybe_unused]] opaque_network_state& state) {
        if (!handle || handle->get_socket() == INVALID_SOCKET)
            return true;
        handle->close_socket();
        return true;
    }

    udp_peer::udp_peer() = default;
    udp_peer::udp_peer(udp_peer&&) = default;
    udp_peer& udp_peer::operator=(udp_peer&&) = default;
    udp_peer::~udp_peer() = default;

    std::optional<udp_peer> udp_peer::connect(const address& ip_port, const udp_configuration& config) {
        SOCKET sock = WSASocketW(AF_INET6, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, WSA_FLAG_OVERLAPPED);
        if (sock == INVALID_SOCKET)
            return std::nullopt;
        udp_peer p;
        p.handle = std::make_unique<udp_handle>(sock);
        if (!p.handle->set_configuration(config))
            return std::nullopt;
        if (::connect(sock, (const sockaddr*)ip_port.get_data(), (int)ip_port.data_size()) == SOCKET_ERROR)
            return std::nullopt;
        return p;
    }

    uint32_t udp_peer::recv(std::span<uint8_t> data) {
        uint32_t bytes_read = 0;
        opaque_network_state state;
        auto* loc = get_loc();
        if (loc && loc->is_task_thread) {
            mutex_unify mut(get_data(loc->curr_task).get_self_unify());
            std::unique_lock guard(mut);
            if (!enter_recv(loc->curr_task, state, bytes_read, data)) {
                guard.release();
                swapCtxUnlock(mut);
            }
        } else {
            std::mutex mtx;
            std::condition_variable cv;
            bool done = false;
            auto t = task::create([&] { std::lock_guard lock(mtx); done = true; cv.notify_one(); });
            if (!enter_recv(t, state, bytes_read, data)) {
                scheduler::ensure_global_worker();
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
        return bytes_read;
    }

    uint32_t udp_peer::send(std::span<const uint8_t> data) {
        uint32_t bytes_sent = 0;
        opaque_network_state state;
        auto* loc = get_loc();
        if (loc && loc->is_task_thread) {
            mutex_unify mut(get_data(loc->curr_task).get_self_unify());
            std::unique_lock guard(mut);
            if (!enter_send(loc->curr_task, state, bytes_sent, data)) {
                guard.release();
                swapCtxUnlock(mut);
            }
        } else {
            std::mutex mtx;
            std::condition_variable cv;
            bool done = false;
            auto t = task::create([&] { std::lock_guard lock(mtx); done = true; cv.notify_one(); });
            if (!enter_send(t, state, bytes_sent, data)) {
                scheduler::ensure_global_worker();
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
        return bytes_sent;
    }

    int32_t udp_peer::recvv(std::span<const std::span<uint8_t>> buffers) {
        uint32_t bytes_read = 0;
        opaque_network_state state;
        std::span<std::span<uint8_t>> mbufs{const_cast<std::span<uint8_t>*>(buffers.data()), buffers.size()};
        auto* loc = get_loc();
        if (loc && loc->is_task_thread) {
            mutex_unify mut(get_data(loc->curr_task).get_self_unify());
            std::unique_lock guard(mut);
            if (!enter_recvv(loc->curr_task, state, bytes_read, mbufs)) {
                guard.release();
                swapCtxUnlock(mut);
            }
        } else {
            std::mutex mtx;
            std::condition_variable cv;
            bool done = false;
            auto t = task::create([&] { std::lock_guard lock(mtx); done = true; cv.notify_one(); });
            if (!enter_recvv(t, state, bytes_read, mbufs)) {
                scheduler::ensure_global_worker();
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
        return (int32_t)bytes_read;
    }

    int32_t udp_peer::sendv(std::span<const std::span<const uint8_t>> data) {
        uint32_t bytes_sent = 0;
        opaque_network_state state;
        auto* loc = get_loc();
        if (loc && loc->is_task_thread) {
            mutex_unify mut(get_data(loc->curr_task).get_self_unify());
            std::unique_lock guard(mut);
            if (!enter_sendv(loc->curr_task, state, bytes_sent, data)) {
                guard.release();
                swapCtxUnlock(mut);
            }
        } else {
            std::mutex mtx;
            std::condition_variable cv;
            bool done = false;
            auto t = task::create([&] { std::lock_guard lock(mtx); done = true; cv.notify_one(); });
            if (!enter_sendv(t, state, bytes_sent, data)) {
                scheduler::ensure_global_worker();
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
        return (int32_t)bytes_sent;
    }

    address udp_peer::local_address() {
        if (!handle)
            return {};
        return handle->local_address();
    }

    address udp_peer::remote_address() {
        if (!handle)
            return {};
        return handle->remote_address();
    }

    void udp_peer::close() {
        opaque_network_state state;
        auto* loc = get_loc();
        if (loc && loc->is_task_thread) {
            mutex_unify mut(get_data(loc->curr_task).get_self_unify());
            std::unique_lock guard(mut);
            if (!enter_close(loc->curr_task, state)) {
                guard.release();
                swapCtxUnlock(mut);
            }
        } else {
            std::mutex mtx;
            std::condition_variable cv;
            bool done = false;
            auto t = task::create([&] { std::lock_guard lock(mtx); done = true; cv.notify_one(); });
            if (!enter_close(t, state)) {
                scheduler::ensure_global_worker();
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
    }

    bool udp_peer::enter_recv(const task& t, opaque_network_state& state, uint32_t& bytes_read, std::span<uint8_t> data) {
        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            bytes_read = 0;
            state.use<native_state>(nullptr)->error = WSAENOTSOCK;
            return true;
        }
        auto& ns = *state.use<udp_recv_state>(handle.get(), nullptr, &bytes_read, data.data(), static_cast<uint32_t>(data.size()));
        ns.awaiting_task = t;
        if (WSARecv(handle->get_socket(), &ns.buf, 1, nullptr, &ns.flags, &ns.overlapped, nullptr) == SOCKET_ERROR) {
            int err = ::WSAGetLastError();
            if (err != WSA_IO_PENDING) {
                ns.error = err;
                ns.awaiting_task.reset();
                bytes_read = 0;
                return true;
            }
        }
        return false;
    }

    bool udp_peer::enter_send(const task& t, opaque_network_state& state, uint32_t& bytes_sent, std::span<const uint8_t> data) {
        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            bytes_sent = 0;
            state.use<native_state>(nullptr)->error = WSAENOTSOCK;
            return true;
        }
        auto& ns = *state.use<udp_send_state>(handle.get(), &bytes_sent, data.data(), static_cast<uint32_t>(data.size()));
        ns.awaiting_task = t;
        if (WSASend(handle->get_socket(), &ns.buf, 1, nullptr, 0, &ns.overlapped, nullptr) == SOCKET_ERROR) {
            int err = ::WSAGetLastError();
            if (err != WSA_IO_PENDING) {
                ns.error = err;
                ns.awaiting_task.reset();
                bytes_sent = 0;
                return true;
            }
        }
        return false;
    }

    bool udp_peer::enter_recvv(const task& t, opaque_network_state& state, uint32_t& bytes_read, std::span<std::span<uint8_t>> buffers) {
        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            bytes_read = 0;
            state.use<native_state>(nullptr)->error = WSAENOTSOCK;
            return true;
        }
        auto& ns = *state.use<udp_recvv_state>(handle.get(), nullptr, &bytes_read);
        ns.bufs = new WSABUF[buffers.size()];
        DWORD count = 0;
        for (const auto& span : buffers) {
            if (!span.empty()) {
                ns.bufs[count].buf = reinterpret_cast<CHAR*>(span.data());
                ns.bufs[count].len = static_cast<ULONG>(span.size());
                count++;
            }
        }
        ns.awaiting_task = t;
        if (WSARecv(handle->get_socket(), ns.bufs, count, nullptr, &ns.flags, &ns.overlapped, nullptr) == SOCKET_ERROR) {
            int err = ::WSAGetLastError();
            if (err != WSA_IO_PENDING) {
                ns.error = err;
                delete[] ns.bufs;
                ns.bufs = nullptr;
                ns.awaiting_task.reset();
                bytes_read = 0;
                return true;
            }
        }
        return false;
    }

    bool udp_peer::enter_sendv(const task& t, opaque_network_state& state, uint32_t& bytes_sent, std::span<const std::span<const uint8_t>> data) {
        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            bytes_sent = 0;
            state.use<native_state>(nullptr)->error = WSAENOTSOCK;
            return true;
        }
        auto& ns = *state.use<udp_sendv_state>(handle.get(), &bytes_sent);
        ns.bufs = new WSABUF[data.size()];
        DWORD count = 0;
        for (const auto& span : data) {
            if (!span.empty()) {
                ns.bufs[count].buf = const_cast<CHAR*>(reinterpret_cast<const CHAR*>(span.data()));
                ns.bufs[count].len = static_cast<ULONG>(span.size());
                count++;
            }
        }
        ns.awaiting_task = t;
        if (WSASend(handle->get_socket(), ns.bufs, count, nullptr, 0, &ns.overlapped, nullptr) == SOCKET_ERROR) {
            int err = ::WSAGetLastError();
            if (err != WSA_IO_PENDING) {
                ns.error = err;
                delete[] ns.bufs;
                ns.bufs = nullptr;
                ns.awaiting_task.reset();
                bytes_sent = 0;
                return true;
            }
        }
        return false;
    }

    bool udp_peer::enter_close([[maybe_unused]] const task& t, [[maybe_unused]] opaque_network_state& state) {
        if (!handle || handle->get_socket() == INVALID_SOCKET)
            return true;
        handle->close_socket();
        return true;
    }

    uint8_t init_networking() {
        if (!inited.load(std::memory_order_acquire)) {
            std::lock_guard lock(net_init_mutex);
            if (!inited.load(std::memory_order_relaxed)) {
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
                }
                inited.store(true, std::memory_order_release);
            }
        }
        return 0;
    }

    #pragma region DNS

    struct resolve_state : public native_state {
        HANDLE cancel_handle = nullptr;
        address* out_single = nullptr;
        std::vector<address>* out_multi = nullptr;
        ADDRINFOEXW hints{};
        wchar_t* host_w = nullptr;
        wchar_t* service_w = nullptr;
        PADDRINFOEXW results = nullptr;
        wchar_t port_str[8]{};
        bool service_allocated = false;

        resolve_state() : native_state(nullptr) {}

        ~resolve_state() {
            delete[] host_w;
            if (service_allocated)
                delete[] service_w;
        }
    };

    void enter_resolve_callback(DWORD dwError, DWORD, LPWSAOVERLAPPED lpOverlapped) {
        auto rs = reinterpret_cast<resolve_state*>(lpOverlapped);

        if (dwError == NO_ERROR && rs->results) {
            for (auto* ai = rs->results; ai; ai = ai->ai_next) {
                if (rs->hints.ai_family != 0)
                    if (ai->ai_family != rs->hints.ai_family)
                        continue;
                address addr = to_address(ai->ai_addr);
                if (rs->out_single) {
                    *rs->out_single = addr;
                    rs->out_single = nullptr;
                    break;
                } else if (rs->out_multi)
                    rs->out_multi->push_back(addr);
            }
        } else if (dwError != NO_ERROR)
            rs->error = dwError;

        if (rs->results) {
            FreeAddrInfoExW(rs->results);
            rs->results = nullptr;
        }

        auto to_resume = std::move(rs->awaiting_task);
        if (to_resume) {
            fast_task::lock_guard guard(get_data(to_resume));
            transfer_task(std::move(to_resume));
        }
    }

    static bool enter_resolve_impl(
        const task& t,
        opaque_network_state& state,
        address* out_single,
        std::vector<address>* out_multi,
        std::string_view host,
        std::string_view service,
        uint16_t port_override,
        address::family preferred_family
    ) {
        init_networking();
        auto rs = state.use<resolve_state>();
        rs->out_single = out_single;
        rs->out_multi = out_multi;
        rs->hints.ai_family = AF_UNSPEC;
        if (preferred_family == address::family::ipv4)
            rs->hints.ai_family = AF_INET;
        else if (preferred_family == address::family::ipv6)
            rs->hints.ai_family = AF_INET6;
        rs->hints.ai_socktype = SOCK_STREAM;
        rs->awaiting_task = t;

        int host_len = (int)host.size();
        int wchar_host_len = MultiByteToWideChar(CP_UTF8, 0, host.data(), host_len, nullptr, 0);
        rs->host_w = new wchar_t[wchar_host_len + 1];
        int host_zero_pos = MultiByteToWideChar(CP_UTF8, 0, host.data(), host_len, rs->host_w, wchar_host_len);
        rs->host_w[host_zero_pos] = 0;

        if (port_override != 0) {
            int pos = _snwprintf_s(rs->port_str, _countof(rs->port_str), L"%u", (unsigned)port_override);
            rs->service_w = rs->port_str;
            if (pos >= 0 && pos < static_cast<int>(_countof(rs->port_str)))
                rs->service_w[pos] = 0;
        } else if (!service.empty()) {
            int svc_len = (int)service.size();
            rs->service_allocated = true;
            int wchar_svc_len = MultiByteToWideChar(CP_UTF8, 0, service.data(), svc_len, nullptr, 0);
            rs->service_w = new wchar_t[wchar_svc_len + 1];
            int pos = MultiByteToWideChar(CP_UTF8, 0, service.data(), svc_len, rs->service_w, wchar_svc_len);
            rs->service_w[pos] = 0;
        }

        int result = GetAddrInfoExW(
            rs->host_w,
            rs->service_w,
            NS_DNS,
            NULL,
            &rs->hints,
            &rs->results,
            NULL,
            &rs->overlapped,
            enter_resolve_callback,
            &rs->cancel_handle
        );
        if (result == WSA_IO_PENDING)
            return false;
        else {
            rs->awaiting_task = nullptr;
            enter_resolve_callback(result, 0, &rs->overlapped);
            return true;
        }
    }

    bool address::enter_resolve(const task& t, opaque_network_state& state, address& res, std::string_view host, std::string_view service, address::family preferred_family) {
        return enter_resolve_impl(t, state, &res, nullptr, host, service, 0, preferred_family);
    }

    bool address::enter_resolve(const task& t, opaque_network_state& state, address& res, std::string_view host, std::string_view service, uint16_t port, address::family preferred_family) {
        return enter_resolve_impl(t, state, &res, nullptr, host, service, port, preferred_family);
    }

    bool address::enter_resolve_multiple(const task& t, opaque_network_state& state, std::vector<address>& res, std::string_view host, std::string_view service, address::family preferred_family) {
        return enter_resolve_impl(t, state, nullptr, &res, host, service, 0, preferred_family);
    }

    bool address::enter_resolve_multiple(const task& t, opaque_network_state& state, std::vector<address>& res, std::string_view host, std::string_view service, uint16_t port, address::family preferred_family) {
        return enter_resolve_impl(t, state, nullptr, &res, host, service, port, preferred_family);
    }

    address address::resolve(std::string_view host, std::string_view service, address::family preferred_family) {
        address res;
        opaque_network_state state;
        auto* loc = get_loc();
        if (loc && loc->is_task_thread) {
            mutex_unify mut(fast_task::get_data(loc->curr_task).get_self_unify());
            std::unique_lock guard(mut);
            if (!enter_resolve(loc->curr_task, state, res, host, service, preferred_family)) {
                guard.release();
                swapCtxUnlock(mut);
            }
        } else {
            std::mutex mtx;
            std::condition_variable cv;
            bool done = false;
            auto t = task::create([&mtx, &cv, &done] { std::lock_guard lock(mtx); done = true; cv.notify_one(); });
            if (!enter_resolve(t, state, res, host, service, preferred_family)) {
                scheduler::ensure_global_worker();
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
        return res;
    }

    address address::resolve(std::string_view host, std::string_view service, uint16_t port, address::family preferred_family) {
        address res;
        opaque_network_state state;
        auto* loc = get_loc();
        if (loc && loc->is_task_thread) {
            mutex_unify mut(fast_task::get_data(loc->curr_task).get_self_unify());
            std::unique_lock guard(mut);
            if (!enter_resolve(loc->curr_task, state, res, host, service, port, preferred_family)) {
                guard.release();
                swapCtxUnlock(mut);
            }
        } else {
            std::mutex mtx;
            std::condition_variable cv;
            bool done = false;
            auto t = task::create([&mtx, &cv, &done] { std::lock_guard lock(mtx); done = true; cv.notify_one(); });
            if (!enter_resolve(t, state, res, host, service, port, preferred_family)) {
                scheduler::ensure_global_worker();
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
        return res;
    }

    std::vector<address> address::resolve_multiple(std::string_view host, std::string_view service, address::family preferred_family) {
        std::vector<address> res;
        opaque_network_state state;
        auto* loc = get_loc();
        if (loc && loc->is_task_thread) {
            mutex_unify mut(fast_task::get_data(loc->curr_task).get_self_unify());
            std::unique_lock guard(mut);
            if (!enter_resolve_multiple(loc->curr_task, state, res, host, service, preferred_family)) {
                guard.release();
                swapCtxUnlock(mut);
            }
        } else {
            std::mutex mtx;
            std::condition_variable cv;
            bool done = false;
            auto t = task::create([&mtx, &cv, &done] { std::lock_guard lock(mtx); done = true; cv.notify_one(); });
            if (!enter_resolve_multiple(t, state, res, host, service, preferred_family)) {
                scheduler::ensure_global_worker();
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
        return res;
    }

    std::vector<address> address::resolve_multiple(std::string_view host, std::string_view service, uint16_t port, address::family preferred_family) {
        std::vector<address> res;
        opaque_network_state state;
        auto* loc = get_loc();
        if (loc && loc->is_task_thread) {
            mutex_unify mut(fast_task::get_data(loc->curr_task).get_self_unify());
            std::unique_lock guard(mut);
            if (!enter_resolve_multiple(loc->curr_task, state, res, host, service, port, preferred_family)) {
                guard.release();
                swapCtxUnlock(mut);
            }
        } else {
            std::mutex mtx;
            std::condition_variable cv;
            bool done = false;
            auto t = task::create([&mtx, &cv, &done] { std::lock_guard lock(mtx); done = true; cv.notify_one(); });
            if (!enter_resolve_multiple(t, state, res, host, service, port, preferred_family)) {
                scheduler::ensure_global_worker();
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
        return res;
    }

    #pragma endregion DNS

    void deinit_networking() {
        if (inited.load(std::memory_order_acquire)) {
            std::lock_guard lock(net_init_mutex);
            if (inited.load(std::memory_order_relaxed)) {
                WSACleanup();
                inited.store(false, std::memory_order_release);
            }
        }
    }
}
#endif