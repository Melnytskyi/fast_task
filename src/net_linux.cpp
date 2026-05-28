// Copyright Danyil Melnytskyi 2022-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef _WIN64
    #include <unistd.h>
    #define SOCKET int
    #define INVALID_SOCKET (-1)
    #include "net_shared.hpp"

    #include "tasks/_internal.hpp"
    #include "tasks/util/native_workers_singleton.hpp"
    #include <fcntl.h>
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
        if (state.error == 0)
            return tcp_error::none;
        switch (state.error) {
        case ECONNRESET:
            return tcp_error::remote_close;
        case ECONNABORTED:
        case ECANCELED:
        case ENETRESET:
            return tcp_error::local_close;
        case EAGAIN:
            return tcp_error::none;
        default:
            return tcp_error::undefined_error;
        }
    }

    static_assert(sizeof(native_state) <= sizeof(opaque_network_state::data), "opaque_network_state buffer is too small for native_state!");

    class tcp_socket::manager : public util::native_worker_manager {
        int sock = -1;

    public:
        manager(int s) : sock(s) {}

        ~manager() override {
            if (sock != -1) {
                ::close(sock);
                sock = -1;
            }
        }

        manager(const manager&) = delete;
        manager& operator=(const manager&) = delete;
        manager(manager&&) = delete;
        manager& operator=(manager&&) = delete;

        int get_socket() const noexcept {
            return sock;
        }

        void handle(util::native_worker_handle* overlap, int32_t res, uint32_t flags) override {
            auto state = static_cast<native_state*>(overlap);
            state->error = res < 0 ? -res : 0;

            if (state->on_complete)
                state->on_complete(static_cast<void*>(state));
            if (state->awaiting_task) {
                if (state->out_processed_bytes)
                    *state->out_processed_bytes = res > -1 ? res : -1;
                fast_task::lock_guard guard(get_data(state->awaiting_task).no_race);
                transfer_task(std::move(state->awaiting_task));
            }
        }

        bool set_configuration(const tcp_configuration& config) {
            int cfg = !config.allow_ip4;
            if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &cfg, sizeof(cfg)) == -1)
                return false;

            cfg = !config.enable_delay;
            if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &cfg, sizeof(cfg)) == -1)
                return false;

            cfg = config.recv_timeout_ms;
            if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &cfg, sizeof(cfg)) == -1)
                return false;

            cfg = config.send_timeout_ms;
            if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &cfg, sizeof(cfg)) == -1)
                return false;

            cfg = config.enable_keep_alive;
            if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &cfg, sizeof(cfg)) == -1)
                return false;
            if (config.enable_keep_alive) {
                int cfg = config.keep_alive_settings.idle_ms;
                if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &cfg, sizeof(cfg)) == -1)
                    return false;
                cfg = config.keep_alive_settings.interval_ms;
                if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &cfg, sizeof(cfg)) == -1)
                    return false;
                cfg = config.keep_alive_settings.retry_count;
                if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, &cfg, sizeof(cfg)) == -1)
                    return false;
                cfg = config.keep_alive_settings.user_timeout_ms;
                if (setsockopt(sock, IPPROTO_TCP, TCP_USER_TIMEOUT, &cfg, sizeof(cfg)) == -1)
                    return false;
            }
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
        int value = 0;
        int result = ::ioctl(handle->get_socket(), FIONREAD, &value);
        if (result == -1)
            return 0;
        else
            return value;
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
        SOCKET clientSocket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        if (clientSocket == INVALID_SOCKET) {
            res = std::nullopt;
            return true;
        }
        auto mgr = std::make_unique<manager>(clientSocket);
        if (!mgr->set_configuration(config)) {
            res = std::nullopt;
            return true;
        }

        int argp = 1;
        if (ioctl(clientSocket, FIONBIO, &argp) == -1) {
            res = std::nullopt;
            return true;
        }

        auto& n_state = *new (&state) native_state(mgr.get());
        n_state.awaiting_task = t;

        util::native_workers_singleton::post_connect(&n_state, clientSocket, (sockaddr*)ip_port.get_data(), ip_port.data_size());

        tcp_socket new_sock;
        new_sock.handle = std::move(mgr);
        res = std::move(new_sock);
        return false;
    }

    bool tcp_socket::enter_connect(const std::shared_ptr<task>& t, opaque_network_state& state, std::optional<tcp_socket>& res, const address& ip_port, char* data, int32_t& size, const tcp_configuration& config) {
        SOCKET clientSocket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        if (clientSocket == INVALID_SOCKET) {
            res = std::nullopt;
            return true;
        }
        auto mgr = std::make_unique<manager>(clientSocket);
        if (!mgr->set_configuration(config)) {
            res = std::nullopt;
            return true;
        }

        int argp = 1;
        if (ioctl(clientSocket, FIONBIO, &argp) == -1) {
            res = std::nullopt;
            return true;
        }

        auto& n_state = *new (&state) native_state(mgr.get());
        n_state.awaiting_task = t;
        n_state.out_processed_bytes = &size;

        util::native_workers_singleton::post_fast_connect(&n_state, clientSocket, (sockaddr*)ip_port.get_data(), ip_port.data_size(), data, size);

        tcp_socket new_sock;
        new_sock.handle = std::move(mgr);
        res = std::move(new_sock);
        return false;
    }

    bool tcp_socket::enter_recv(const std::shared_ptr<task>& t, opaque_network_state& state, int32_t& bytes_read, std::span<char> data) {
        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            bytes_read = -1;
            return true;
        }

        auto& n_state = *new (&state) native_state(handle.get());
        n_state.awaiting_task = t;
        n_state.out_processed_bytes = &bytes_read;
        util::native_workers_singleton::post_recv(&n_state, handle->get_socket(), data.data(), data.size(), 0);
        return false;
    }

    bool tcp_socket::enter_send(const std::shared_ptr<task>& t, opaque_network_state& state, int32_t& bytes_sent, std::span<const uint8_t> data) {
        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            bytes_sent = -1;
            return true;
        }

        auto& ns = *new (&state) native_state(handle.get());
        ns.awaiting_task = t;
        ns.out_processed_bytes = &bytes_sent;
        util::native_workers_singleton::post_send(&ns, handle->get_socket(), (char*)data.data(), data.size(), 0);
        return false;
    }

    bool tcp_socket::enter_sendv(const std::shared_ptr<task>& t, opaque_network_state& state, int32_t& bytes_sent, std::span<const std::span<const uint8_t>> data) {
        auto& ns = *new (&state) native_state(handle.get());
        ns.awaiting_task = t;
        ns.out_processed_bytes = &bytes_sent;
        util::native_workers_singleton::post_sendv(&ns, handle->get_socket(), data, 0);
        return false;
    }

    struct transmit_file_state : public native_state {
        int file_handle = -1;
        int pipe_rfd = -1;
        int pipe_wfd = -1;
        bool close_file_on_complete = false;

        transmit_file_state(util::native_worker_manager* mgr) : native_state(mgr) {
            on_complete = [](void* base) {
                auto s = static_cast<transmit_file_state*>(base);
                if (s->close_file_on_complete && s->file_handle != -1) {
                    ::close(s->file_handle);
                    s->file_handle = -1;
                }
                if (s->pipe_rfd != -1) {
                    ::close(s->pipe_rfd);
                    s->pipe_rfd = -1;
                }
                if (s->pipe_wfd != -1) {
                    ::close(s->pipe_wfd);
                    s->pipe_wfd = -1;
                }
            };
        }
    };

    bool tcp_socket::enter_send_file(const std::shared_ptr<task>& t, opaque_network_state& state, int32_t& bytes_sent, const char* file_path, size_t file_path_len, uint32_t data_len, uint64_t offset, uint32_t chunks_size) {
        auto& ns = *new (&state) transmit_file_state(handle.get());
        ns.awaiting_task = t;
        ns.out_processed_bytes = &bytes_sent;

        ns.file_handle = ::open(file_path, O_RDONLY | O_CLOEXEC);
        if (ns.file_handle == -1) {
            bytes_sent = -1;
            ns.error = errno;
            return true;
        }
        ns.close_file_on_complete = true;

        int pipe_fds[2];
        if (::pipe2(pipe_fds, O_CLOEXEC) == -1) {
            ::close(ns.file_handle);
            ns.file_handle = -1;
            bytes_sent = -1;
            ns.error = errno;
            return true;
        }
        ns.pipe_rfd = pipe_fds[0];
        ns.pipe_wfd = pipe_fds[1];

        util::native_workers_singleton::post_sendfile(&ns, handle->get_socket(), ns.file_handle, ns.pipe_rfd, ns.pipe_wfd, data_len ? data_len : UINT32_MAX, offset);
        return false;
    }

    bool tcp_socket::enter_send_file(const std::shared_ptr<task>& t, opaque_network_state& state, int32_t& bytes_sent, class fast_task::file::file_handle& file_path, uint32_t data_len, uint64_t offset, uint32_t chunks_size) {
        auto& ns = *new (&state) transmit_file_state(handle.get());
        ns.awaiting_task = t;
        ns.out_processed_bytes = &bytes_sent;

        ns.file_handle = static_cast<int>(file_path.internal_get_handle());
        ns.close_file_on_complete = false;

        int pipe_fds[2];
        if (::pipe2(pipe_fds, O_CLOEXEC) == -1) {
            bytes_sent = -1;
            ns.error = errno;
            return true;
        }
        ns.pipe_rfd = pipe_fds[0];
        ns.pipe_wfd = pipe_fds[1];

        util::native_workers_singleton::post_sendfile(&ns, handle->get_socket(), ns.file_handle, ns.pipe_rfd, ns.pipe_wfd, data_len ? data_len : UINT32_MAX, offset);
        return false;
    }

    struct transmit_filev_state : public transmit_file_state {
        const uint8_t* prefix_data = nullptr;
        uint32_t prefix_len = 0;
        const uint8_t* postfix_data = nullptr;
        uint32_t postfix_len = 0;

        transmit_filev_state(util::native_worker_manager* mgr) : transmit_file_state(mgr) {}
    };

    bool tcp_socket::enter_sendv_file(const std::shared_ptr<task>& t, opaque_network_state& state, int32_t& bytes_sent, const std::span<const uint8_t> prefix, const std::span<const uint8_t> postfix, const char* file_path, size_t file_path_len, uint32_t data_len, uint64_t offset, uint32_t chunks_size) {
        auto& ns = *new (&state) transmit_filev_state(handle.get());
        ns.awaiting_task = t;
        ns.out_processed_bytes = &bytes_sent;
        ns.prefix_data = prefix.data();
        ns.prefix_len = static_cast<uint32_t>(prefix.size());
        ns.postfix_data = postfix.data();
        ns.postfix_len = static_cast<uint32_t>(postfix.size());

        ns.file_handle = ::open(file_path, O_RDONLY | O_CLOEXEC);
        if (ns.file_handle == -1) {
            bytes_sent = -1;
            ns.error = errno;
            return true;
        }
        ns.close_file_on_complete = true;

        int pipe_fds[2];
        if (::pipe2(pipe_fds, O_CLOEXEC) == -1) {
            ::close(ns.file_handle);
            ns.file_handle = -1;
            bytes_sent = -1;
            ns.error = errno;
            return true;
        }
        ns.pipe_rfd = pipe_fds[0];
        ns.pipe_wfd = pipe_fds[1];

        util::native_workers_singleton::post_sendv_file(&ns, handle->get_socket(), ns.file_handle, ns.pipe_rfd, ns.pipe_wfd, data_len ? data_len : UINT32_MAX, offset, ns.prefix_data, ns.prefix_len, ns.postfix_data, ns.postfix_len);
        return false;
    }

    bool tcp_socket::enter_sendv_file(const std::shared_ptr<task>& t, opaque_network_state& state, int32_t& bytes_sent, const std::span<const uint8_t> prefix, const std::span<const uint8_t> postfix, class fast_task::file::file_handle& file_path, uint32_t data_len, uint64_t offset, uint32_t chunks_size) {
        auto& ns = *new (&state) transmit_filev_state(handle.get());
        ns.awaiting_task = t;
        ns.out_processed_bytes = &bytes_sent;
        ns.prefix_data = prefix.data();
        ns.prefix_len = static_cast<uint32_t>(prefix.size());
        ns.postfix_data = postfix.data();
        ns.postfix_len = static_cast<uint32_t>(postfix.size());

        ns.file_handle = static_cast<int>(file_path.internal_get_handle());
        ns.close_file_on_complete = false;

        int pipe_fds[2];
        if (::pipe2(pipe_fds, O_CLOEXEC) == -1) {
            bytes_sent = -1;
            ns.error = errno;
            return true;
        }
        ns.pipe_rfd = pipe_fds[0];
        ns.pipe_wfd = pipe_fds[1];

        util::native_workers_singleton::post_sendv_file(&ns, handle->get_socket(), ns.file_handle, ns.pipe_rfd, ns.pipe_wfd, data_len ? data_len : UINT32_MAX, offset, ns.prefix_data, ns.prefix_len, ns.postfix_data, ns.postfix_len);
        return false;
    }

    bool tcp_socket::enter_shutdown(const std::shared_ptr<task>& t, opaque_network_state& state, shutdown_mode mode) {
        int how = SHUT_RDWR;
        switch (mode) {
        case shutdown_mode::read:
            how = SHUT_RD;
            break;
        case shutdown_mode::write:
            how = SHUT_WR;
            break;
        case shutdown_mode::read_write:
            how = SHUT_RDWR;
            break;
        }

        int res = ::shutdown(handle->get_socket(), how);

        auto& ns = *new (&state) native_state(handle.get());
        ns.awaiting_task = nullptr;

        if (res == -1)
            ns.error = errno;

        return true;
    }

    bool tcp_socket::enter_reset(const std::shared_ptr<task>& t, opaque_network_state& state) {
        linger lingerStruct;
        lingerStruct.l_onoff = 1;
        lingerStruct.l_linger = 0;
        ::setsockopt(handle->get_socket(), SOL_SOCKET, SO_LINGER, &lingerStruct, sizeof(lingerStruct));

        auto& ns = *new (&state) native_state(handle.get());
        ns.awaiting_task = t;
        util::native_workers_singleton::post_close(&ns, handle->get_socket());
        return false;
    }

    bool tcp_socket::enter_close(const std::shared_ptr<task>& t, opaque_network_state& state) {
        auto& ns = *new (&state) native_state(handle.get());
        ns.awaiting_task = t;
        util::native_workers_singleton::post_close(&ns, handle->get_socket());
        return false;
    }

    class udp_handle : public util::native_worker_handle, public util::native_worker_manager {
        task_mutex mt;
        task_condition_variable cv;
        int socket;
        sockaddr_in6 server_address;
        bool is_complete = false;
        struct iovec recv_iov{}, send_iov{};
        struct msghdr recv_msg{}, send_msg{};

    public:
        uint32_t fullifed_bytes;
        uint32_t last_error;

        udp_handle(sockaddr_in6& address, uint32_t _)
            : util::native_worker_handle(this), fullifed_bytes(0), last_error(0) {
            socket = ::socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
            if (socket == -1)
                return;
            if (bind(socket, (sockaddr*)&address, sizeof(sockaddr_in6)) == -1) {
                ::close(socket);
                socket = -1;
                return;
            }
            server_address = address;
        }

        void handle(util::native_worker_handle* _, int32_t res, [[maybe_unused]] uint32_t flags) override {
            this->fullifed_bytes = res > -1 ? res : 0;
            this->last_error = res < 0 ? static_cast<uint32_t>(-res) : 0;

            unique_lock lock(mt);
            is_complete = true;
            cv.notify_all();
        }

        void recv(uint8_t* data, uint32_t size, sockaddr_storage& sender, int& sender_len) {
            if (socket == -1)
                throw std::runtime_error("Socket is not connected");
            mutex_unify u(mt);
            unique_lock lock(u);
            is_complete = false;
            memset(&recv_msg, 0, sizeof(recv_msg));
            recv_iov.iov_base = data;
            recv_iov.iov_len = size;
            recv_msg.msg_name = &sender;
            recv_msg.msg_namelen = sizeof(sender);
            recv_msg.msg_iov = &recv_iov;
            recv_msg.msg_iovlen = 1;
            util::native_workers_singleton::post_recvmsg(this, socket, &recv_msg, 0);
            while (!is_complete)
                cv.wait(lock);
            is_complete = false;
            sender_len = static_cast<int>(recv_msg.msg_namelen);
        }

        void send(uint8_t* data, uint32_t size, sockaddr_storage& to) {
            if (socket == -1)
                throw std::runtime_error("Socket is not connected");
            mutex_unify u(mt);
            unique_lock lock(u);
            is_complete = false;
            memset(&send_msg, 0, sizeof(send_msg));
            send_iov.iov_base = data;
            send_iov.iov_len = size;
            send_msg.msg_name = &to;
            send_msg.msg_namelen = sizeof(to);
            send_msg.msg_iov = &send_iov;
            send_msg.msg_iovlen = 1;
            util::native_workers_singleton::post_sendmsg(this, socket, &send_msg, 0);
            while (!is_complete)
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

    uint8_t init_networking() {
        return 0;
    }

    void deinit_networking() {
    }
}
#endif