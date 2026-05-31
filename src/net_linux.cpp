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
    #include <ares.h>

namespace fast_task::net {
    bool inited = false;

    static_assert(sizeof(universal_address) <= sizeof(address), "address buffer is too small for universal_address!");

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
        if (ip)
            memcpy(data, ip, sizeof(universal_address));
    }

    address::address() {
    }

    address::address(std::string_view ip_port) {
        if (ip_port.empty())
            ip_port = "[::]:0";
        internal_makeIP_port(*((universal_address*)data), ip_port.data());
    }

    address::address(std::string_view ip, uint16_t port) {
        if (ip.empty())
            ip = "[::]";
        internal_makeIP(*((universal_address*)data), ip.data(), port);
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
        else if (addr->ss_family == AF_INET6)
            return family::ipv6;
        else
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

    std::error_code opaque_network_state::get_error_code() const noexcept {
        auto& state = *reinterpret_cast<const native_state*>(this);
        return std::error_code(state.error, std::system_category());
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

        void handle(util::native_worker_handle* overlap, int32_t res, uint32_t) override {
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

        if (get_loc().is_task_thread) {
            mutex_unify mut(get_data(get_loc().curr_task).no_race);
            std::lock_guard guard(mut);
            if (!tcp_socket::enter_connect(get_loc().curr_task, state, res, ip_port, config))
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

    std::optional<tcp_socket> tcp_socket::connect(const address& ip_port, uint8_t* data, int32_t& size, const tcp_configuration& config) {
        std::optional<tcp_socket> res;
        opaque_network_state state;

        if (get_loc().is_task_thread) {
            mutex_unify mut(get_data(get_loc().curr_task).no_race);
            std::lock_guard guard(mut);
            if (!tcp_socket::enter_connect(get_loc().curr_task, state, res, ip_port, data, size, config))
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

    int32_t tcp_socket::recv(std::span<uint8_t> data) {
        opaque_network_state state;
        int32_t bytes_read = 0;

        if (get_loc().is_task_thread) {
            mutex_unify mut(get_data(get_loc().curr_task).no_race);
            std::lock_guard guard(mut);
            if (!tcp_socket::enter_recv(get_loc().curr_task, state, bytes_read, data))
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

    int32_t tcp_socket::recvv(std::span<std::span<uint8_t>> data) {
        opaque_network_state state;
        int32_t bytes_read = 0;

        if (get_loc().is_task_thread) {
            mutex_unify mut(get_data(get_loc().curr_task).no_race);
            std::lock_guard guard(mut);
            if (!tcp_socket::enter_recvv(get_loc().curr_task, state, bytes_read, data))
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

            if (!tcp_socket::enter_recvv(t, state, bytes_read, data)) {
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
        return bytes_read;
    }

    int32_t tcp_socket::send(std::span<const uint8_t> data) {
        opaque_network_state state;
        int32_t res = 0;

        if (get_loc().is_task_thread) {
            mutex_unify mut(get_data(get_loc().curr_task).no_race);
            std::lock_guard guard(mut);
            if (!tcp_socket::enter_send(get_loc().curr_task, state, res, data))
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

        if (get_loc().is_task_thread) {
            mutex_unify mut(get_data(get_loc().curr_task).no_race);
            std::lock_guard guard(mut);
            if (!tcp_socket::enter_sendv(get_loc().curr_task, state, res, data))
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

        if (get_loc().is_task_thread) {
            mutex_unify mut(get_data(get_loc().curr_task).no_race);
            std::lock_guard guard(mut);
            if (!tcp_socket::enter_send_file(get_loc().curr_task, state, res, file_path, file_path_len, data_len, offset, chunks_size))
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

        if (get_loc().is_task_thread) {
            mutex_unify mut(get_data(get_loc().curr_task).no_race);
            std::lock_guard guard(mut);
            if (!tcp_socket::enter_send_file(get_loc().curr_task, state, res, file, data_len, offset, chunks_size))
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

        if (get_loc().is_task_thread) {
            mutex_unify mut(get_data(get_loc().curr_task).no_race);
            std::lock_guard guard(mut);
            if (!tcp_socket::enter_sendv_file(get_loc().curr_task, state, res, prefix, postfix, file_path, file_path_len, data_len, offset, chunks_size))
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

        if (get_loc().is_task_thread) {
            mutex_unify mut(get_data(get_loc().curr_task).no_race);
            std::lock_guard guard(mut);
            if (!tcp_socket::enter_sendv_file(get_loc().curr_task, state, res, prefix, postfix, file, data_len, offset, chunks_size))
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

        if (get_loc().is_task_thread) {
            mutex_unify mut(get_data(get_loc().curr_task).no_race);
            std::lock_guard guard(mut);
            if (!tcp_socket::enter_shutdown(get_loc().curr_task, state, mode))
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

        if (get_loc().is_task_thread) {
            mutex_unify mut(get_data(get_loc().curr_task).no_race);
            std::lock_guard guard(mut);
            if (!tcp_socket::enter_reset(get_loc().curr_task, state))
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

        if (get_loc().is_task_thread) {
            mutex_unify mut(get_data(get_loc().curr_task).no_race);
            std::lock_guard guard(mut);
            if (!tcp_socket::enter_close(get_loc().curr_task, state))
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

    bool tcp_socket::enter_connect(const std::shared_ptr<task>& t, opaque_network_state& state, std::optional<tcp_socket>& res, const address& ip_port, uint8_t* data, int32_t& size, const tcp_configuration& config) {
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

    bool tcp_socket::enter_recv(const std::shared_ptr<task>& t, opaque_network_state& state, int32_t& bytes_read, std::span<uint8_t> data) {
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

    bool tcp_socket::enter_recvv(const std::shared_ptr<task>& t, opaque_network_state& state, int32_t& bytes_read, std::span<std::span<uint8_t>> data) {
        static constexpr size_t max_inline_buffers = (sizeof(opaque_network_state::data) - sizeof(native_state) - sizeof(struct iovec*) - sizeof(bool)) / sizeof(struct iovec);

        struct recvv_state : public native_state {
            struct iovec inline_bufs[max_inline_buffers];
            struct iovec* bufs = nullptr;
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
        };

        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            bytes_read = -1;
            return true;
        }

        auto& n_state = *new (&state) recvv_state(handle.get());

        if (data.size() <= max_inline_buffers)
            n_state.bufs = n_state.inline_bufs;
        else {
            n_state.bufs = new struct iovec[data.size()];
            n_state.uses_heap = true;
        }

        size_t buf_count = 0;
        for (const auto& span : data) {
            if (!span.empty()) {
                n_state.bufs[buf_count].iov_base = (void*)span.data();
                n_state.bufs[buf_count].iov_len = span.size();
                buf_count++;
            }
        }

        n_state.awaiting_task = t;
        n_state.out_processed_bytes = &bytes_read;
        util::native_workers_singleton::post_readv(&n_state, handle->get_socket(), n_state.bufs, buf_count, 0);
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
        static constexpr size_t max_inline_buffers = (sizeof(opaque_network_state::data) - sizeof(native_state) - sizeof(struct iovec*) - sizeof(bool)) / sizeof(struct iovec);

        struct sendv_state : public native_state {
            struct iovec inline_bufs[max_inline_buffers];
            struct iovec* bufs = nullptr;
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

        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            bytes_sent = -1;
            return true;
        }

        auto& n_state = *new (&state) sendv_state(handle.get());

        if (data.size() <= max_inline_buffers)
            n_state.bufs = n_state.inline_bufs;
        else {
            n_state.bufs = new struct iovec[data.size()];
            n_state.uses_heap = true;
        }

        size_t buf_count = 0;
        for (const auto& span : data) {
            if (!span.empty()) {
                n_state.bufs[buf_count].iov_base = (void*)span.data();
                n_state.bufs[buf_count].iov_len = span.size();
                buf_count++;
            }
        }

        n_state.awaiting_task = t;
        n_state.out_processed_bytes = &bytes_sent;
        util::native_workers_singleton::post_writev(&n_state, handle->get_socket(), n_state.bufs, buf_count, 0);
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

    bool tcp_socket::enter_send_file(const std::shared_ptr<task>& t, opaque_network_state& state, int32_t& bytes_sent, const char* file_path, size_t, uint32_t data_len, uint64_t offset, uint32_t) {
        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            bytes_sent = -1;
            return true;
        }
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

    bool tcp_socket::enter_send_file(const std::shared_ptr<task>& t, opaque_network_state& state, int32_t& bytes_sent, class fast_task::file::file_handle& file_path, uint32_t data_len, uint64_t offset, uint32_t) {
        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            bytes_sent = -1;
            return true;
        }
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

    bool tcp_socket::enter_sendv_file(const std::shared_ptr<task>& t, opaque_network_state& state, int32_t& bytes_sent, const std::span<const uint8_t> prefix, const std::span<const uint8_t> postfix, const char* file_path, size_t, uint32_t data_len, uint64_t offset, uint32_t) {
        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            bytes_sent = -1;
            return true;
        }

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

    bool tcp_socket::enter_sendv_file(const std::shared_ptr<task>& t, opaque_network_state& state, int32_t& bytes_sent, const std::span<const uint8_t> prefix, const std::span<const uint8_t> postfix, class fast_task::file::file_handle& file_path, uint32_t data_len, uint64_t offset, uint32_t) {
        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            bytes_sent = -1;
            return true;
        }

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

    bool tcp_socket::enter_shutdown(const std::shared_ptr<task>&, opaque_network_state& state, shutdown_mode mode) {
        if (!handle || handle->get_socket() == INVALID_SOCKET)
            return true;

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
        if (!handle || handle->get_socket() == INVALID_SOCKET)
            return true;

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
        if (!handle || handle->get_socket() == INVALID_SOCKET)
            return true;

        auto& ns = *new (&state) native_state(handle.get());
        ns.awaiting_task = t;
        util::native_workers_singleton::post_close(&ns, handle->get_socket());
        return false;
    }

    class tcp_listener::manager : public util::native_worker_manager {
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

        void handle(util::native_worker_handle* overlap, int32_t res, uint32_t) override {
            auto state = static_cast<native_state*>(overlap);
            state->error = res < 0 ? -res : 0;
            if (state->out_processed_bytes)
                *state->out_processed_bytes = res > -1 ? res : -1;
            if (state->on_complete)
                state->on_complete(static_cast<void*>(state));
            if (state->awaiting_task) {
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

    struct accept_state : public native_state {
        std::optional<tcp_socket>* out_socket = nullptr;
        int32_t new_fd = -1;

        accept_state(util::native_worker_manager* mgr) : native_state(mgr) {
            out_processed_bytes = &new_fd;
        }
    };

    static_assert(sizeof(accept_state) <= sizeof(opaque_network_state::data), "accept_state too large for opaque_network_state");

    tcp_listener::tcp_listener() = default;
    tcp_listener::tcp_listener(tcp_listener&&) = default;
    tcp_listener& tcp_listener::operator=(tcp_listener&&) = default;
    tcp_listener::~tcp_listener() = default;

    std::optional<tcp_listener> tcp_listener::bind(const address& ip_port, const tcp_configuration& config) {
        int sock = ::socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET)
            return std::nullopt;
        auto mgr = std::make_unique<manager>(sock);
        if (!mgr->set_configuration(config))
            return std::nullopt;
        int argp = 1;
        if (ioctl(sock, FIONBIO, &argp) == -1)
            return std::nullopt;
        if (::bind(sock, (sockaddr*)ip_port.get_data(), ip_port.data_size()) == -1)
            return std::nullopt;
        if (::listen(sock, SOMAXCONN) == -1)
            return std::nullopt;

        tcp_listener new_listener;
        new_listener.handle = std::move(mgr);
        return new_listener;
    }

    std::optional<tcp_socket> tcp_listener::accept() {
        std::optional<tcp_socket> res;
        opaque_network_state state;

        if (get_loc().is_task_thread) {
            mutex_unify mut(get_data(get_loc().curr_task).no_race);
            std::lock_guard guard(mut);
            if (!enter_accept(get_loc().curr_task, state, res))
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
            if (!enter_accept(t, state, res)) {
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
        return res;
    }

    void tcp_listener::close() {
        opaque_network_state state;

        if (get_loc().is_task_thread) {
            mutex_unify mut(get_data(get_loc().curr_task).no_race);
            std::lock_guard guard(mut);
            if (!enter_close(get_loc().curr_task, state))
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
            if (!enter_close(t, state)) {
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
        sockaddr_storage addr;
        socklen_t addr_len = sizeof(addr);
        if (getsockname(handle->get_socket(), (sockaddr*)&addr, &addr_len) == -1)
            return address();
        return to_address(&addr);
    }

    address tcp_listener::remote_address() const noexcept {
        return address();
    }

    bool tcp_listener::enter_close(const std::shared_ptr<task>& t, opaque_network_state& state) {
        if (!handle || handle->get_socket() == INVALID_SOCKET)
            return true;
        auto& ns = *new (&state) native_state(handle.get());
        ns.awaiting_task = t;
        util::native_workers_singleton::post_close(&ns, handle->get_socket());
        return false;
    }

    bool tcp_listener::enter_accept(const std::shared_ptr<task>& t, opaque_network_state& state, std::optional<tcp_socket>& res) {
        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            res = std::nullopt;
            return true;
        }
        auto& ns = *new (&state) accept_state(handle.get());
        ns.awaiting_task = t;
        ns.out_socket = &res;
        ns.on_complete = [](void* base) {
            auto s = static_cast<accept_state*>(base);
            if (s->error == 0 && s->new_fd >= 0 && s->out_socket) {
                tcp_socket new_sock;
                new_sock.handle = std::make_unique<tcp_socket::manager>(s->new_fd);
                *s->out_socket = std::move(new_sock);
            } else if (s->out_socket) {
                *s->out_socket = std::nullopt;
            }
        };
        util::native_workers_singleton::post_accept(&ns, handle->get_socket(), nullptr, nullptr, SOCK_CLOEXEC);
        return false;
    }

    class udp_handle : public util::native_worker_manager {
        int sock = -1;
        struct iovec recv_iov{};
        struct msghdr recv_msg{};
        sockaddr_storage recv_sender_addr{};
        struct iovec send_iov{};
        struct msghdr send_msg{};
        sockaddr_storage send_dest_addr{};

    public:
        udp_handle(int s) : sock(s) {}

        ~udp_handle() override {
            if (sock != -1) {
                ::close(sock);
                sock = -1;
            }
        }

        udp_handle(const udp_handle&) = delete;
        udp_handle& operator=(const udp_handle&) = delete;

        int get_socket() const noexcept {
            return sock;
        }

        void handle(util::native_worker_handle* overlap, int32_t res, uint32_t) override {
            auto state = static_cast<native_state*>(overlap);
            state->error = res < 0 ? -res : 0;
            if (state->out_processed_bytes)
                *state->out_processed_bytes = res > -1 ? (int32_t)res : -1;
            if (state->on_complete)
                state->on_complete(static_cast<void*>(state));
            if (state->awaiting_task) {
                fast_task::lock_guard guard(get_data(state->awaiting_task).no_race);
                transfer_task(std::move(state->awaiting_task));
            }
        }

        bool set_configuration(const udp_configuration& config) {
            int cfg = !config.allow_ip4;
            if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &cfg, sizeof(cfg)) == -1)
                return false;

            cfg = config.reuse_address ? 1 : 0;
            if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &cfg, sizeof(cfg)) == -1)
                return false;

            cfg = config.reuse_port ? 1 : 0;
            if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &cfg, sizeof(cfg)) == -1)
                return false;

            cfg = config.enable_broadcast ? 1 : 0;
            if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &cfg, sizeof(cfg)) == -1)
                return false;

            cfg = (int)config.recv_timeout_ms;
            if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &cfg, sizeof(cfg)) == -1)
                return false;

            cfg = (int)config.send_timeout_ms;
            if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &cfg, sizeof(cfg)) == -1)
                return false;

            if (config.recv_buffer_size > 0) {
                cfg = (int)config.recv_buffer_size;
                if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &cfg, sizeof(cfg)) == -1)
                    return false;
            }

            if (config.send_buffer_size > 0) {
                cfg = (int)config.send_buffer_size;
                if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &cfg, sizeof(cfg)) == -1)
                    return false;
            }

            if (config.dont_fragment) {
                cfg = IPV6_PMTUDISC_DO;
                if (setsockopt(sock, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &cfg, sizeof(cfg)) == -1)
                    return false;
                if (config.allow_ip4) {
                    cfg = IP_PMTUDISC_DO;
                    if (setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER, &cfg, sizeof(cfg)) == -1)
                        return false;
                }
            }

            cfg = config.multicast_loopback ? 1 : 0;
            if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &cfg, sizeof(cfg)) == -1)
                return false;

            cfg = config.multicast_ttl;
            if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &cfg, sizeof(cfg)) == -1)
                return false;

            return true;
        }

        void setup_recv(uint8_t* data, uint32_t size) {
            recv_iov.iov_base = data;
            recv_iov.iov_len = size;
            memset(&recv_msg, 0, sizeof(recv_msg));
            memset(&recv_sender_addr, 0, sizeof(recv_sender_addr));
            recv_msg.msg_name = &recv_sender_addr;
            recv_msg.msg_namelen = sizeof(recv_sender_addr);
            recv_msg.msg_iov = &recv_iov;
            recv_msg.msg_iovlen = 1;
        }

        void setup_send(const uint8_t* data, uint32_t size, const address& to) {
            send_iov.iov_base = const_cast<uint8_t*>(data);
            send_iov.iov_len = size;
            memset(&send_msg, 0, sizeof(send_msg));
            memcpy(&send_dest_addr, to.get_data(), sizeof(universal_address));
            send_msg.msg_name = &send_dest_addr;
            send_msg.msg_namelen = sizeof(universal_address);
            send_msg.msg_iov = &send_iov;
            send_msg.msg_iovlen = 1;
        }

        void setup_recvv(struct iovec* iovs, size_t count) {
            memset(&recv_msg, 0, sizeof(recv_msg));
            memset(&recv_sender_addr, 0, sizeof(recv_sender_addr));
            recv_msg.msg_name = &recv_sender_addr;
            recv_msg.msg_namelen = sizeof(recv_sender_addr);
            recv_msg.msg_iov = iovs;
            recv_msg.msg_iovlen = count;
        }

        void setup_sendv(struct iovec* iovs, size_t count, const address& to) {
            memset(&send_msg, 0, sizeof(send_msg));
            memcpy(&send_dest_addr, to.get_data(), sizeof(universal_address));
            send_msg.msg_name = &send_dest_addr;
            send_msg.msg_namelen = sizeof(universal_address);
            send_msg.msg_iov = iovs;
            send_msg.msg_iovlen = count;
        }

        void setup_recv_peer(uint8_t* data, uint32_t size) {
            recv_iov.iov_base = data;
            recv_iov.iov_len = size;
            memset(&recv_msg, 0, sizeof(recv_msg));
            recv_msg.msg_iov = &recv_iov;
            recv_msg.msg_iovlen = 1;
        }

        void setup_send_peer(const uint8_t* data, uint32_t size) {
            send_iov.iov_base = const_cast<uint8_t*>(data);
            send_iov.iov_len = size;
            memset(&send_msg, 0, sizeof(send_msg));
            send_msg.msg_iov = &send_iov;
            send_msg.msg_iovlen = 1;
        }

        void setup_recvv_peer(struct iovec* iovs, size_t count) {
            memset(&recv_msg, 0, sizeof(recv_msg));
            recv_msg.msg_iov = iovs;
            recv_msg.msg_iovlen = count;
        }

        void setup_sendv_peer(struct iovec* iovs, size_t count) {
            memset(&send_msg, 0, sizeof(send_msg));
            send_msg.msg_iov = iovs;
            send_msg.msg_iovlen = count;
        }

        msghdr* get_recv_msg() {
            return &recv_msg;
        }

        msghdr* get_send_msg() {
            return &send_msg;
        }

        address get_recv_sender() {
            return to_address((void*)&recv_sender_addr);
        }

        address local_address() {
            universal_address addr;
            socklen_t socklen = sizeof(universal_address);
            if (getsockname(sock, (sockaddr*)&addr, &socklen) == -1)
                return {};
            return to_address(addr);
        }

        address remote_address() {
            universal_address addr;
            socklen_t socklen = sizeof(universal_address);
            if (getpeername(sock, (sockaddr*)&addr, &socklen) == -1)
                return {};
            return to_address(addr);
        }
    };

    struct udp_recv_state : public native_state {
        udp_handle* hdl;
        address* out_sender;
        uint32_t* out_bytes;
        int32_t bytes_io = 0;

        udp_recv_state(udp_handle* h, address* sender, uint32_t* bytes)
            : native_state(h), hdl(h), out_sender(sender), out_bytes(bytes) {
            out_processed_bytes = &bytes_io;
        }
    };

    static_assert(sizeof(udp_recv_state) <= sizeof(opaque_network_state::data), "udp_recv_state too large for opaque_network_state");

    struct udp_send_state : public native_state {
        uint32_t* out_bytes;
        int32_t bytes_io = 0;

        udp_send_state(udp_handle* h, uint32_t* bytes)
            : native_state(h), out_bytes(bytes) {
            out_processed_bytes = &bytes_io;
        }
    };

    static_assert(sizeof(udp_send_state) <= sizeof(opaque_network_state::data), "udp_send_state too large for opaque_network_state");

    struct udp_recvv_state : public native_state {
        udp_handle* hdl;
        address* out_sender;
        uint32_t* out_bytes;
        int32_t bytes_io = 0;
        struct iovec* bufs = nullptr;

        udp_recvv_state(udp_handle* h, address* sender, uint32_t* bytes)
            : native_state(h), hdl(h), out_sender(sender), out_bytes(bytes) {
            out_processed_bytes = &bytes_io;
            on_complete = [](void* base) {
                auto s = static_cast<udp_recvv_state*>(base);
                if (s->out_bytes)
                    *s->out_bytes = s->bytes_io >= 0 ? static_cast<uint32_t>(s->bytes_io) : 0;
                if (s->out_sender && s->error == 0)
                    *s->out_sender = s->hdl->get_recv_sender();
                delete[] s->bufs;
                s->bufs = nullptr;
            };
        }
    };

    static_assert(sizeof(udp_recvv_state) <= sizeof(opaque_network_state::data), "udp_recvv_state too large for opaque_network_state");

    struct udp_sendv_state : public native_state {
        uint32_t* out_bytes;
        int32_t bytes_io = 0;
        struct iovec* bufs = nullptr;

        udp_sendv_state(udp_handle* h, uint32_t* bytes)
            : native_state(h), out_bytes(bytes) {
            out_processed_bytes = &bytes_io;
            on_complete = [](void* base) {
                auto s = static_cast<udp_sendv_state*>(base);
                if (s->out_bytes)
                    *s->out_bytes = s->bytes_io >= 0 ? static_cast<uint32_t>(s->bytes_io) : 0;
                delete[] s->bufs;
                s->bufs = nullptr;
            };
        }
    };

    static_assert(sizeof(udp_sendv_state) <= sizeof(opaque_network_state::data), "udp_sendv_state too large for opaque_network_state");

    udp_socket::udp_socket() = default;
    udp_socket::udp_socket(udp_socket&&) = default;
    udp_socket& udp_socket::operator=(udp_socket&&) = default;
    udp_socket::~udp_socket() = default;

    std::optional<udp_socket> udp_socket::bind(const address& ip_port, const udp_configuration& config) {
        int sock = ::socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        if (sock == -1)
            return std::nullopt;
        udp_socket s;
        s.handle = std::make_unique<udp_handle>(sock);
        if (!s.handle->set_configuration(config))
            return std::nullopt;
        if (::bind(sock, (const sockaddr*)ip_port.get_data(), (socklen_t)ip_port.data_size()) == -1)
            return std::nullopt;
        return s;
    }

    uint32_t udp_socket::recv(std::span<uint8_t> data, address& sender) {
        uint32_t bytes_read = 0;
        opaque_network_state state;

        if (get_loc().is_task_thread) {
            mutex_unify mut(get_data(get_loc().curr_task).no_race);
            std::lock_guard guard(mut);
            if (!enter_recv(get_loc().curr_task, state, bytes_read, data, sender))
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
            if (!enter_recv(t, state, bytes_read, data, sender)) {
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
        return bytes_read;
    }

    uint32_t udp_socket::send(std::span<const uint8_t> data, const address& to) {
        uint32_t bytes_sent = 0;
        opaque_network_state state;

        if (get_loc().is_task_thread) {
            mutex_unify mut(get_data(get_loc().curr_task).no_race);
            std::lock_guard guard(mut);
            if (!enter_send(get_loc().curr_task, state, bytes_sent, data, to))
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
            if (!enter_send(t, state, bytes_sent, data, to)) {
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

        if (get_loc().is_task_thread) {
            mutex_unify mut(get_data(get_loc().curr_task).no_race);
            std::lock_guard guard(mut);
            if (!enter_recvv(get_loc().curr_task, state, bytes_read, mbufs, sender))
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
            if (!enter_recvv(t, state, bytes_read, mbufs, sender)) {
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
        return (int32_t)bytes_read;
    }

    int32_t udp_socket::sendv(std::span<const std::span<const uint8_t>> data, const address& to) {
        uint32_t bytes_sent = 0;
        opaque_network_state state;

        if (get_loc().is_task_thread) {
            mutex_unify mut(get_data(get_loc().curr_task).no_race);
            std::lock_guard guard(mut);
            if (!enter_sendv(get_loc().curr_task, state, bytes_sent, data, to))
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
            if (!enter_sendv(t, state, bytes_sent, data, to)) {
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
        auto family = multicast_group.get_family();
        if (family == address::family::ipv4) {
            struct ip_mreq mreq{};
            const auto* sin = (const sockaddr_in*)multicast_group.get_data();
            mreq.imr_multiaddr = sin->sin_addr;
            mreq.imr_interface.s_addr = INADDR_ANY;
            return setsockopt(handle->get_socket(), IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) == 0;
        } else if (family == address::family::ipv6) {
            struct ipv6_mreq mreq{};
            const auto* sin6 = (const sockaddr_in6*)multicast_group.get_data();
            mreq.ipv6mr_multiaddr = sin6->sin6_addr;
            mreq.ipv6mr_interface = 0;
            return setsockopt(handle->get_socket(), IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) == 0;
        }
        return false;
    }

    bool udp_socket::leave_multicast_group(const address& multicast_group) {
        if (!handle)
            return false;
        auto family = multicast_group.get_family();
        if (family == address::family::ipv4) {
            struct ip_mreq mreq{};
            const auto* sin = (const sockaddr_in*)multicast_group.get_data();
            mreq.imr_multiaddr = sin->sin_addr;
            mreq.imr_interface.s_addr = INADDR_ANY;
            return setsockopt(handle->get_socket(), IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq)) == 0;
        } else if (family == address::family::ipv6) {
            struct ipv6_mreq mreq{};
            const auto* sin6 = (const sockaddr_in6*)multicast_group.get_data();
            mreq.ipv6mr_multiaddr = sin6->sin6_addr;
            mreq.ipv6mr_interface = 0;
            return setsockopt(handle->get_socket(), IPPROTO_IPV6, IPV6_LEAVE_GROUP, &mreq, sizeof(mreq)) == 0;
        }
        return false;
    }

    void udp_socket::close() {
        opaque_network_state state;
        if (get_loc().is_task_thread) {
            mutex_unify mut(get_data(get_loc().curr_task).no_race);
            std::lock_guard guard(mut);
            if (!enter_close(get_loc().curr_task, state))
                swapCtxRelock(mut);
        } else {
            std::mutex mtx;
            std::condition_variable cv;
            bool done = false;
            auto t = task::create([&] { std::lock_guard lock(mtx); done = true; cv.notify_one(); });
            if (!enter_close(t, state)) {
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
    }

    bool udp_socket::enter_recv(const std::shared_ptr<task>& t, opaque_network_state& state, uint32_t& bytes_read, std::span<uint8_t> data, address& sender) {
        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            bytes_read = 0;
            return true;
        }
        handle->setup_recv(data.data(), static_cast<uint32_t>(data.size()));
        auto& ns = *new (&state) udp_recv_state(handle.get(), &sender, &bytes_read);
        ns.awaiting_task = t;
        ns.on_complete = [](void* base) {
            auto s = static_cast<udp_recv_state*>(base);
            if (s->out_bytes)
                *s->out_bytes = s->bytes_io >= 0 ? static_cast<uint32_t>(s->bytes_io) : 0;
            if (s->out_sender && s->error == 0)
                *s->out_sender = s->hdl->get_recv_sender();
        };
        util::native_workers_singleton::post_recvmsg(&ns, handle->get_socket(), handle->get_recv_msg(), 0);
        return false;
    }

    bool udp_socket::enter_send(const std::shared_ptr<task>& t, opaque_network_state& state, uint32_t& bytes_sent, std::span<const uint8_t> data, const address& to) {
        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            bytes_sent = 0;
            return true;
        }
        handle->setup_send(data.data(), static_cast<uint32_t>(data.size()), to);
        auto& ns = *new (&state) udp_send_state(handle.get(), &bytes_sent);
        ns.awaiting_task = t;
        ns.on_complete = [](void* base) {
            auto s = static_cast<udp_send_state*>(base);
            if (s->out_bytes)
                *s->out_bytes = s->bytes_io >= 0 ? static_cast<uint32_t>(s->bytes_io) : 0;
        };
        util::native_workers_singleton::post_sendmsg(&ns, handle->get_socket(), handle->get_send_msg(), 0);
        return false;
    }

    bool udp_socket::enter_recvv(const std::shared_ptr<task>& t, opaque_network_state& state, uint32_t& bytes_read, std::span<std::span<uint8_t>> buffers, address& sender) {
        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            bytes_read = 0;
            return true;
        }
        auto& ns = *new (&state) udp_recvv_state(handle.get(), &sender, &bytes_read);
        ns.bufs = new struct iovec[buffers.size()];
        size_t count = 0;
        for (const auto& span : buffers) {
            if (!span.empty()) {
                ns.bufs[count].iov_base = span.data();
                ns.bufs[count].iov_len = span.size();
                count++;
            }
        }
        handle->setup_recvv(ns.bufs, count);
        ns.awaiting_task = t;
        util::native_workers_singleton::post_recvmsg(&ns, handle->get_socket(), handle->get_recv_msg(), 0);
        return false;
    }

    bool udp_socket::enter_sendv(const std::shared_ptr<task>& t, opaque_network_state& state, uint32_t& bytes_sent, std::span<const std::span<const uint8_t>> data, const address& to) {
        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            bytes_sent = 0;
            return true;
        }
        auto& ns = *new (&state) udp_sendv_state(handle.get(), &bytes_sent);
        ns.bufs = new struct iovec[data.size()];
        size_t count = 0;
        for (const auto& span : data) {
            if (!span.empty()) {
                ns.bufs[count].iov_base = const_cast<uint8_t*>(span.data());
                ns.bufs[count].iov_len = span.size();
                count++;
            }
        }
        handle->setup_sendv(ns.bufs, count, to);
        ns.awaiting_task = t;
        util::native_workers_singleton::post_sendmsg(&ns, handle->get_socket(), handle->get_send_msg(), 0);
        return false;
    }

    bool udp_socket::enter_close(const std::shared_ptr<task>& t, opaque_network_state& state) {
        if (!handle || handle->get_socket() == INVALID_SOCKET)
            return true;
        auto& ns = *new (&state) native_state(handle.get());
        ns.awaiting_task = t;
        util::native_workers_singleton::post_close(&ns, handle->get_socket());
        return false;
    }

    udp_peer::udp_peer() = default;
    udp_peer::udp_peer(udp_peer&&) = default;
    udp_peer& udp_peer::operator=(udp_peer&&) = default;
    udp_peer::~udp_peer() = default;

    std::optional<udp_peer> udp_peer::connect(const address& ip_port, const udp_configuration& config) {
        int sock = ::socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        if (sock == -1)
            return std::nullopt;
        udp_peer p;
        p.handle = std::make_unique<udp_handle>(sock);
        if (!p.handle->set_configuration(config))
            return std::nullopt;
        if (::connect(sock, (const sockaddr*)ip_port.get_data(), (socklen_t)ip_port.data_size()) == -1)
            return std::nullopt;
        return p;
    }

    uint32_t udp_peer::recv(std::span<uint8_t> data) {
        uint32_t bytes_read = 0;
        opaque_network_state state;
        if (get_loc().is_task_thread) {
            mutex_unify mut(get_data(get_loc().curr_task).no_race);
            std::lock_guard guard(mut);
            if (!enter_recv(get_loc().curr_task, state, bytes_read, data))
                swapCtxRelock(mut);
        } else {
            std::mutex mtx;
            std::condition_variable cv;
            bool done = false;
            auto t = task::create([&] { std::lock_guard lock(mtx); done = true; cv.notify_one(); });
            if (!enter_recv(t, state, bytes_read, data)) {
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
        return bytes_read;
    }

    uint32_t udp_peer::send(std::span<const uint8_t> data) {
        uint32_t bytes_sent = 0;
        opaque_network_state state;
        if (get_loc().is_task_thread) {
            mutex_unify mut(get_data(get_loc().curr_task).no_race);
            std::lock_guard guard(mut);
            if (!enter_send(get_loc().curr_task, state, bytes_sent, data))
                swapCtxRelock(mut);
        } else {
            std::mutex mtx;
            std::condition_variable cv;
            bool done = false;
            auto t = task::create([&] { std::lock_guard lock(mtx); done = true; cv.notify_one(); });
            if (!enter_send(t, state, bytes_sent, data)) {
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
        if (get_loc().is_task_thread) {
            mutex_unify mut(get_data(get_loc().curr_task).no_race);
            std::lock_guard guard(mut);
            if (!enter_recvv(get_loc().curr_task, state, bytes_read, mbufs))
                swapCtxRelock(mut);
        } else {
            std::mutex mtx;
            std::condition_variable cv;
            bool done = false;
            auto t = task::create([&] { std::lock_guard lock(mtx); done = true; cv.notify_one(); });
            if (!enter_recvv(t, state, bytes_read, mbufs)) {
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
        return (int32_t)bytes_read;
    }

    int32_t udp_peer::sendv(std::span<const std::span<const uint8_t>> data) {
        uint32_t bytes_sent = 0;
        opaque_network_state state;
        if (get_loc().is_task_thread) {
            mutex_unify mut(get_data(get_loc().curr_task).no_race);
            std::lock_guard guard(mut);
            if (!enter_sendv(get_loc().curr_task, state, bytes_sent, data))
                swapCtxRelock(mut);
        } else {
            std::mutex mtx;
            std::condition_variable cv;
            bool done = false;
            auto t = task::create([&] { std::lock_guard lock(mtx); done = true; cv.notify_one(); });
            if (!enter_sendv(t, state, bytes_sent, data)) {
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
        if (get_loc().is_task_thread) {
            mutex_unify mut(get_data(get_loc().curr_task).no_race);
            std::lock_guard guard(mut);
            if (!enter_close(get_loc().curr_task, state))
                swapCtxRelock(mut);
        } else {
            std::mutex mtx;
            std::condition_variable cv;
            bool done = false;
            auto t = task::create([&] { std::lock_guard lock(mtx); done = true; cv.notify_one(); });
            if (!enter_close(t, state)) {
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
    }

    bool udp_peer::enter_recv(const std::shared_ptr<task>& t, opaque_network_state& state, uint32_t& bytes_read, std::span<uint8_t> data) {
        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            bytes_read = 0;
            return true;
        }
        handle->setup_recv_peer(data.data(), static_cast<uint32_t>(data.size()));
        auto& ns = *new (&state) udp_send_state(handle.get(), &bytes_read);
        ns.awaiting_task = t;
        ns.on_complete = [](void* base) {
            auto s = static_cast<udp_send_state*>(base);
            if (s->out_bytes)
                *s->out_bytes = s->bytes_io >= 0 ? static_cast<uint32_t>(s->bytes_io) : 0;
        };
        util::native_workers_singleton::post_recvmsg(&ns, handle->get_socket(), handle->get_recv_msg(), 0);
        return false;
    }

    bool udp_peer::enter_send(const std::shared_ptr<task>& t, opaque_network_state& state, uint32_t& bytes_sent, std::span<const uint8_t> data) {
        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            bytes_sent = 0;
            return true;
        }
        handle->setup_send_peer(data.data(), static_cast<uint32_t>(data.size()));
        auto& ns = *new (&state) udp_send_state(handle.get(), &bytes_sent);
        ns.awaiting_task = t;
        ns.on_complete = [](void* base) {
            auto s = static_cast<udp_send_state*>(base);
            if (s->out_bytes)
                *s->out_bytes = s->bytes_io >= 0 ? static_cast<uint32_t>(s->bytes_io) : 0;
        };
        util::native_workers_singleton::post_sendmsg(&ns, handle->get_socket(), handle->get_send_msg(), 0);
        return false;
    }

    bool udp_peer::enter_recvv(const std::shared_ptr<task>& t, opaque_network_state& state, uint32_t& bytes_read, std::span<std::span<uint8_t>> buffers) {
        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            bytes_read = 0;
            return true;
        }
        auto& ns = *new (&state) udp_sendv_state(handle.get(), &bytes_read);
        ns.bufs = new struct iovec[buffers.size()];
        size_t count = 0;
        for (const auto& span : buffers) {
            if (!span.empty()) {
                ns.bufs[count].iov_base = span.data();
                ns.bufs[count].iov_len = span.size();
                count++;
            }
        }
        handle->setup_recvv_peer(ns.bufs, count);
        ns.awaiting_task = t;
        util::native_workers_singleton::post_recvmsg(&ns, handle->get_socket(), handle->get_recv_msg(), 0);
        return false;
    }

    bool udp_peer::enter_sendv(const std::shared_ptr<task>& t, opaque_network_state& state, uint32_t& bytes_sent, std::span<const std::span<const uint8_t>> data) {
        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            bytes_sent = 0;
            return true;
        }
        auto& ns = *new (&state) udp_sendv_state(handle.get(), &bytes_sent);
        ns.bufs = new struct iovec[data.size()];
        size_t count = 0;
        for (const auto& span : data) {
            if (!span.empty()) {
                ns.bufs[count].iov_base = const_cast<uint8_t*>(span.data());
                ns.bufs[count].iov_len = span.size();
                count++;
            }
        }
        handle->setup_sendv_peer(ns.bufs, count);
        ns.awaiting_task = t;
        util::native_workers_singleton::post_sendmsg(&ns, handle->get_socket(), handle->get_send_msg(), 0);
        return false;
    }

    bool udp_peer::enter_close(const std::shared_ptr<task>& t, opaque_network_state& state) {
        if (!handle || handle->get_socket() == INVALID_SOCKET)
            return true;
        auto& ns = *new (&state) native_state(handle.get());
        ns.awaiting_task = t;
        util::native_workers_singleton::post_close(&ns, handle->get_socket());
        return false;
    }

    #pragma region DNS

    struct resolve_state : public native_state, public util::native_worker_manager {
        ares_channel channel = nullptr;
        address* out_single = nullptr;
        std::vector<address>* out_multi = nullptr;
        char port_buf[16]{};

        std::atomic<int> pending_polls{0};
        std::atomic_flag processing{};
        address::family preferred_family = address::family::none;
        bool done = false;

        struct sock_poll_handle : public util::native_worker_handle {
            resolve_state* state;
            ares_socket_t fd;
            int events;
            bool is_active;
            sock_poll_handle* next;

            sock_poll_handle(resolve_state* s, ares_socket_t f)
                : util::native_worker_handle(s), state(s), fd(f), events(0), is_active(false), next(nullptr) {}
        };

        sock_poll_handle* active_polls = nullptr;

        resolve_state() : native_state(this) {
        }

        ~resolve_state() {
            while (active_polls) {
                auto* next = active_polls->next;
                delete active_polls;
                active_polls = next;
            }
        }

        void add_poll(sock_poll_handle* ph) {
            ph->is_active = true;
            pending_polls.fetch_add(1, std::memory_order_relaxed);
            util::native_workers_singleton::post_poll_add(ph, ph->fd, ph->events);
        }

        void handle(util::native_worker_handle* h, int32_t res, uint32_t) override {
            auto* ph = static_cast<sock_poll_handle*>(h);
            ares_socket_t fd = ph->fd;

            while (processing.test_and_set(std::memory_order_acquire))
                ;

            ph->is_active = false;

            if (!done && channel && ph->events != 0) {
                ares_socket_t rfd = ARES_SOCKET_BAD, wfd = ARES_SOCKET_BAD;
                if (res > 0) {
                    if (ph->events & POLLIN)
                        rfd = fd;
                    if (ph->events & POLLOUT)
                        wfd = fd;
                } else {
                    rfd = wfd = fd;
                }
                ares_process_fd(channel, rfd, wfd);
            }

            int rem = pending_polls.fetch_sub(1, std::memory_order_acq_rel) - 1;

            if (done) {
                if (channel) {
                    ares_destroy(channel);
                    channel = nullptr;
                }

                std::shared_ptr<task> to_resume;
                if (rem == 0) {
                    to_resume = std::move(awaiting_task);
                }
                processing.clear(std::memory_order_release);

                if (to_resume) {
                    fast_task::lock_guard guard(get_data(to_resume).no_race);
                    transfer_task(std::move(to_resume));
                }

                if (rem == 0) {
                    this->~resolve_state();
                }
                return;
            } else {
                if (ph->events != 0) {
                    add_poll(ph);
                }
            }

            processing.clear(std::memory_order_release);
        }
    };

    static_assert(sizeof(resolve_state) <= sizeof(opaque_network_state::data), "opaque_network_state::data too small for resolve_state");

    static void ares_sock_state_cb(void* data, ares_socket_t socket_fd, int readable, int writable) {
        auto* rs = static_cast<resolve_state*>(data);

        int events = 0;
        if (readable)
            events |= POLLIN;
        if (writable)
            events |= POLLOUT;

        resolve_state::sock_poll_handle* handle = nullptr;
        for (auto* ph = rs->active_polls; ph; ph = ph->next) {
            if (ph->fd == socket_fd) {
                handle = ph;
                break;
            }
        }

        if (events == 0) {
            if (handle) {
                handle->events = 0;
            }
        } else {
            if (!handle) {
                handle = new resolve_state::sock_poll_handle(rs, socket_fd);
                handle->next = rs->active_polls;
                rs->active_polls = handle;
            }
            handle->events = events;
            if (!handle->is_active) {
                rs->add_poll(handle);
            }
        }
    }

    static void ares_addrinfo_cb(void* arg, int status, int /*timeouts*/, struct ares_addrinfo* result) {
        auto* rs = static_cast<resolve_state*>(arg);

        if (status == ARES_SUCCESS && result) {
            for (auto* node = result->nodes; node; node = node->ai_next) {
                if (rs->preferred_family != address::family::none) {
                    address::family nf = address::family::none;
                    if (node->ai_family == AF_INET)
                        nf = address::family::ipv4;
                    else if (node->ai_family == AF_INET6)
                        nf = address::family::ipv6;
                    if (nf != rs->preferred_family)
                        continue;
                }
                address addr = to_address(node->ai_addr);
                if (rs->out_single) {
                    *rs->out_single = addr;
                    rs->out_single = nullptr;
                    break;
                } else if (rs->out_multi) {
                    rs->out_multi->push_back(addr);
                }
            }
            ares_freeaddrinfo(result);
        } else if (status != ARES_SUCCESS) {
            rs->error = status;
        }

        rs->done = true;
    }

    static bool enter_resolve_impl( //TODO add timeout handling
        const std::shared_ptr<task>& t,
        opaque_network_state& state,
        address* out_single,
        std::vector<address>* out_multi,
        std::string_view host,
        std::string_view service,
        uint16_t port_override,
        address::family preferred_family
    ) {
        auto* rs = new (state.data) resolve_state();
        rs->out_single = out_single;
        rs->out_multi = out_multi;
        rs->preferred_family = preferred_family;

        const char* service_ptr = nullptr;
        if (port_override != 0) {
            snprintf(rs->port_buf, sizeof(rs->port_buf), "%u", (unsigned)port_override);
            service_ptr = rs->port_buf;
        } else if (!service.empty())
            service_ptr = service.data();

        while (rs->processing.test_and_set(std::memory_order_acquire))
            ;

        struct ares_options options{};
        int optmask = ARES_OPT_SOCK_STATE_CB;
        options.sock_state_cb = ares_sock_state_cb;
        options.sock_state_cb_data = rs;

        if (ares_init_options(&rs->channel, &options, optmask) != ARES_SUCCESS) {
            rs->error = EINVAL;
            rs->processing.clear(std::memory_order_release);
            rs->~resolve_state();
            return true;
        }

        struct ares_addrinfo_hints hints{};
        hints.ai_family = AF_UNSPEC;
        if (preferred_family == address::family::ipv4)
            hints.ai_family = AF_INET;
        else if (preferred_family == address::family::ipv6)
            hints.ai_family = AF_INET6;
        hints.ai_socktype = SOCK_STREAM;

        ares_getaddrinfo(rs->channel, host.data(), service_ptr, &hints, ares_addrinfo_cb, rs);

        if (rs->done) {
            if (rs->channel) {
                ares_destroy(rs->channel);
                rs->channel = nullptr;
            }
            if (rs->pending_polls.load(std::memory_order_acquire) == 0) {
                rs->processing.clear(std::memory_order_release);
                rs->~resolve_state();
                return true;
            }
        }
        rs->awaiting_task = t;
        rs->processing.clear(std::memory_order_release);
        return false;
    }

    bool address::enter_resolve(const std::shared_ptr<task>& t, opaque_network_state& state,
                                address& res, std::string_view host, std::string_view service,
                                address::family preferred_family) {
        return enter_resolve_impl(t, state, &res, nullptr, host, service, 0, preferred_family);
    }

    bool address::enter_resolve(const std::shared_ptr<task>& t, opaque_network_state& state,
                                address& res, std::string_view host, std::string_view service,
                                uint16_t port, address::family preferred_family) {
        return enter_resolve_impl(t, state, &res, nullptr, host, service, port, preferred_family);
    }

    bool address::enter_resolve_multiple(const std::shared_ptr<task>& t, opaque_network_state& state,
                                         std::vector<address>& res, std::string_view host,
                                         std::string_view service, address::family preferred_family) {
        return enter_resolve_impl(t, state, nullptr, &res, host, service, 0, preferred_family);
    }

    bool address::enter_resolve_multiple(const std::shared_ptr<task>& t, opaque_network_state& state,
                                         std::vector<address>& res, std::string_view host,
                                         std::string_view service, uint16_t port,
                                         address::family preferred_family) {
        return enter_resolve_impl(t, state, nullptr, &res, host, service, port, preferred_family);
    }

    address address::resolve(std::string_view host, std::string_view service,
                             address::family preferred_family) {
        address res;
        opaque_network_state state;
        if (get_loc().is_task_thread) {
            mutex_unify mut(fast_task::get_data(get_loc().curr_task).no_race);
            std::lock_guard guard(mut);
            if (!enter_resolve(get_loc().curr_task, state, res, host, service, preferred_family))
                swapCtxRelock(mut);
        } else {
            std::mutex mtx;
            std::condition_variable cv;
            bool done = false;
            auto t = task::create([&] { std::lock_guard lock(mtx); done = true; cv.notify_one(); });
            if (!enter_resolve(t, state, res, host, service, preferred_family)) {
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
        return res;
    }

    address address::resolve(std::string_view host, std::string_view service, uint16_t port,
                             address::family preferred_family) {
        address res;
        opaque_network_state state;
        if (get_loc().is_task_thread) {
            mutex_unify mut(fast_task::get_data(get_loc().curr_task).no_race);
            std::lock_guard guard(mut);
            if (!enter_resolve(get_loc().curr_task, state, res, host, service, port, preferred_family))
                swapCtxRelock(mut);
        } else {
            std::mutex mtx;
            std::condition_variable cv;
            bool done = false;
            auto t = task::create([&] { std::lock_guard lock(mtx); done = true; cv.notify_one(); });
            if (!enter_resolve(t, state, res, host, service, port, preferred_family)) {
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
        return res;
    }

    std::vector<address> address::resolve_multiple(std::string_view host, std::string_view service,
                                                   address::family preferred_family) {
        std::vector<address> res;
        opaque_network_state state;
        if (get_loc().is_task_thread) {
            mutex_unify mut(fast_task::get_data(get_loc().curr_task).no_race);
            std::lock_guard guard(mut);
            if (!enter_resolve_multiple(get_loc().curr_task, state, res, host, service, preferred_family))
                swapCtxRelock(mut);
        } else {
            std::mutex mtx;
            std::condition_variable cv;
            bool done = false;
            auto t = task::create([&] { std::lock_guard lock(mtx); done = true; cv.notify_one(); });
            if (!enter_resolve_multiple(t, state, res, host, service, preferred_family)) {
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
        return res;
    }

    std::vector<address> address::resolve_multiple(std::string_view host, std::string_view service,
                                                   uint16_t port, address::family preferred_family) {
        std::vector<address> res;
        opaque_network_state state;
        if (get_loc().is_task_thread) {
            mutex_unify mut(fast_task::get_data(get_loc().curr_task).no_race);
            std::lock_guard guard(mut);
            if (!enter_resolve_multiple(get_loc().curr_task, state, res, host, service, port, preferred_family))
                swapCtxRelock(mut);
        } else {
            std::mutex mtx;
            std::condition_variable cv;
            bool done = false;
            auto t = task::create([&] { std::lock_guard lock(mtx); done = true; cv.notify_one(); });
            if (!enter_resolve_multiple(t, state, res, host, service, port, preferred_family)) {
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
        return res;
    }

    #pragma endregion DNS

    uint8_t init_networking() {
        if (!inited) {
            ares_library_init(ARES_LIB_INIT_ALL);
            inited = true;
        }
        return 0;
    }

    void deinit_networking() {
        if (inited) {
            ares_library_cleanup();
            inited = false;
        }
    }
}
#endif