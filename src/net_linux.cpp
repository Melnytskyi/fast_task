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
    #include <ares.h>
    #include <fast_task/file.hpp>
    #include <fast_task/net.hpp>
    #include <fcntl.h>

namespace fast_task::net {
    std::atomic<bool> inited{false};
    static std::mutex net_init_mutex;

    static_assert(sizeof(universal_address) <= sizeof(address), "address buffer is too small for universal_address!");

    static bool set_socket_timeout(int sock, int optname, uint32_t timeout_ms) {
        timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        return setsockopt(sock, SOL_SOCKET, optname, &tv, sizeof(tv)) != -1;
    }

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
        if (!destruct)
            return {};
        auto& state = *reinterpret_cast<const native_state*>(this);
        return std::error_code(state.error, std::system_category());
    }

    class tcp_socket::manager : public util::native_worker_manager {
        std::atomic<int> sock{-1};

    public:
        manager(int s) : sock(s) {}

        ~manager() override {
            int fd = sock.exchange(INVALID_SOCKET, std::memory_order_acq_rel);
            if (fd != INVALID_SOCKET) {
                ::close(fd);
            }
        }

        manager(const manager&) = delete;
        manager& operator=(const manager&) = delete;
        manager(manager&&) = delete;
        manager& operator=(manager&&) = delete;

        int get_socket() const noexcept {
            return sock.load(std::memory_order_acquire);
        }

        int detach_socket() noexcept {
            return sock.exchange(INVALID_SOCKET, std::memory_order_acq_rel);
        }

        void handle(util::native_worker_handle* overlap, int32_t res, uint32_t) override {
            auto state = static_cast<native_state*>(overlap);
            state->error = res < 0 ? -res : 0;

            if (state->on_complete)
                state->on_complete(static_cast<void*>(state));
            if (state->awaiting_task) {
                if (state->out_processed_bytes)
                    *state->out_processed_bytes = res > -1 ? res : -1;
                {
                    fast_task::lock_guard guard(get_data(state->awaiting_task));
                }
                transfer_task(std::move(state->awaiting_task));
            }
        }

        bool set_configuration(const tcp_configuration& config) {
            int fd = get_socket();
            if (fd == INVALID_SOCKET)
                return false;
            int cfg = !config.allow_ip4;
            if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &cfg, sizeof(cfg)) == -1)
                return false;

            cfg = !config.enable_delay;
            if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &cfg, sizeof(cfg)) == -1)
                return false;

            if (!set_socket_timeout(fd, SO_RCVTIMEO, config.recv_timeout_ms))
                return false;

            if (!set_socket_timeout(fd, SO_SNDTIMEO, config.send_timeout_ms))
                return false;

            cfg = config.enable_keep_alive;
            if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &cfg, sizeof(cfg)) == -1)
                return false;
            if (config.enable_keep_alive) {
                int cfg = static_cast<int>(std::max<uint32_t>(1, config.keep_alive_settings.idle_ms / 1000));
                if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &cfg, sizeof(cfg)) == -1)
                    return false;
                cfg = static_cast<int>(std::max<uint32_t>(1, config.keep_alive_settings.interval_ms / 1000));
                if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &cfg, sizeof(cfg)) == -1)
                    return false;
                cfg = config.keep_alive_settings.retry_count == 0 ? 3 : config.keep_alive_settings.retry_count;
                if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cfg, sizeof(cfg)) == -1)
                    return false;
                cfg = static_cast<int>(config.keep_alive_settings.user_timeout_ms);
                if (setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &cfg, sizeof(cfg)) == -1)
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

        sockaddr_storage addr{};
        socklen_t addr_len = sizeof(addr);
        if (getsockname(handle->get_socket(), (sockaddr*)&addr, &addr_len) == -1)
            return address();
        return to_address(&addr);
    }

    address tcp_socket::remote_address() const noexcept {
        if (!handle || handle->get_socket() == INVALID_SOCKET)
            return address();

        sockaddr_storage addr{};
        socklen_t addr_len = sizeof(addr);
        if (getpeername(handle->get_socket(), (sockaddr*)&addr, &addr_len) == -1)
            return address();
        return to_address(&addr);
    }

    struct connect_state : public native_state {
        std::optional<tcp_socket>* out_socket = nullptr;
        sockaddr_storage dest_addr{};

        connect_state(util::native_worker_manager* mgr, std::optional<tcp_socket>* out, const address& ip_port)
            : native_state(mgr), out_socket(out) {
            memcpy(&dest_addr, ip_port.get_data(), sizeof(dest_addr));
            on_complete = [](void* base) {
                auto* s = static_cast<connect_state*>(base);
                if (s->error != 0 && s->out_socket)
                    *s->out_socket = std::nullopt;
            };
        }
    };

    bool tcp_socket::enter_connect(const task& t, opaque_network_state& state, std::optional<tcp_socket>& res, const address& ip_port, const tcp_configuration& config) {
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

        auto& n_state = *state.use<connect_state>(mgr.get(), &res, ip_port);
        n_state.awaiting_task = t;

        util::native_workers_singleton::post_connect(&n_state, clientSocket, (sockaddr*)&n_state.dest_addr, sizeof(n_state.dest_addr));

        tcp_socket new_sock;
        new_sock.handle = std::move(mgr);
        res = std::move(new_sock);
        return false;
    }

    bool tcp_socket::enter_connect(const task& t, opaque_network_state& state, std::optional<tcp_socket>& res, const address& ip_port, uint8_t* data, int32_t& size, const tcp_configuration& config) {
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

        auto& n_state = *state.use<connect_state>(mgr.get(), &res, ip_port);
        n_state.awaiting_task = t;
        n_state.out_processed_bytes = &size;

        util::native_workers_singleton::post_fast_connect(&n_state, clientSocket, (sockaddr*)&n_state.dest_addr, sizeof(n_state.dest_addr), data, size);

        tcp_socket new_sock;
        new_sock.handle = std::move(mgr);
        res = std::move(new_sock);
        return false;
    }

    bool tcp_socket::enter_recv(const task& t, opaque_network_state& state, int32_t& bytes_read, std::span<uint8_t> data) {
        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            bytes_read = -1;
            return true;
        }

        auto& n_state = *state.use<native_state>(handle.get());
        n_state.awaiting_task = t;
        n_state.out_processed_bytes = &bytes_read;
        util::native_workers_singleton::post_recv(&n_state, handle->get_socket(), data.data(), data.size(), 0);
        return false;
    }

    bool tcp_socket::enter_recvv(const task& t, opaque_network_state& state, int32_t& bytes_read, std::span<std::span<uint8_t>> data) {
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

            ~recvv_state() {
                if (uses_heap) {
                    delete[] bufs;
                    uses_heap = false;
                }
            }
        };

        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            bytes_read = -1;
            return true;
        }

        auto& n_state = *state.use<recvv_state>(handle.get());

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

    bool tcp_socket::enter_send(const task& t, opaque_network_state& state, int32_t& bytes_sent, std::span<const uint8_t> data) {
        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            bytes_sent = -1;
            return true;
        }

        auto& ns = *state.use<native_state>(handle.get());
        ns.awaiting_task = t;
        ns.out_processed_bytes = &bytes_sent;
        util::native_workers_singleton::post_send(&ns, handle->get_socket(), (char*)data.data(), data.size(), 0);
        return false;
    }

    bool tcp_socket::enter_sendv(const task& t, opaque_network_state& state, int32_t& bytes_sent, std::span<const std::span<const uint8_t>> data) {
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

            ~sendv_state() {
                if (uses_heap) {
                    delete[] bufs;
                    uses_heap = false;
                }
            }
        };

        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            bytes_sent = -1;
            return true;
        }

        auto& n_state = *state.use<sendv_state>(handle.get());

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

        ~transmit_file_state() {
            if (close_file_on_complete && file_handle != -1) {
                ::close(file_handle);
                file_handle = -1;
            }
            if (pipe_rfd != -1) {
                ::close(pipe_rfd);
                pipe_rfd = -1;
            }
            if (pipe_wfd != -1) {
                ::close(pipe_wfd);
                pipe_wfd = -1;
            }
        }
    };

    bool tcp_socket::enter_send_file(const task& t, opaque_network_state& state, int32_t& bytes_sent, const char* file_path, size_t file_path_len, uint32_t data_len, uint64_t offset, uint32_t) {
        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            bytes_sent = -1;
            return true;
        }
        auto& ns = *state.use<transmit_file_state>(handle.get());
        ns.awaiting_task = t;
        ns.out_processed_bytes = &bytes_sent;

        if (!file_path) {
            bytes_sent = -1;
            ns.error = EINVAL;
            return true;
        }
        std::string path_str(file_path, file_path_len);
        ns.file_handle = ::open(path_str.c_str(), O_RDONLY | O_CLOEXEC);
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

    bool tcp_socket::enter_send_file(const task& t, opaque_network_state& state, int32_t& bytes_sent, class fast_task::file::file_handle& file_path, uint32_t data_len, uint64_t offset, uint32_t) {
        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            bytes_sent = -1;
            return true;
        }
        auto& ns = *state.use<transmit_file_state>(handle.get());
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

    bool tcp_socket::enter_sendv_file(const task& t, opaque_network_state& state, int32_t& bytes_sent, const std::span<const uint8_t> prefix, const std::span<const uint8_t> postfix, const char* file_path, size_t file_path_len, uint32_t data_len, uint64_t offset, uint32_t) {
        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            bytes_sent = -1;
            return true;
        }

        auto& ns = *state.use<transmit_filev_state>(handle.get());
        ns.awaiting_task = t;
        ns.out_processed_bytes = &bytes_sent;
        ns.prefix_data = prefix.data();
        ns.prefix_len = static_cast<uint32_t>(prefix.size());
        ns.postfix_data = postfix.data();
        ns.postfix_len = static_cast<uint32_t>(postfix.size());

        if (!file_path) {
            bytes_sent = -1;
            ns.error = EINVAL;
            return true;
        }
        std::string path_str(file_path, file_path_len);
        ns.file_handle = ::open(path_str.c_str(), O_RDONLY | O_CLOEXEC);
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

    bool tcp_socket::enter_sendv_file(const task& t, opaque_network_state& state, int32_t& bytes_sent, const std::span<const uint8_t> prefix, const std::span<const uint8_t> postfix, class fast_task::file::file_handle& file_path, uint32_t data_len, uint64_t offset, uint32_t) {
        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            bytes_sent = -1;
            return true;
        }

        auto& ns = *state.use<transmit_filev_state>(handle.get());
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

    bool tcp_socket::enter_shutdown(const task&, opaque_network_state& state, shutdown_mode mode) {
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

        auto& ns = *state.use<native_state>(handle.get());
        ns.awaiting_task = nullptr;

        if (res == -1)
            ns.error = errno;

        return true;
    }

    bool tcp_socket::enter_reset(const task& t, opaque_network_state& state) {
        if (!handle)
            return true;
        int fd = handle->detach_socket();
        if (fd == INVALID_SOCKET)
            return true;

        linger lingerStruct;
        lingerStruct.l_onoff = 1;
        lingerStruct.l_linger = 0;
        ::setsockopt(fd, SOL_SOCKET, SO_LINGER, &lingerStruct, sizeof(lingerStruct));

        auto& ns = *state.use<native_state>(handle.get());
        ns.awaiting_task = t;
        util::native_workers_singleton::post_close(&ns, fd);
        return false;
    }

    bool tcp_socket::enter_close(const task& t, opaque_network_state& state) {
        if (!handle)
            return true;
        int fd = handle->detach_socket();
        if (fd == INVALID_SOCKET)
            return true;

        auto& ns = *state.use<native_state>(handle.get());
        ns.awaiting_task = t;
        util::native_workers_singleton::post_close(&ns, fd);
        return false;
    }

    class tcp_listener::manager : public util::native_worker_manager {
        std::atomic<int> sock{-1};

    public:
        manager(int s) : sock(s) {}

        ~manager() override {
            int fd = sock.exchange(INVALID_SOCKET, std::memory_order_acq_rel);
            if (fd != INVALID_SOCKET) {
                ::close(fd);
            }
        }

        manager(const manager&) = delete;
        manager& operator=(const manager&) = delete;
        manager(manager&&) = delete;
        manager& operator=(manager&&) = delete;

        int get_socket() const noexcept {
            return sock.load(std::memory_order_acquire);
        }

        int detach_socket() noexcept {
            return sock.exchange(INVALID_SOCKET, std::memory_order_acq_rel);
        }

        void handle(util::native_worker_handle* overlap, int32_t res, uint32_t) override {
            auto state = static_cast<native_state*>(overlap);
            state->error = res < 0 ? -res : 0;
            if (state->out_processed_bytes)
                *state->out_processed_bytes = res > -1 ? res : -1;
            if (state->on_complete)
                state->on_complete(static_cast<void*>(state));
            if (state->awaiting_task) {
                {
                    fast_task::lock_guard guard(get_data(state->awaiting_task));
                }
                transfer_task(std::move(state->awaiting_task));
            }
        }

        bool set_configuration(const tcp_configuration& config) {
            int fd = get_socket();
            if (fd == INVALID_SOCKET)
                return false;
            int cfg = !config.allow_ip4;
            if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &cfg, sizeof(cfg)) == -1)
                return false;

            cfg = !config.enable_delay;
            if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &cfg, sizeof(cfg)) == -1)
                return false;

            if (!set_socket_timeout(fd, SO_RCVTIMEO, config.recv_timeout_ms))
                return false;

            if (!set_socket_timeout(fd, SO_SNDTIMEO, config.send_timeout_ms))
                return false;

            cfg = config.enable_keep_alive;
            if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &cfg, sizeof(cfg)) == -1)
                return false;
            if (config.enable_keep_alive) {
                int cfg = static_cast<int>(std::max<uint32_t>(1, config.keep_alive_settings.idle_ms / 1000));
                if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &cfg, sizeof(cfg)) == -1)
                    return false;
                cfg = static_cast<int>(std::max<uint32_t>(1, config.keep_alive_settings.interval_ms / 1000));
                if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &cfg, sizeof(cfg)) == -1)
                    return false;
                cfg = config.keep_alive_settings.retry_count == 0 ? 3 : config.keep_alive_settings.retry_count;
                if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cfg, sizeof(cfg)) == -1)
                    return false;
                cfg = static_cast<int>(config.keep_alive_settings.user_timeout_ms);
                if (setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &cfg, sizeof(cfg)) == -1)
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
        if (getsockname(handle->get_socket(), (sockaddr*)&addr, &addr_len) == -1)
            return address();
        return to_address(&addr);
    }

    address tcp_listener::remote_address() const noexcept {
        return address();
    }

    bool tcp_listener::enter_close(const task& t, opaque_network_state& state) {
        if (!handle)
            return true;
        int fd = handle->detach_socket();
        if (fd == INVALID_SOCKET)
            return true;
        auto& ns = *state.use<native_state>(handle.get());
        ns.awaiting_task = t;
        util::native_workers_singleton::post_close(&ns, fd);
        return false;
    }

    bool tcp_listener::enter_accept(const task& t, opaque_network_state& state, std::optional<tcp_socket>& res) {
        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            res = std::nullopt;
            return true;
        }
        auto& ns = *state.use<accept_state>(handle.get());
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

    #pragma endregion
    #pragma region UDP

    class udp_handle : public util::native_worker_manager {
        std::atomic<int> sock{-1};

    public:
        udp_handle(int s) : sock(s) {}

        ~udp_handle() override {
            int fd = sock.exchange(INVALID_SOCKET, std::memory_order_acq_rel);
            if (fd != INVALID_SOCKET) {
                ::close(fd);
            }
        }

        udp_handle(const udp_handle&) = delete;
        udp_handle& operator=(const udp_handle&) = delete;

        int get_socket() const noexcept {
            return sock.load(std::memory_order_acquire);
        }

        int detach_socket() noexcept {
            return sock.exchange(INVALID_SOCKET, std::memory_order_acq_rel);
        }

        void handle(util::native_worker_handle* overlap, int32_t res, uint32_t) override {
            auto state = static_cast<native_state*>(overlap);
            state->error = res < 0 ? -res : 0;
            if (state->out_processed_bytes)
                *state->out_processed_bytes = res > -1 ? (int32_t)res : -1;
            if (state->on_complete)
                state->on_complete(static_cast<void*>(state));
            if (state->awaiting_task) {
                {
                    fast_task::lock_guard guard(get_data(state->awaiting_task));
                }
                transfer_task(std::move(state->awaiting_task));
            }
        }

        bool set_configuration(const udp_configuration& config) {
            int fd = get_socket();
            if (fd == INVALID_SOCKET)
                return false;
            int cfg = !config.allow_ip4;
            if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &cfg, sizeof(cfg)) == -1)
                return false;

            cfg = config.reuse_address ? 1 : 0;
            if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &cfg, sizeof(cfg)) == -1)
                return false;

            cfg = config.reuse_port ? 1 : 0;
            if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &cfg, sizeof(cfg)) == -1)
                return false;

            cfg = config.enable_broadcast ? 1 : 0;
            if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &cfg, sizeof(cfg)) == -1)
                return false;

            if (!set_socket_timeout(fd, SO_RCVTIMEO, config.recv_timeout_ms))
                return false;

            if (!set_socket_timeout(fd, SO_SNDTIMEO, config.send_timeout_ms))
                return false;

            if (config.recv_buffer_size > 0) {
                cfg = (int)config.recv_buffer_size;
                if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &cfg, sizeof(cfg)) == -1)
                    return false;
            }

            if (config.send_buffer_size > 0) {
                cfg = (int)config.send_buffer_size;
                if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &cfg, sizeof(cfg)) == -1)
                    return false;
            }

            if (config.dont_fragment) {
                cfg = IPV6_PMTUDISC_DO;
                if (setsockopt(fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &cfg, sizeof(cfg)) == -1)
                    return false;
                if (config.allow_ip4) {
                    cfg = IP_PMTUDISC_DO;
                    if (setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &cfg, sizeof(cfg)) == -1)
                        return false;
                }
            }

            cfg = config.multicast_loopback ? 1 : 0;
            if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &cfg, sizeof(cfg)) == -1)
                return false;

            cfg = config.multicast_ttl;
            if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &cfg, sizeof(cfg)) == -1)
                return false;

            return true;
        }

        address local_address() {
            int fd = get_socket();
            if (fd == INVALID_SOCKET)
                return {};
            universal_address addr{};
            socklen_t socklen = sizeof(universal_address);
            if (getsockname(fd, (sockaddr*)&addr, &socklen) == -1)
                return {};
            return to_address(addr);
        }

        address remote_address() {
            int fd = get_socket();
            if (fd == INVALID_SOCKET)
                return {};
            universal_address addr{};
            socklen_t socklen = sizeof(universal_address);
            if (getpeername(fd, (sockaddr*)&addr, &socklen) == -1)
                return {};
            return to_address(addr);
        }
    };

    struct udp_recv_state : public native_state {
        address* out_sender;
        uint32_t* out_bytes;
        int32_t bytes_io = 0;
        struct iovec iov{};
        struct msghdr msg{};
        sockaddr_storage sender_addr{};

        udp_recv_state(udp_handle* h, address* sender, uint32_t* bytes, uint8_t* data, size_t size)
            : native_state(h), out_sender(sender), out_bytes(bytes) {
            out_processed_bytes = &bytes_io;
            iov.iov_base = data;
            iov.iov_len = size;
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            if (sender) {
                msg.msg_name = &sender_addr;
                msg.msg_namelen = sizeof(sender_addr);
            }
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
        struct iovec iov{};
        struct msghdr msg{};
        sockaddr_storage dest_addr{};

        udp_send_state(udp_handle* h, uint32_t* bytes, const uint8_t* data, size_t size, const address* to = nullptr)
            : native_state(h), out_bytes(bytes) {
            out_processed_bytes = &bytes_io;
            iov.iov_base = const_cast<uint8_t*>(data);
            iov.iov_len = size;
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            if (to) {
                memcpy(&dest_addr, to->get_data(), sizeof(dest_addr));
                msg.msg_name = &dest_addr;
                msg.msg_namelen = sizeof(dest_addr);
            }
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
        struct iovec* bufs = nullptr;
        struct msghdr msg{};
        sockaddr_storage sender_addr{};

        udp_recvv_state(udp_handle* h, address* sender, uint32_t* bytes)
            : native_state(h), out_sender(sender), out_bytes(bytes) {
            out_processed_bytes = &bytes_io;
            if (sender) {
                msg.msg_name = &sender_addr;
                msg.msg_namelen = sizeof(sender_addr);
            }
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
        struct iovec* bufs = nullptr;
        struct msghdr msg{};
        sockaddr_storage dest_addr{};

        udp_sendv_state(udp_handle* h, uint32_t* bytes, const address* to = nullptr)
            : native_state(h), out_bytes(bytes) {
            out_processed_bytes = &bytes_io;
            if (to) {
                memcpy(&dest_addr, to->get_data(), sizeof(dest_addr));
                msg.msg_name = &dest_addr;
                msg.msg_namelen = sizeof(dest_addr);
            }
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
            return setsockopt(handle->get_socket(), IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) == 0;
        } else if (family == address::family::ipv6) {
            struct ipv6_mreq mreq{};
            const auto* sin6 = reinterpret_cast<const sockaddr_in6*>(addr);
            mreq.ipv6mr_multiaddr = sin6->sin6_addr;
            mreq.ipv6mr_interface = 0;
            return setsockopt(handle->get_socket(), IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) == 0;
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
            return setsockopt(handle->get_socket(), IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq)) == 0;
        } else if (family == address::family::ipv6) {
            struct ipv6_mreq mreq{};
            const auto* sin6 = reinterpret_cast<const sockaddr_in6*>(addr);
            mreq.ipv6mr_multiaddr = sin6->sin6_addr;
            mreq.ipv6mr_interface = 0;
            return setsockopt(handle->get_socket(), IPPROTO_IPV6, IPV6_LEAVE_GROUP, &mreq, sizeof(mreq)) == 0;
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
            return true;
        }
        auto& ns = *state.use<udp_recv_state>(handle.get(), &sender, &bytes_read, data.data(), data.size());
        ns.awaiting_task = t;
        util::native_workers_singleton::post_recvmsg(&ns, handle->get_socket(), &ns.msg, 0);
        return false;
    }

    bool udp_socket::enter_send(const task& t, opaque_network_state& state, uint32_t& bytes_sent, std::span<const uint8_t> data, const address& to) {
        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            bytes_sent = 0;
            return true;
        }
        auto& ns = *state.use<udp_send_state>(handle.get(), &bytes_sent, data.data(), data.size(), &to);
        ns.awaiting_task = t;
        util::native_workers_singleton::post_sendmsg(&ns, handle->get_socket(), &ns.msg, 0);
        return false;
    }

    bool udp_socket::enter_recvv(const task& t, opaque_network_state& state, uint32_t& bytes_read, std::span<std::span<uint8_t>> buffers, address& sender) {
        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            bytes_read = 0;
            return true;
        }
        auto& ns = *state.use<udp_recvv_state>(handle.get(), &sender, &bytes_read);
        ns.bufs = new struct iovec[buffers.size()];
        size_t count = 0;
        for (const auto& span : buffers) {
            if (!span.empty()) {
                ns.bufs[count].iov_base = span.data();
                ns.bufs[count].iov_len = span.size();
                count++;
            }
        }
        ns.msg.msg_iov = ns.bufs;
        ns.msg.msg_iovlen = count;
        ns.awaiting_task = t;
        util::native_workers_singleton::post_recvmsg(&ns, handle->get_socket(), &ns.msg, 0);
        return false;
    }

    bool udp_socket::enter_sendv(const task& t, opaque_network_state& state, uint32_t& bytes_sent, std::span<const std::span<const uint8_t>> data, const address& to) {
        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            bytes_sent = 0;
            return true;
        }
        auto& ns = *state.use<udp_sendv_state>(handle.get(), &bytes_sent, &to);
        ns.bufs = new struct iovec[data.size()];
        size_t count = 0;
        for (const auto& span : data) {
            if (!span.empty()) {
                ns.bufs[count].iov_base = const_cast<uint8_t*>(span.data());
                ns.bufs[count].iov_len = span.size();
                count++;
            }
        }
        ns.msg.msg_iov = ns.bufs;
        ns.msg.msg_iovlen = count;
        ns.awaiting_task = t;
        util::native_workers_singleton::post_sendmsg(&ns, handle->get_socket(), &ns.msg, 0);
        return false;
    }

    bool udp_socket::enter_close(const task& t, opaque_network_state& state) {
        if (!handle)
            return true;
        int fd = handle->detach_socket();
        if (fd == INVALID_SOCKET)
            return true;
        auto& ns = *state.use<native_state>(handle.get());
        ns.awaiting_task = t;
        util::native_workers_singleton::post_close(&ns, fd);
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
            return true;
        }
        auto& ns = *state.use<udp_recv_state>(handle.get(), nullptr, &bytes_read, data.data(), data.size());
        ns.awaiting_task = t;
        util::native_workers_singleton::post_recvmsg(&ns, handle->get_socket(), &ns.msg, 0);
        return false;
    }

    bool udp_peer::enter_send(const task& t, opaque_network_state& state, uint32_t& bytes_sent, std::span<const uint8_t> data) {
        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            bytes_sent = 0;
            return true;
        }
        auto& ns = *state.use<udp_send_state>(handle.get(), &bytes_sent, data.data(), data.size());
        ns.awaiting_task = t;
        util::native_workers_singleton::post_sendmsg(&ns, handle->get_socket(), &ns.msg, 0);
        return false;
    }

    bool udp_peer::enter_recvv(const task& t, opaque_network_state& state, uint32_t& bytes_read, std::span<std::span<uint8_t>> buffers) {
        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            bytes_read = 0;
            return true;
        }
        auto& ns = *state.use<udp_recvv_state>(handle.get(), nullptr, &bytes_read);
        ns.bufs = new struct iovec[buffers.size()];
        size_t count = 0;
        for (const auto& span : buffers) {
            if (!span.empty()) {
                ns.bufs[count].iov_base = span.data();
                ns.bufs[count].iov_len = span.size();
                count++;
            }
        }
        ns.msg.msg_iov = ns.bufs;
        ns.msg.msg_iovlen = count;
        ns.awaiting_task = t;
        util::native_workers_singleton::post_recvmsg(&ns, handle->get_socket(), &ns.msg, 0);
        return false;
    }

    bool udp_peer::enter_sendv(const task& t, opaque_network_state& state, uint32_t& bytes_sent, std::span<const std::span<const uint8_t>> data) {
        if (!handle || handle->get_socket() == INVALID_SOCKET) {
            bytes_sent = 0;
            return true;
        }
        auto& ns = *state.use<udp_sendv_state>(handle.get(), &bytes_sent);
        ns.bufs = new struct iovec[data.size()];
        size_t count = 0;
        for (const auto& span : data) {
            if (!span.empty()) {
                ns.bufs[count].iov_base = const_cast<uint8_t*>(span.data());
                ns.bufs[count].iov_len = span.size();
                count++;
            }
        }
        ns.msg.msg_iov = ns.bufs;
        ns.msg.msg_iovlen = count;
        ns.awaiting_task = t;
        util::native_workers_singleton::post_sendmsg(&ns, handle->get_socket(), &ns.msg, 0);
        return false;
    }

    bool udp_peer::enter_close(const task& t, opaque_network_state& state) {
        if (!handle)
            return true;
        int fd = handle->detach_socket();
        if (fd == INVALID_SOCKET)
            return true;
        auto& ns = *state.use<native_state>(handle.get());
        ns.awaiting_task = t;
        util::native_workers_singleton::post_close(&ns, fd);
        return false;
    }

    #pragma endregion
    #pragma region DNS

    struct resolve_impl : public util::native_worker_manager, public std::enable_shared_from_this<resolve_impl> {
        ares_channel channel = nullptr;
        address* out_single = nullptr;
        std::vector<address>* out_multi = nullptr;
        int* out_error = nullptr;
        task awaiting_task;

        std::atomic_flag processing{};
        address::family preferred_family = address::family::none;
        bool done = false;

        struct sock_poll_handle : public util::native_worker_handle {
            std::shared_ptr<resolve_impl> owner;
            ares_socket_t fd;
            int events;
            bool is_active;
            sock_poll_handle* next;

            sock_poll_handle(resolve_impl* s, ares_socket_t f)
                : util::native_worker_handle(s), fd(f), events(0), is_active(false), next(nullptr) {}
        };

        sock_poll_handle* active_polls = nullptr;

        ~resolve_impl() override {
            if (channel) {
                ares_destroy(channel);
                channel = nullptr;
            }
            while (active_polls) {
                auto* next = active_polls->next;
                delete active_polls;
                active_polls = next;
            }
        }

        void add_poll(sock_poll_handle* ph) {
            ph->is_active = true;
            ph->owner = shared_from_this();
            util::native_workers_singleton::post_poll_add(ph, ph->fd, ph->events);
        }

        void handle(util::native_worker_handle* h, int32_t res, uint32_t) override {
            auto* ph = static_cast<sock_poll_handle*>(h);
            std::shared_ptr<resolve_impl> keep_alive = std::move(ph->owner);

            while (processing.test_and_set(std::memory_order_acquire))
                ;

            ph->is_active = false;

            if (!done && channel && ph->events != 0) {
                ares_socket_t fd = ph->fd;
                ares_socket_t rfd = ARES_SOCKET_BAD, wfd = ARES_SOCKET_BAD;
                if (res > 0) {
                    if (res & POLLIN)
                        rfd = fd;
                    if (res & POLLOUT)
                        wfd = fd;
                    if (res & (POLLERR | POLLHUP | POLLNVAL)) {
                        rfd = fd;
                        wfd = fd;
                    }
                } else {
                    rfd = wfd = fd;
                }
                ares_process_fd(channel, rfd, wfd);
            }

            if (done) {
                if (channel) {
                    ares_destroy(channel);
                    channel = nullptr;
                }
                task to_resume = std::move(awaiting_task);
                out_single = nullptr;
                out_multi = nullptr;
                out_error = nullptr;
                processing.clear(std::memory_order_release);

                if (to_resume) {
                    {
                        fast_task::lock_guard guard(get_data(to_resume));
                    }
                    transfer_task(std::move(to_resume));
                }
                return;
            } else {
                if (!ph->is_active && ph->events != 0) {
                    add_poll(ph);
                }
            }

            processing.clear(std::memory_order_release);
        }
    };

    struct resolve_state : public native_state {
        std::shared_ptr<resolve_impl> impl;

        resolve_state() : native_state(nullptr), impl(std::make_shared<resolve_impl>()) {
            impl->out_error = &error;
        }
    };

    static void ares_sock_state_cb(void* data, ares_socket_t socket_fd, int readable, int writable) {
        auto* impl = static_cast<resolve_impl*>(data);

        int events = 0;
        if (readable)
            events |= POLLIN;
        if (writable)
            events |= POLLOUT;

        resolve_impl::sock_poll_handle* handle = nullptr;
        for (auto* ph = impl->active_polls; ph; ph = ph->next) {
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
                handle = new resolve_impl::sock_poll_handle(impl, socket_fd);
                handle->next = impl->active_polls;
                impl->active_polls = handle;
            }
            handle->events = events;
            if (!handle->is_active) {
                impl->add_poll(handle);
            }
        }
    }

    static void ares_addrinfo_cb(void* arg, int status, int /*timeouts*/, struct ares_addrinfo* result) {
        auto* impl = static_cast<resolve_impl*>(arg);

        if (status == ARES_SUCCESS && result) {
            for (auto* node = result->nodes; node; node = node->ai_next) {
                if (impl->preferred_family != address::family::none) {
                    address::family nf = address::family::none;
                    if (node->ai_family == AF_INET)
                        nf = address::family::ipv4;
                    else if (node->ai_family == AF_INET6)
                        nf = address::family::ipv6;
                    if (nf != impl->preferred_family)
                        continue;
                }
                address addr = to_address(node->ai_addr);
                if (impl->out_single) {
                    *impl->out_single = addr;
                    impl->out_single = nullptr;
                    break;
                } else if (impl->out_multi) {
                    impl->out_multi->push_back(addr);
                }
            }
            ares_freeaddrinfo(result);
        } else if (status != ARES_SUCCESS) {
            if (impl->out_error)
                *impl->out_error = status;
        }

        impl->done = true;
    }

    static bool enter_resolve_impl( //TODO add timeout handling
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
        auto* rs = state.use<resolve_state>();
        auto& impl = rs->impl;
        impl->out_single = out_single;
        impl->out_multi = out_multi;
        impl->preferred_family = preferred_family;

        std::string host_str(host);
        std::string service_str;
        const char* service_ptr = nullptr;
        if (port_override != 0) {
            service_str = std::to_string(port_override);
            service_ptr = service_str.c_str();
        } else if (!service.empty()) {
            service_str.assign(service.data(), service.size());
            service_ptr = service_str.c_str();
        }

        while (impl->processing.test_and_set(std::memory_order_acquire))
            ;

        struct ares_options options{};
        int optmask = ARES_OPT_SOCK_STATE_CB;
        options.sock_state_cb = ares_sock_state_cb;
        options.sock_state_cb_data = impl.get();

        if (ares_init_options(&impl->channel, &options, optmask) != ARES_SUCCESS) {
            rs->error = EINVAL;
            impl->out_single = nullptr;
            impl->out_multi = nullptr;
            impl->out_error = nullptr;
            impl->processing.clear(std::memory_order_release);
            return true;
        }

        struct ares_addrinfo_hints hints{};
        hints.ai_family = AF_UNSPEC;
        if (preferred_family == address::family::ipv4)
            hints.ai_family = AF_INET;
        else if (preferred_family == address::family::ipv6)
            hints.ai_family = AF_INET6;
        hints.ai_socktype = SOCK_STREAM;

        ares_getaddrinfo(impl->channel, host_str.c_str(), service_ptr, &hints, ares_addrinfo_cb, impl.get());

        if (impl->done) {
            if (impl->channel) {
                ares_destroy(impl->channel);
                impl->channel = nullptr;
            }
            impl->out_single = nullptr;
            impl->out_multi = nullptr;
            impl->out_error = nullptr;
            impl->processing.clear(std::memory_order_release);
            return true;
        }
        impl->awaiting_task = t;
        impl->processing.clear(std::memory_order_release);
        return false;
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

    address address::resolve(std::string_view host, std::string_view service,
                             address::family preferred_family) {
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
            auto t = task::create([&] { std::lock_guard lock(mtx); done = true; cv.notify_one(); });
            if (!enter_resolve(t, state, res, host, service, preferred_family)) {
                scheduler::ensure_global_worker();
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
            auto t = task::create([&] { std::lock_guard lock(mtx); done = true; cv.notify_one(); });
            if (!enter_resolve(t, state, res, host, service, port, preferred_family)) {
                scheduler::ensure_global_worker();
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
            auto t = task::create([&] { std::lock_guard lock(mtx); done = true; cv.notify_one(); });
            if (!enter_resolve_multiple(t, state, res, host, service, preferred_family)) {
                scheduler::ensure_global_worker();
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
            auto t = task::create([&] { std::lock_guard lock(mtx); done = true; cv.notify_one(); });
            if (!enter_resolve_multiple(t, state, res, host, service, port, preferred_family)) {
                scheduler::ensure_global_worker();
                std::unique_lock lock(mtx);
                cv.wait(lock, [&] { return done; });
            }
        }
        return res;
    }

    #pragma endregion

    uint8_t init_networking() {
        if (!inited.load(std::memory_order_acquire)) {
            std::lock_guard lock(net_init_mutex);
            if (!inited.load(std::memory_order_relaxed)) {
                ares_library_init(ARES_LIB_INIT_ALL);
                inited.store(true, std::memory_order_release);
            }
        }
        return 0;
    }

    void deinit_networking() {
        if (inited.load(std::memory_order_acquire)) {
            std::lock_guard lock(net_init_mutex);
            if (inited.load(std::memory_order_relaxed)) {
                ares_library_cleanup();
                inited.store(false, std::memory_order_release);
            }
        }
    }
}
#endif