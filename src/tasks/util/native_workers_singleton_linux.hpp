
// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)
#ifndef SRC_TASKS_UTIL_NATIVE_WORKERS_SINGLETON_LINUX
#define SRC_TASKS_UTIL_NATIVE_WORKERS_SINGLETON_LINUX
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <concurrentqueue/moodycamel/concurrentqueue.h>
#include <cstdio>
#include <cstring>
#include <fast_task/native/thread.hpp>
#include <fast_task/shared.hpp>
#include <liburing.h>
#include <list>
#include <system_error>
#include <vector>

#include <fcntl.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/resource.h>
#include <unistd.h>

namespace fast_task::util {
    void driver_notify_io_submission() noexcept;

    class FT_API_LOCAL native_worker_manager {
    public:
        virtual void handle(class native_worker_handle* overlapped, int32_t res, uint32_t flags) = 0;
        virtual ~native_worker_manager() noexcept(false) = default;
    };
    enum class operations : uint8_t {
        nop,
        connect,
        fast_connect,
        recv,
        send,
        close,
        accept,
        recvmsg,
        sendmsg,
        sendfile,
        sendv_file,
        read,
        write,
        readv,
        writev,
        poll_add,
    };

    class FT_API_LOCAL native_worker_handle {
        friend class native_workers_singleton;
        native_worker_manager* manager;

        struct iov_args {
            const iovec* iov;
            uint32_t iovcnt;
        };

        struct buf_args {
            const void* buf;
            uint32_t len;
            int32_t buf_index;
        };

        struct open_args {
            const char* pPath;
            mode_t mode;
        };

        struct splice_args {
            int file_fd;
            int pipe_rfd;
            int pipe_wfd;
            uint32_t len;
        };

        struct vector_args {
            struct iovec* iovs;
            uint32_t iovcnt;
        };

        struct addr_recv_args {
            sockaddr* addr;
            socklen_t* len;
        };

        struct addr_target_args {
            const sockaddr* addr;
            socklen_t len;
        };

        struct send_file_v_args {
            const void* prefix;
            uint32_t prefix_len;
            const void* postfix;
            uint32_t postfix_len;
        };

        struct {
            operations opcode = operations::nop;
            int fd = 0;
            uint64_t offset = 0;

            union {
                iov_args v;
                buf_args b;
                open_args f_o;
                splice_args splice_fds;
                vector_args vector;
                msghdr* pMsg;
                uint64_t range;
                short mask;
                int how;
                __kernel_timespec* timeout;
            };

            union {
                addr_recv_args addr_recv;
                addr_target_args addr_target;
                send_file_v_args send_file_v;
                struct statx* pStatxbuf;
                uint64_t user_data;
            };

            int32_t flags = 0;
            int32_t linked_error = 0;
        } request_data;

    public:
        native_worker_handle(native_worker_manager* manager)
            : manager(manager) {
            request_data.b.buf = nullptr;
            request_data.b.buf_index = 0;
            request_data.b.len = 0;
            request_data.addr_recv.addr = nullptr;
            request_data.addr_recv.len = nullptr;
        }

        native_worker_handle() = delete;
        native_worker_handle(const native_worker_handle&) = delete;
        native_worker_handle(native_worker_handle&&) = delete;
        native_worker_handle& operator=(const native_worker_handle&) = delete;
        native_worker_handle& operator=(native_worker_handle&&) = delete;
    };

    static_assert(alignof(native_worker_handle) >= 4, "native_worker_handle alignment too small for user_data tagging");

    class FT_API_LOCAL native_workers_singleton {
        static constexpr uintptr_t WAKEUP_USER_DATA = 1;
        static constexpr uintptr_t LINKED_PREREQ_TAG = 2;
        static constexpr uint32_t MAX_SPLICE_CHUNK = 65536u;

        io_uring ring{};
        moodycamel::ConcurrentQueue<native_worker_handle*> queue;
        int wakeup_eventfd = -1;
        bool wake_armed = false;
        bool ring_initialized = false;
        int ring_init_error = 0;

        std::atomic<uint32_t> pending_submissions{0};
        static inline std::atomic<bool> ring_live{false};

        static void* linked_prereq_data(native_worker_handle* h) noexcept {
            return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(h) | LINKED_PREREQ_TAG);
        }

        static unsigned needed_sqes_for(const native_worker_handle* h) noexcept {
            switch (h->request_data.opcode) {
            case operations::fast_connect:
                return (h->request_data.b.buf && h->request_data.b.len > 0) ? 2u : 1u;
            case operations::sendfile:
                return 2u;
            case operations::sendv_file: {
                unsigned n = 2u;
                if (h->request_data.send_file_v.prefix_len > 0)
                    ++n;
                if (h->request_data.send_file_v.postfix_len > 0)
                    ++n;
                return n;
            }
            default:
                return 1u;
            }
        }

        native_workers_singleton() {
            wakeup_eventfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);

            struct rlimit mem_rl = {};
            getrlimit(RLIMIT_MEMLOCK, &mem_rl);
            size_t locked_kb = 0;
            if (mem_rl.rlim_cur != RLIM_INFINITY) {
                if (FILE* f = fopen("/proc/self/status", "r")) {
                    char line[256];
                    while (fgets(line, sizeof(line), f))
                        if (sscanf(line, "VmLck: %zu kB", &locked_kb) == 1)
                            break;
                    fclose(f);
                }
            }

            auto ring_bytes_estimate = [](unsigned int q) -> size_t {
                return static_cast<size_t>(q) * 112 + 16384;
            };

            static constexpr unsigned int candidates[] = {1024, 512, 256, 128, 64};
            static constexpr unsigned int num_candidates = sizeof(candidates) / sizeof(*candidates);
            unsigned int start_idx = 0;
            if (mem_rl.rlim_cur != RLIM_INFINITY) {
                size_t available = static_cast<size_t>(mem_rl.rlim_cur) > locked_kb * 1024
                                       ? static_cast<size_t>(mem_rl.rlim_cur) - locked_kb * 1024
                                       : 0;
                start_idx = num_candidates - 1;
                for (unsigned int ci = 0; ci < num_candidates; ++ci) {
                    if (ring_bytes_estimate(candidates[ci]) <= available) {
                        start_idx = ci;
                        break;
                    }
                }
            }

            struct io_uring_params params;
            std::memset(&params, 0, sizeof(params));
            int uring_ret = -ENOMEM;
            for (unsigned int ci = start_idx; ci < num_candidates && uring_ret == -ENOMEM; ++ci) {
                for (int attempt = 0; attempt < 10 && uring_ret == -ENOMEM; ++attempt) {
                    uring_ret = io_uring_queue_init_params(candidates[ci], &ring, &params);
                    if (uring_ret != -ENOMEM)
                        break;
                    struct timespec ts = {0, static_cast<long>(20000000L * (attempt + 1))};
                    nanosleep(&ts, nullptr);
                }
                if (uring_ret == 0)
                    break;
                std::memset(&params, 0, sizeof(params));
            }
            if (uring_ret < 0) {
                fprintf(stderr, "fast_task: io_uring_queue_init_params failed: %s\n", strerror(-uring_ret));
                if (uring_ret == -ENOMEM && mem_rl.rlim_cur != RLIM_INFINITY) {
                    fprintf(stderr, "  RLIMIT_MEMLOCK = %zu KB, currently locked = %zu KB\n"
                                    "  Estimated minimum requirement: ~%zu KB for 1 ring\n"
                                    "  To fix, increase the locked memory limit:\n"
                                    "    session:   ulimit -l unlimited\n"
                                    "    permanent: add '* - memlock unlimited' to /etc/security/limits.conf\n"
                                    "               then log out and back in\n",
                            static_cast<size_t>(mem_rl.rlim_cur) / 1024,
                            locked_kb,
                            ring_bytes_estimate(candidates[num_candidates - 1]) / 1024);
                }
                ring_initialized = false;
                ring_init_error = -uring_ret;
                return;
            }

            ring_initialized = true;
            arm_wakeup_on(*this);
            ring_live.store(true, std::memory_order_release);
        }

        static void arm_wakeup_on(native_workers_singleton& self) {
            if (!self.ring_initialized || self.wakeup_eventfd < 0) {
                self.wake_armed = false;
                return;
            }
            io_uring_sqe* sqe = io_uring_get_sqe(&self.ring);
            if (!sqe) {
                io_uring_submit(&self.ring);
                sqe = io_uring_get_sqe(&self.ring);
            }
            if (!sqe) {
                self.wake_armed = false;
                return;
            }
            io_uring_prep_poll_add(sqe, self.wakeup_eventfd, POLLIN);
            io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(WAKEUP_USER_DATA));
            self.wake_armed = true;
        }

        static void arm_wakeup() {
            arm_wakeup_on(get_instance());
        }

        static bool prepare_handle_sqe(native_worker_handle* h) {
            auto& self = get_instance();
            if (!self.ring_initialized)
                return false;

            const unsigned needed = needed_sqes_for(h);
            if (io_uring_sq_space_left(&self.ring) < needed)
                io_uring_submit(&self.ring);
            if (io_uring_sq_space_left(&self.ring) < needed) {
                drain();
                io_uring_submit(&self.ring);
            }
            if (io_uring_sq_space_left(&self.ring) < needed)
                return false;

            io_uring_sqe* sqes[4] = {};
            for (unsigned i = 0; i < needed; ++i) {
                sqes[i] = io_uring_get_sqe(&self.ring);
                if (!sqes[i]) {
                    for (unsigned j = 0; j < i; ++j) {
                        io_uring_prep_nop(sqes[j]);
                        io_uring_sqe_set_data(sqes[j], nullptr);
                    }
                    return false;
                }
            }

            h->request_data.linked_error = 0;

            switch (h->request_data.opcode) {
            case operations::nop:
                io_uring_prep_nop(sqes[0]);
                io_uring_sqe_set_data(sqes[0], h);
                break;
            case operations::connect:
                io_uring_prep_connect(sqes[0], h->request_data.fd, h->request_data.addr_target.addr, h->request_data.addr_target.len);
                io_uring_sqe_set_data(sqes[0], h);
                break;
            case operations::fast_connect:
                io_uring_prep_connect(sqes[0], h->request_data.fd, h->request_data.addr_target.addr, h->request_data.addr_target.len);
                if (needed == 2u) {
                    io_uring_sqe_set_data(sqes[0], linked_prereq_data(h));
                    sqes[0]->flags |= IOSQE_IO_LINK;
                    io_uring_prep_send(sqes[1], h->request_data.fd, h->request_data.b.buf, h->request_data.b.len, 0);
                    io_uring_sqe_set_data(sqes[1], h);
                } else {
                    io_uring_sqe_set_data(sqes[0], h);
                }
                break;
            case operations::recv:
                io_uring_prep_recv(sqes[0], h->request_data.fd, const_cast<void*>(h->request_data.b.buf), h->request_data.b.len, h->request_data.flags);
                io_uring_sqe_set_data(sqes[0], h);
                break;
            case operations::send:
                io_uring_prep_send(sqes[0], h->request_data.fd, h->request_data.b.buf, h->request_data.b.len, h->request_data.flags);
                io_uring_sqe_set_data(sqes[0], h);
                break;
            case operations::close:
                io_uring_prep_close(sqes[0], h->request_data.fd);
                io_uring_sqe_set_data(sqes[0], h);
                break;
            case operations::accept:
                io_uring_prep_accept(sqes[0], h->request_data.fd, h->request_data.addr_recv.addr, h->request_data.addr_recv.len, h->request_data.flags);
                io_uring_sqe_set_data(sqes[0], h);
                break;
            case operations::recvmsg:
                io_uring_prep_recvmsg(sqes[0], h->request_data.fd, h->request_data.pMsg, h->request_data.flags);
                io_uring_sqe_set_data(sqes[0], h);
                break;
            case operations::sendmsg:
                io_uring_prep_sendmsg(sqes[0], h->request_data.fd, h->request_data.pMsg, h->request_data.flags);
                io_uring_sqe_set_data(sqes[0], h);
                break;
            case operations::sendfile: {
                const uint32_t splice_len = std::min<uint32_t>(h->request_data.splice_fds.len, MAX_SPLICE_CHUNK);
                io_uring_prep_splice(sqes[0], h->request_data.splice_fds.file_fd, static_cast<int64_t>(h->request_data.offset), h->request_data.splice_fds.pipe_wfd, -1, splice_len, SPLICE_F_MOVE);
                io_uring_sqe_set_data(sqes[0], linked_prereq_data(h));
                sqes[0]->flags |= IOSQE_IO_LINK;
                io_uring_prep_splice(sqes[1], h->request_data.splice_fds.pipe_rfd, -1, h->request_data.fd, -1, splice_len, SPLICE_F_MOVE);
                io_uring_sqe_set_data(sqes[1], h);
                break;
            }
            case operations::sendv_file: {
                const uint32_t splice_len = std::min<uint32_t>(h->request_data.splice_fds.len, MAX_SPLICE_CHUNK);
                unsigned idx = 0;
                if (h->request_data.send_file_v.prefix_len > 0) {
                    io_uring_prep_send(sqes[idx], h->request_data.fd, h->request_data.send_file_v.prefix, h->request_data.send_file_v.prefix_len, 0);
                    io_uring_sqe_set_data(sqes[idx], linked_prereq_data(h));
                    sqes[idx]->flags |= IOSQE_IO_LINK;
                    ++idx;
                }
                io_uring_prep_splice(sqes[idx], h->request_data.splice_fds.file_fd, static_cast<int64_t>(h->request_data.offset), h->request_data.splice_fds.pipe_wfd, -1, splice_len, SPLICE_F_MOVE);
                io_uring_sqe_set_data(sqes[idx], linked_prereq_data(h));
                sqes[idx]->flags |= IOSQE_IO_LINK;
                ++idx;
                io_uring_prep_splice(sqes[idx], h->request_data.splice_fds.pipe_rfd, -1, h->request_data.fd, -1, splice_len, SPLICE_F_MOVE);
                if (h->request_data.send_file_v.postfix_len > 0) {
                    io_uring_sqe_set_data(sqes[idx], linked_prereq_data(h));
                    sqes[idx]->flags |= IOSQE_IO_LINK;
                    ++idx;
                    io_uring_prep_send(sqes[idx], h->request_data.fd, h->request_data.send_file_v.postfix, h->request_data.send_file_v.postfix_len, 0);
                }
                io_uring_sqe_set_data(sqes[idx], h);
                break;
            }
            case operations::read:
                io_uring_prep_read(sqes[0], h->request_data.fd, const_cast<void*>(h->request_data.b.buf), h->request_data.b.len, h->request_data.offset);
                io_uring_sqe_set_data(sqes[0], h);
                break;
            case operations::write:
                io_uring_prep_write(sqes[0], h->request_data.fd, h->request_data.b.buf, h->request_data.b.len, h->request_data.offset);
                io_uring_sqe_set_data(sqes[0], h);
                break;
            case operations::readv:
                io_uring_prep_readv2(sqes[0], h->request_data.fd, h->request_data.vector.iovs, h->request_data.vector.iovcnt, h->request_data.offset, h->request_data.flags);
                io_uring_sqe_set_data(sqes[0], h);
                break;
            case operations::writev:
                io_uring_prep_writev2(sqes[0], h->request_data.fd, h->request_data.vector.iovs, h->request_data.vector.iovcnt, h->request_data.offset, h->request_data.flags);
                io_uring_sqe_set_data(sqes[0], h);
                break;
            case operations::poll_add:
                io_uring_prep_poll_add(sqes[0], h->request_data.fd, (uint32_t)(unsigned short)h->request_data.mask);
                io_uring_sqe_set_data(sqes[0], h);
                break;
            default:
                io_uring_prep_nop(sqes[0]);
                io_uring_sqe_set_data(sqes[0], h);
                break;
            }
            return true;
        }

        static void drain() {
            auto& self = get_instance();
            if (!self.ring_initialized)
                return;

            io_uring_cqe* cqe = nullptr;
            while (io_uring_peek_cqe(&self.ring, &cqe) == 0) {
                auto user_data = reinterpret_cast<uintptr_t>(io_uring_cqe_get_data(cqe));
                int32_t res = cqe->res;
                uint32_t flags = cqe->flags;
                io_uring_cqe_seen(&self.ring, cqe);

                if (user_data == WAKEUP_USER_DATA) {
                    if (self.wakeup_eventfd >= 0) {
                        uint64_t val = 0;
                        ssize_t r = read(self.wakeup_eventfd, &val, sizeof(val));
                        (void)r;
                    }
                    self.wake_armed = false;
                    arm_wakeup_on(self);
                    continue;
                }

                if ((user_data & LINKED_PREREQ_TAG) != 0) {
                    auto handle = reinterpret_cast<native_worker_handle*>(user_data & ~LINKED_PREREQ_TAG);
                    if (handle && res < 0 && handle->request_data.linked_error == 0)
                        handle->request_data.linked_error = res;
                    continue;
                }

                auto handle = reinterpret_cast<native_worker_handle*>(user_data);
                if (!handle || !handle->manager)
                    continue;

                if (res == -ECANCELED && handle->request_data.linked_error < 0)
                    res = handle->request_data.linked_error;

                handle->manager->handle(handle, res, flags);
            }
        }

        static void build_submissions() {
            auto& self = get_instance();
            if (!self.ring_initialized)
                return;

            native_worker_handle* handles[256];
            size_t count;
            while ((count = self.queue.try_dequeue_bulk(handles, 256)) > 0) {
                bool stalled = false;
                for (size_t i = 0; i < count; ++i) {
                    if (!prepare_handle_sqe(handles[i])) {
                        size_t remaining = count - i;
                        self.pending_submissions.fetch_add(
                            static_cast<uint32_t>(remaining), std::memory_order_release
                        );
                        self.queue.enqueue_bulk(handles + i, remaining);
                        stalled = true;
                        break;
                    }
                }
                self.pending_submissions.fetch_sub(
                    static_cast<uint32_t>(count), std::memory_order_acq_rel
                );
                if (stalled)
                    break;
            }
        }

        static native_workers_singleton& get_instance() {
            static native_workers_singleton instance;
            return instance;
        }

        static void sumbmit(native_worker_handle* handle, int /*hFile*/) {
            auto& self = get_instance();
            if (!self.ring_initialized)
                throw std::system_error(
                    self.ring_init_error ? self.ring_init_error : ENOSYS,
                    std::generic_category(),
                    "io_uring is not initialized"
                );
            self.pending_submissions.fetch_add(1, std::memory_order_release);
            try {
                self.queue.enqueue(handle);
            } catch (...) {
                self.pending_submissions.fetch_sub(1, std::memory_order_release);
                throw;
            }
            driver_notify_io_submission();
        }

    public:
        ~native_workers_singleton() {
            ring_live.store(false, std::memory_order_release);
            if (ring_initialized)
                io_uring_queue_exit(&ring);
            if (wakeup_eventfd >= 0)
                close(wakeup_eventfd);
        }

        static bool has_ready_work() {
            if (!ring_live.load(std::memory_order_acquire))
                return false;
            auto& self = get_instance();
            if (!self.ring_initialized)
                return false;
            if (self.pending_submissions.load(std::memory_order_acquire) != 0)
                return true;
            return io_uring_cq_ready(&self.ring) != 0;
        }

        static bool poll_all(int timeout_ms) {
            auto& self = get_instance();
            if (!self.ring_initialized)
                return false;
            if (!self.wake_armed && self.wakeup_eventfd >= 0)
                arm_wakeup_on(self);
            build_submissions();

            if (timeout_ms == 0 && io_uring_sq_ready(&self.ring) == 0 &&
                io_uring_cq_ready(&self.ring) == 0)
                return true;

            io_uring_cqe* cqe = nullptr;
            __kernel_timespec ts{};
            __kernel_timespec* ts_ptr = nullptr;
            if (timeout_ms >= 0) {
                ts.tv_sec = timeout_ms / 1000;
                ts.tv_nsec = static_cast<long long>(timeout_ms % 1000) * 1000000LL;
                ts_ptr = &ts;
            }

            int ret = io_uring_submit_and_wait_timeout(&self.ring, &cqe, 1, ts_ptr, nullptr);
            if (ret < 0 && ret != -ETIME && ret != -EINTR && ret != -EBUSY && ret != -EAGAIN) {
                drain();
                return false;
            }

            drain();
            return true;
        }

        static void wake_all() {
            if (!ring_live.load(std::memory_order_acquire))
                return;
            auto& self = get_instance();
            if (!self.ring_initialized || self.wakeup_eventfd < 0)
                return;
            uint64_t val = 1;
            ssize_t r = write(self.wakeup_eventfd, &val, sizeof(val));
            (void)r;
        }

        static void post_connect(native_worker_handle* handle, int hSocket, const sockaddr* pAddr, socklen_t addrLen) {
            handle->request_data.opcode = operations::connect;
            handle->request_data.fd = hSocket;
            handle->request_data.addr_target.addr = pAddr;
            handle->request_data.addr_target.len = addrLen;
            sumbmit(handle, hSocket);
        }

        static void post_fast_connect(native_worker_handle* handle, int hSocket, const sockaddr* pAddr, socklen_t addrLen, void* buffer, uint32_t buffer_len) {
            handle->request_data.opcode = operations::fast_connect;
            handle->request_data.fd = hSocket;
            handle->request_data.addr_target.addr = pAddr;
            handle->request_data.addr_target.len = addrLen;
            handle->request_data.b.buf = buffer;
            handle->request_data.b.len = buffer_len;
            sumbmit(handle, hSocket);
        }

        static void post_recv(native_worker_handle* handle, int hSocket, void* pBuffer, uint32_t nBuffer, int32_t flags) {
            handle->request_data.opcode = operations::recv;
            handle->request_data.fd = hSocket;
            handle->request_data.b.buf = pBuffer;
            handle->request_data.b.len = nBuffer;
            handle->request_data.flags = flags;
            handle->request_data.addr_recv.addr = nullptr;
            handle->request_data.addr_recv.len = 0;
            sumbmit(handle, hSocket);
        }

        static void post_send(native_worker_handle* handle, int hSocket, const void* pBuffer, uint32_t nBuffer, int32_t flags) {
            handle->request_data.opcode = operations::send;
            handle->request_data.fd = hSocket;
            handle->request_data.b.buf = pBuffer;
            handle->request_data.b.len = nBuffer;
            handle->request_data.flags = flags;
            sumbmit(handle, hSocket);
        }

        static void post_close(native_worker_handle* handle, int hFile) {
            handle->request_data.opcode = operations::close;
            handle->request_data.fd = hFile;
            sumbmit(handle, hFile);
        }

        static void post_accept(native_worker_handle* handle, int hSocket, sockaddr* pAddr, socklen_t* pAddrLen, int32_t flags) {
            handle->request_data.opcode = operations::accept;
            handle->request_data.fd = hSocket;
            handle->request_data.addr_recv.addr = pAddr;
            handle->request_data.addr_recv.len = pAddrLen;
            handle->request_data.flags = flags;
            sumbmit(handle, hSocket);
        }

        static void post_recvmsg(native_worker_handle* handle, int hSocket, msghdr* pMsg, int32_t flags) {
            handle->request_data.opcode = operations::recvmsg;
            handle->request_data.fd = hSocket;
            handle->request_data.pMsg = pMsg;
            handle->request_data.flags = flags;
            sumbmit(handle, hSocket);
        }

        static void post_sendmsg(native_worker_handle* handle, int hSocket, const msghdr* pMsg, int32_t flags) {
            handle->request_data.opcode = operations::sendmsg;
            handle->request_data.fd = hSocket;
            handle->request_data.pMsg = const_cast<msghdr*>(pMsg);
            handle->request_data.flags = flags;
            sumbmit(handle, hSocket);
        }

        static void post_sendfile(native_worker_handle* handle, int hSocket, int file_fd, int pipe_rfd, int pipe_wfd, uint32_t data_len, uint64_t offset) {
            handle->request_data.opcode = operations::sendfile;
            handle->request_data.fd = hSocket;
            handle->request_data.offset = offset;
            handle->request_data.splice_fds.file_fd = file_fd;
            handle->request_data.splice_fds.pipe_rfd = pipe_rfd;
            handle->request_data.splice_fds.pipe_wfd = pipe_wfd;
            handle->request_data.splice_fds.len = data_len;
            sumbmit(handle, hSocket);
        }

        static void post_sendv_file(native_worker_handle* handle, int hSocket, int file_fd, int pipe_rfd, int pipe_wfd, uint32_t data_len, uint64_t offset, const void* prefix, uint32_t prefix_len, const void* postfix, uint32_t postfix_len) {
            handle->request_data.opcode = operations::sendv_file;
            handle->request_data.fd = hSocket;
            handle->request_data.offset = offset;
            handle->request_data.splice_fds.file_fd = file_fd;
            handle->request_data.splice_fds.pipe_rfd = pipe_rfd;
            handle->request_data.splice_fds.pipe_wfd = pipe_wfd;
            handle->request_data.splice_fds.len = data_len;
            handle->request_data.send_file_v.prefix = prefix;
            handle->request_data.send_file_v.prefix_len = prefix_len;
            handle->request_data.send_file_v.postfix = postfix;
            handle->request_data.send_file_v.postfix_len = postfix_len;
            sumbmit(handle, hSocket);
        }

        static void post_read(native_worker_handle* handle, int hFile, void* pBuffer, uint32_t nBuffer, uint64_t offset) {
            handle->request_data.opcode = operations::read;
            handle->request_data.fd = hFile;
            handle->request_data.b.buf = pBuffer;
            handle->request_data.b.len = nBuffer;
            handle->request_data.offset = offset;
            sumbmit(handle, hFile);
        }

        static void post_write(native_worker_handle* handle, int hFile, const void* pBuffer, uint32_t nBuffer, uint64_t offset) {
            handle->request_data.opcode = operations::write;
            handle->request_data.fd = hFile;
            handle->request_data.b.buf = pBuffer;
            handle->request_data.b.len = nBuffer;
            handle->request_data.offset = offset;
            sumbmit(handle, hFile);
        }

        static void post_readv(native_worker_handle* handle, int hSocket, struct iovec* iovs, uint32_t iovcnt, int32_t flags) {
            handle->request_data.opcode = operations::readv;
            handle->request_data.fd = hSocket;
            handle->request_data.offset = 0;
            handle->request_data.vector.iovs = iovs;
            handle->request_data.vector.iovcnt = iovcnt;
            handle->request_data.flags = flags;
            sumbmit(handle, hSocket);
        }

        static void post_writev(native_worker_handle* handle, int hSocket, struct iovec* iovs, uint32_t iovcnt, int32_t flags) {
            handle->request_data.opcode = operations::writev;
            handle->request_data.fd = hSocket;
            handle->request_data.offset = 0;
            handle->request_data.vector.iovs = iovs;
            handle->request_data.vector.iovcnt = iovcnt;
            handle->request_data.flags = flags;
            sumbmit(handle, hSocket);
        }

        static void post_poll_add(native_worker_handle* handle, int fd, short events) {
            handle->request_data.opcode = operations::poll_add;
            handle->request_data.fd = fd;
            handle->request_data.mask = events;
            sumbmit(handle, fd);
        }

        static bool await_cancel_fd(int /*hIn*/) {
            return false; // TODO: implement io_uring async cancel
        }

        static bool await_cancel_fd_all(int /*hIn*/) {
            return false; // TODO: implement io_uring async cancel
        }
    };
}

#endif /* SRC_TASKS_UTIL_NATIVE_WORKERS_SINGLETON_LINUX */
