
// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)
#ifndef SRC_TASKS_UTIL_NATIVE_WORKERS_SINGLETON_LINUX
#define SRC_TASKS_UTIL_NATIVE_WORKERS_SINGLETON_LINUX
#include <chrono>
#include <concurrentqueue/moodycamel/concurrentqueue.h>
#include <cstring>
#include <fast_task/native/thread.hpp>
#include <fast_task/shared.hpp>
#include <liburing.h>
#include <list>
#include <vector>

#include <fcntl.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/resource.h>
#include <unistd.h>

namespace fast_task::util {
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

        struct {
            operations opcode = operations::nop;
            int fd = 0;
            uint64_t offset = 0;

            union {
                struct {
                    const iovec* iov;
                    uint32_t iovcnt;
                } v;

                struct {
                    const void* buf;
                    uint32_t len;
                    int32_t buf_index;
                } b;

                struct {
                    const char* pPath;
                    mode_t mode;
                } f_o;

                struct {
                    int file_fd;
                    int pipe_rfd;
                    int pipe_wfd;
                    uint32_t len;
                } splice_fds;

                struct {
                    struct iovec* iovs;
                    uint32_t iovcnt;
                } vector;

                msghdr* pMsg;
                uint64_t range;
                short mask;
                int how;
                __kernel_timespec* timeout;
            };

            union {
                struct {
                    sockaddr* addr;
                    socklen_t* len;
                } addr_recv;

                struct {
                    const sockaddr* addr;
                    socklen_t len;
                } addr_target;

                struct {
                    const void* prefix;
                    uint32_t prefix_len;
                    const void* postfix;
                    uint32_t postfix_len;
                } send_file_v;

                struct statx* pStatxbuf;
                uint64_t user_data;
            };

            int32_t flags = 0;
        } request_data;

    public:
        native_worker_handle(native_worker_manager* manager)
            : manager(manager) {
            request_data.b.buf = nullptr;
            request_data.b.buf_index = 0;
            request_data.b.len = 0;
            request_data.addr_recv.addr = nullptr;
            request_data.addr_recv.len = nullptr;
        };

        native_worker_handle() = delete;
        native_worker_handle(const native_worker_handle&) = delete;
        native_worker_handle(native_worker_handle&&) = delete;
        native_worker_handle& operator=(const native_worker_handle&) = delete;
        native_worker_handle& operator=(native_worker_handle&&) = delete;
    };

    class FT_API_LOCAL native_workers_singleton {
        // A single ring driven by driver_context. There is no dispatcher thread
        // and therefore no reason to shard: the driver is the only consumer of
        // completions, so spreading submissions across N rings would only add
        // wake-up fan-out without adding parallelism.
        io_uring ring;
        moodycamel::ConcurrentQueue<native_worker_handle*> queue;
        int wakeup_eventfd = -1;

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
                // One ring now gets the whole budget instead of a 1/N slice.
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
                assert(false && "io_uring_queue_init_params failed");
                std::terminate();
            }

            // Arm directly on `this`: calling arm_wakeup() here would re-enter
            // get_instance() while the function-local static guard is still
            // held by this very constructor, deadlocking on __cxa_guard_acquire.
            arm_wakeup_on(*this);
        }

        static void arm_wakeup_on(native_workers_singleton& self) {
            io_uring_sqe* sqe = io_uring_get_sqe(&self.ring);
            if (!sqe) {
                io_uring_submit(&self.ring);
                sqe = io_uring_get_sqe(&self.ring);
            }
            if (!sqe)
                return;
            io_uring_prep_poll_add(sqe, self.wakeup_eventfd, POLLIN);
            io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(1));
        }

        static void arm_wakeup() {
            arm_wakeup_on(get_instance());
        }

        static void prepare_handle_sqe(native_worker_handle* h) {
            auto& self = get_instance();
            io_uring_sqe* sqe = io_uring_get_sqe(&self.ring);
            if (!sqe) {
                io_uring_submit(&self.ring);
                sqe = io_uring_get_sqe(&self.ring);
            }
            switch (h->request_data.opcode) {
            case operations::nop:
                io_uring_prep_nop(sqe);
                break;
            case operations::connect:
                io_uring_prep_connect(sqe, h->request_data.fd, h->request_data.addr_target.addr, h->request_data.addr_target.len);
                break;
            case operations::fast_connect:
                io_uring_prep_connect(sqe, h->request_data.fd, h->request_data.addr_target.addr, h->request_data.addr_target.len);
                io_uring_sqe_set_data(sqe, nullptr);
                sqe->flags |= IOSQE_IO_LINK;
                sqe = io_uring_get_sqe(&self.ring);
                io_uring_prep_recv(sqe, h->request_data.fd, const_cast<void*>(h->request_data.b.buf), h->request_data.b.len, 0);
                break;
            case operations::recv:
                io_uring_prep_recv(sqe, h->request_data.fd, const_cast<void*>(h->request_data.b.buf), h->request_data.b.len, h->request_data.flags);
                break;
            case operations::send:
                io_uring_prep_send(sqe, h->request_data.fd, h->request_data.b.buf, h->request_data.b.len, h->request_data.flags);
                break;
            case operations::close:
                io_uring_prep_close(sqe, h->request_data.fd);
                break;
            case operations::accept:
                io_uring_prep_accept(sqe, h->request_data.fd, h->request_data.addr_recv.addr, h->request_data.addr_recv.len, h->request_data.flags);
                break;
            case operations::recvmsg:
                io_uring_prep_recvmsg(sqe, h->request_data.fd, h->request_data.pMsg, h->request_data.flags);
                break;
            case operations::sendmsg:
                io_uring_prep_sendmsg(sqe, h->request_data.fd, h->request_data.pMsg, h->request_data.flags);
                break;
            case operations::sendfile: {
                io_uring_prep_splice(sqe, h->request_data.splice_fds.file_fd, (int64_t)h->request_data.offset, h->request_data.splice_fds.pipe_wfd, -1, h->request_data.splice_fds.len, SPLICE_F_MOVE);
                io_uring_sqe_set_data(sqe, nullptr);
                sqe->flags |= IOSQE_IO_LINK;
                sqe = io_uring_get_sqe(&self.ring);
                io_uring_prep_splice(sqe, h->request_data.splice_fds.pipe_rfd, -1, h->request_data.fd, -1, h->request_data.splice_fds.len, SPLICE_F_MOVE);
                break;
            }
            case operations::sendv_file: {
                if (h->request_data.send_file_v.prefix_len > 0) {
                    io_uring_prep_send(sqe, h->request_data.fd, h->request_data.send_file_v.prefix, h->request_data.send_file_v.prefix_len, 0);
                    io_uring_sqe_set_data(sqe, nullptr);
                    sqe->flags |= IOSQE_IO_LINK;
                    sqe = io_uring_get_sqe(&self.ring);
                }
                io_uring_prep_splice(sqe, h->request_data.splice_fds.file_fd, (int64_t)h->request_data.offset, h->request_data.splice_fds.pipe_wfd, -1, h->request_data.splice_fds.len, SPLICE_F_MOVE);
                io_uring_sqe_set_data(sqe, nullptr);
                sqe->flags |= IOSQE_IO_LINK;
                sqe = io_uring_get_sqe(&self.ring);
                io_uring_prep_splice(sqe, h->request_data.splice_fds.pipe_rfd, -1, h->request_data.fd, -1, h->request_data.splice_fds.len, SPLICE_F_MOVE);
                if (h->request_data.send_file_v.postfix_len > 0) {
                    io_uring_sqe_set_data(sqe, nullptr);
                    sqe->flags |= IOSQE_IO_LINK;
                    sqe = io_uring_get_sqe(&self.ring);
                    io_uring_prep_send(sqe, h->request_data.fd, h->request_data.send_file_v.postfix, h->request_data.send_file_v.postfix_len, 0);
                }
                break;
            }
            case operations::read:
                io_uring_prep_read(sqe, h->request_data.fd, const_cast<void*>(h->request_data.b.buf), h->request_data.b.len, h->request_data.offset);
                break;
            case operations::write:
                io_uring_prep_write(sqe, h->request_data.fd, h->request_data.b.buf, h->request_data.b.len, h->request_data.offset);
                break;
            case operations::readv:
                io_uring_prep_readv(sqe, h->request_data.fd, h->request_data.vector.iovs, h->request_data.vector.iovcnt, h->request_data.offset);
                break;
            case operations::writev:
                io_uring_prep_writev(sqe, h->request_data.fd, h->request_data.vector.iovs, h->request_data.vector.iovcnt, h->request_data.offset);
                break;
            case operations::poll_add:
                io_uring_prep_poll_add(sqe, h->request_data.fd, (uint32_t)(unsigned short)h->request_data.mask);
                break;
            default:
                break;
            }
            io_uring_sqe_set_data(sqe, h);
        }

        // Reap every completion currently queued on the ring and dispatch it to
        // the owning manager. Non-looping: the caller (driver_context) decides
        // how long to block and how often to call this.
        static void drain() {
            auto& self = get_instance();
            io_uring_cqe* cqe;
            unsigned head;
            uint32_t cqe_count = 0;

            io_uring_for_each_cqe(&self.ring, head, cqe) {
                ++cqe_count;
                auto user_data = reinterpret_cast<uintptr_t>(io_uring_cqe_get_data(cqe));

                if (user_data == 1) {
                    uint64_t val;
                    read(self.wakeup_eventfd, &val, sizeof(val));
                    // Re-arm unconditionally: there is no dispatcher thread to
                    // stop, and dropping the poll would make wake() a no-op.
                    arm_wakeup();
                    continue;
                }

                auto handle = reinterpret_cast<native_worker_handle*>(user_data);
                if (!handle || !handle->manager)
                    continue;

                handle->manager->handle(handle, cqe->res, cqe->flags);
            }

            io_uring_cq_advance(&self.ring, cqe_count);
        }

        // Move every queued request into the submission queue, then submit.
        static void flush() {
            auto& self = get_instance();
            native_worker_handle* handles[256];
            size_t count;
            while ((count = self.queue.try_dequeue_bulk(handles, 256)) > 0)
                for (size_t i = 0; i < count; ++i)
                    prepare_handle_sqe(handles[i]);
            io_uring_submit(&self.ring);
        }

        static native_workers_singleton& get_instance() {
            static native_workers_singleton instance;
            return instance;
        }

        static void sumbmit(native_worker_handle* handle, int /*hFile*/) {
            auto& self = get_instance();
            self.queue.enqueue(handle);
            // Always poke the eventfd. With no dispatcher thread the driver is
            // either inside poll_all() (and will see the completion) or not
            // parked at all, so there is no "asleep" state to test for.
            uint64_t val = 1;
            write(self.wakeup_eventfd, &val, sizeof(val));
        }

    public:
        ~native_workers_singleton() {
            io_uring_queue_exit(&ring);
            if (wakeup_eventfd >= 0)
                close(wakeup_eventfd);
        }

        // Submit pending work and block up to timeout_ms for at least one
        // completion, then drain. A negative timeout blocks indefinitely.
        // Returns true if any completion was processed.
        static bool poll_all(int timeout_ms) {
            auto& self = get_instance();
            flush();

            io_uring_cqe* cqe = nullptr;
            __kernel_timespec ts{};
            __kernel_timespec* ts_ptr = nullptr;
            if (timeout_ms >= 0) {
                ts.tv_sec = timeout_ms / 1000;
                ts.tv_nsec = static_cast<long long>(timeout_ms % 1000) * 1000000LL;
                ts_ptr = &ts;
            }

            int ret = io_uring_submit_and_wait_timeout(&self.ring, &cqe, 1, ts_ptr, nullptr);
            if (ret < 0 && ret != -ETIME && ret != -EINTR)
                return false;

            drain();
            return true;
        }

        // Wake a driver blocked in poll_all(). Safe from any thread.
        static void wake_all() {
            auto& self = get_instance();
            uint64_t val = 1;
            write(self.wakeup_eventfd, &val, sizeof(val));
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
            handle->request_data.vector.iovs = iovs;
            handle->request_data.vector.iovcnt = iovcnt;
            handle->request_data.flags = flags;
            sumbmit(handle, hSocket);
        }

        static void post_writev(native_worker_handle* handle, int hSocket, struct iovec* iovs, uint32_t iovcnt, int32_t flags) {
            handle->request_data.opcode = operations::writev;
            handle->request_data.fd = hSocket;
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
