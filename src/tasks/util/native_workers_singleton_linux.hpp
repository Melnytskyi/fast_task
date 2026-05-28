
// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)
#ifndef SRC_TASKS_UTIL_NATIVE_WORKERS_SINGLETON_LINUX
#define SRC_TASKS_UTIL_NATIVE_WORKERS_SINGLETON_LINUX
#include <bitset>
#include <chrono>
#include <concurrentqueue/moodycamel/concurrentqueue.h>
#include <cstring>
#include <liburing.h>
#include <list>
#include <shared.hpp>
#include <threading.hpp>
#include <vector>

#include <fcntl.h>
#include <poll.h>
#include <sys/eventfd.h>
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
        struct io_shard {
            io_uring ring;
            moodycamel::ConcurrentQueue<native_worker_handle*> queue;
            int wakeup_eventfd;
            fast_task::thread dispatcher_thread;
            alignas(64) std::atomic<bool> is_sleeping{false};

            io_shard() : wakeup_eventfd(-1) {}

            ~io_shard() {
                if (wakeup_eventfd > 0)
                    close(wakeup_eventfd);
                io_uring_queue_exit(&ring);
            }
        };

        std::vector<std::unique_ptr<io_shard>> io_pool;
        std::bitset<IORING_OP_LAST> probe_ops;

        native_workers_singleton() {
            auto* probe = io_uring_get_probe();
            for (int i = 0; i < probe->ops_len && i < IORING_OP_LAST; ++i) {
                if (probe->ops[i].flags & IO_URING_OP_SUPPORTED)
                    probe_ops.set(i);
            }
            io_uring_free_probe(probe);
            auto size = std::max<unsigned int>(fast_task::thread::hardware_concurrency(), 1);
            io_pool.reserve(size);

            for (unsigned int i = 0; i < size; i++) {
                io_pool.push_back(std::make_unique<io_shard>());
                auto& shard = *io_pool.back();
                shard.wakeup_eventfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);

                struct io_uring_params params;
                std::memset(&params, 0, sizeof(params));
                if (io_uring_queue_init_params(1024, &shard.ring, &params) < 0) {
                    assert(false && "io_uring_queue_init_params failed with the error");
                    std::terminate();
                }

                shard.dispatcher_thread = fast_task::thread(dispatch, std::ref(shard));
            }
        }

        static void arm_wakeup(io_shard& shard) {
            io_uring_sqe* sqe = io_uring_get_sqe(&shard.ring);
            io_uring_prep_poll_add(sqe, shard.wakeup_eventfd, POLLIN);
            io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(1));
        }

        static void dispatch(io_shard& shard) {
            pthread_setname_np(pthread_self(), "native_dispatcher");
            native_worker_handle* handles[256];

            arm_wakeup(shard);

            while (true) {
                size_t count = shard.queue.try_dequeue_bulk(handles, 256);

                for (size_t i = 0; i < count; ++i) {
                    io_uring_sqe* sqe = io_uring_get_sqe(&shard.ring);
                    auto* h = handles[i];

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
                        sqe = io_uring_get_sqe(&shard.ring);
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
                        sqe = io_uring_get_sqe(&shard.ring);
                        io_uring_prep_splice(sqe, h->request_data.splice_fds.pipe_rfd, -1, h->request_data.fd, -1, h->request_data.splice_fds.len, SPLICE_F_MOVE);
                        break;
                    }
                    case operations::sendv_file: {
                        if (h->request_data.send_file_v.prefix_len > 0) {
                            io_uring_prep_send(sqe, h->request_data.fd, h->request_data.send_file_v.prefix, h->request_data.send_file_v.prefix_len, 0);
                            io_uring_sqe_set_data(sqe, nullptr);
                            sqe->flags |= IOSQE_IO_LINK;
                            sqe = io_uring_get_sqe(&shard.ring);
                        }
                        io_uring_prep_splice(sqe, h->request_data.splice_fds.file_fd, (int64_t)h->request_data.offset, h->request_data.splice_fds.pipe_wfd, -1, h->request_data.splice_fds.len, SPLICE_F_MOVE);
                        io_uring_sqe_set_data(sqe, nullptr);
                        sqe->flags |= IOSQE_IO_LINK;
                        sqe = io_uring_get_sqe(&shard.ring);
                        io_uring_prep_splice(sqe, h->request_data.splice_fds.pipe_rfd, -1, h->request_data.fd, -1, h->request_data.splice_fds.len, SPLICE_F_MOVE);
                        if (h->request_data.send_file_v.postfix_len > 0) {
                            io_uring_sqe_set_data(sqe, nullptr);
                            sqe->flags |= IOSQE_IO_LINK;
                            sqe = io_uring_get_sqe(&shard.ring);
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

                shard.is_sleeping.store(true, std::memory_order_release);
                io_uring_submit_and_wait(&shard.ring, 1);
                shard.is_sleeping.store(false, std::memory_order_acquire);

                io_uring_cqe* cqe;
                unsigned head;
                uint32_t cqe_count = 0;

                io_uring_for_each_cqe(&shard.ring, head, cqe) {
                    ++cqe_count;
                    auto user_data = reinterpret_cast<uintptr_t>(io_uring_cqe_get_data(cqe));

                    if (user_data == 1) {
                        uint64_t val;
                        read(shard.wakeup_eventfd, &val, sizeof(val));
                        arm_wakeup(shard);
                        continue;
                    }

                    auto handle = reinterpret_cast<native_worker_handle*>(user_data);
                    if (!handle || !handle->manager)
                        continue;

                    task::run([handle, res = cqe->res, flags = cqe->flags]() {
                        handle->manager->handle(handle, res, flags);
                    });
                }

                io_uring_cq_advance(&shard.ring, cqe_count);
            }
        }

        static native_workers_singleton& get_instance() {
            static native_workers_singleton instance;
            return instance;
        }

        io_shard& get_shard(int fd) noexcept {
            return *io_pool[static_cast<size_t>(fd >= 0 ? fd : 0) % io_pool.size()];
        }

        static void sumbmit(native_worker_handle* handle, int hFile) {
            auto& instance = get_instance();
            auto& shard = instance.get_shard(hFile);
            shard.queue.enqueue(handle);
            if (shard.is_sleeping.load(std::memory_order_relaxed)) {
                uint64_t val = 1;
                write(shard.wakeup_eventfd, &val, sizeof(val));
            }
        }

    public:
        ~native_workers_singleton() {
            for (auto& pool : io_pool)
                pool->dispatcher_thread.join();
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
