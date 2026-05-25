
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

namespace fast_task::util {
    class FT_API_LOCAL native_worker_manager {
    public:
        virtual void handle(class native_worker_handle* overlapped, int32_t res, uint32_t flags) = 0;
        virtual ~native_worker_manager() noexcept(false) = default;
    };

    class FT_API_LOCAL native_worker_handle {
        friend class native_workers_singleton;
        native_worker_manager* manager;

        struct {
            uint8_t opcode = 0;
            int fd = 0;
            uint64_t offset = 0;

            union {
                struct {
                    const iovec* iov;
                    uint32_t iovcnt;
                } v;

                struct {
                    void* buf = nullptr;
                    uint32_t len = 0;
                    int32_t buf_index = 0;
                } b;

                struct {
                    const char* pPath;
                    mode_t mode;
                } f_o;

                msghdr* pMsg;
                uint64_t range;
                short mask;
                int how;
                __kernel_timespec* timeout;
            };

            union {
                struct {
                    sockaddr* addr = nullptr;
                    socklen_t* len = nullptr;
                } addr_recv;

                struct {
                    sockaddr* addr;
                    socklen_t* len;
                } addr_target;

                statx* pStatxbuf;
                uint64_t user_data;
            };

            int32_t flags = 0;
        } request_data;

    public:
        native_worker_handle(native_worker_manager* manager)
            : manager(manager){};
        

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

            ~io_shard() {
                sizeof(io_shard);
                if (wakeup_eventfd > 0)
                    close(wakeup_eventfd);
                io_uring_queue_exit(&ring);
            }
        };

        std::vector<io_shard> io_pool;
        std::bitset<IORING_OP_LAST> probe_ops;

        native_workers_singleton() {
            auto* probe = io_uring_get_probe();
            for (int i = 0; i < probe->ops_len && i < IORING_OP_LAST; ++i) {
                if (probe->ops[i].flags & IO_URING_OP_SUPPORTED)
                    probe_ops.set(i);
            }
            io_uring_free_probe(probe);
            auto size = std::max<unsigned int>(fast_task::thread::hardware_concurrency(), 1);

            for (unsigned int i = 0; i < size; i++) {
                auto& shard = io_pool.emplace_back();
                shard.wakeup_eventfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);

                struct io_uring_params params;
                std::memset(&params, 0, sizeof(params));
                if (io_uring_queue_init_params(1024, &shard.ring, &params) < 0) {
                    assert(false && "io_uring_queue_init_params failed with the error");
                    std::terminate();
                }

                shard.dispatcher_thread = fast_task::thread(dispatch, std::ref(shard));
                shard.dispatcher_thread.detach();
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
                    case IORING_OP_READV:
                        io_uring_prep_readv(sqe, h->request_data.fd, h->request_data.v.iov, h->request_data.v.iovcnt, h->request_data.offset);
                        break;
                    case IORING_OP_READV2:
                        io_uring_prep_readv2(sqe, h->request_data.fd, h->request_data.v.iov, h->request_data.v.iovcnt, h->request_data.offset, h->request_data.flags);
                        break;
                    case IORING_OP_WRITEV:
                        io_uring_prep_writev(sqe, h->request_data.fd, h->request_data.v.iov, h->request_data.v.iovcnt, h->request_data.offset);
                        break;
                    case IORING_OP_WRITEV2:
                        io_uring_prep_writev2(sqe, h->request_data.fd, h->request_data.v.iov, h->request_data.v.iovcnt, h->request_data.offset, h->request_data.flags);
                        break;
                    case IORING_OP_READ:
                        io_uring_prep_read(sqe, h->request_data.fd, h->request_data.b.buf, h->request_data.b.len, h->request_data.offset);
                        break;
                    case IORING_OP_WRITE:
                        io_uring_prep_write(sqe, h->request_data.fd, h->request_data.b.buf, h->request_data.b.len, h->request_data.offset);
                        break;
                    case IORING_OP_READ_FIXED:
                        io_uring_prep_read_fixed(sqe, h->request_data.fd, h->request_data.b.buf, h->request_data.b.len, h->request_data.offset, h->request_data.b.buf_index);
                        break;
                    case IORING_OP_WRITE_FIXED:
                        io_uring_prep_write_fixed(sqe, h->request_data.fd, h->request_data.b.buf, h->request_data.b.len, h->request_data.offset, h->request_data.b.buf_index);
                        break;
                    case IORING_OP_FSYNC:
                        io_uring_prep_fsync(sqe, h->request_data.fd, h->request_data.flags);
                        break;
                    case IORING_OP_SYNC_FILE_RANGE:
                        io_uring_prep_sync_file_range(sqe, h->request_data.fd, h->request_data.offset, h->request_data.range, h->request_data.flags);
                        break;
                    case IORING_OP_RECVMSG:
                        io_uring_prep_recvmsg(sqe, h->request_data.fd, h->request_data.pMsg, h->request_data.flags);
                        break;
                    case IORING_OP_SENDMSG:
                        io_uring_prep_sendmsg(sqe, h->request_data.fd, h->request_data.pMsg, h->request_data.flags);
                        break;
                    case IORING_OP_RECV:
                        io_uring_prep_recv(sqe, h->request_data.fd, h->request_data.b.buf, h->request_data.b.len, h->request_data.flags);
                        break;
                    case IORING_OP_RECVFROM:
                        io_uring_prep_recvfrom(sqe, h->request_data.fd, h->request_data.b.buf, h->request_data.b.len, h->request_data.flags, h->request_data.addr_recv.addr, h->request_data.addr_recv.len);
                        break;
                    case IORING_OP_SEND:
                        io_uring_prep_send(sqe, h->request_data.fd, h->request_data.b.buf, h->request_data.b.len, h->request_data.flags);
                        break;
                    case IORING_OP_SENDTO:
                        io_uring_prep_sendto(sqe, h->request_data.fd, h->request_data.b.buf, h->request_data.b.len, h->request_data.flags, h->request_data.addr_target.addr, h->request_data.addr_target.len);
                        break;
                    case IORING_OP_NOP:
                        io_uring_prep_nop(sqe);
                        break;
                    case IORING_OP_ACCEPT:
                        io_uring_prep_accept(sqe, h->request_data.fd, h->request_data.addr_recv.addr, h->request_data.addr_recv.len, h->request_data.flags);
                        break;
                    case IORING_OP_CONNECT:
                        io_uring_prep_connect(sqe, h->request_data.fd, h->request_data.addr_target.addr, h->request_data.addr_target.len);
                        break;
                    case IORING_OP_SHUTDOWN:
                        io_uring_prep_shutdown(sqe, h->request_data.fd, h->request_data.flags);
                        break;
                    case IORING_OP_CLOSE:
                        io_uring_prep_close(sqe, h->request_data.fd);
                        break;
                    case IORING_OP_TIMEOUT:
                        io_uring_prep_timeout(sqe, h->request_data.timeout, h->request_data.flags);
                        break;
                    case IORING_OP_OPENAT:
                        io_uring_prep_openat(sqe, h->request_data.f_o.fd, h->request_data.f_o.pPath, h->request_data.flags, h->request_data.f_o.mode);
                        break;
                    case IORING_OP_STATX:
                        io_uring_prep_statx(sqe, h->request_data.f_o.fd, h->request_data.f_o.pPath, h->request_data.flags, h->request_data.mask, h->request_data.pStatxbuf);
                        break;
                    case IORING_ASYNC_CANCEL:
                        io_uring_prep_cancel(sqe, (void*)(intptr_t)h->request_data.fd, h->request_data.flags);
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

        class await_cancel : public native_worker_handle, native_worker_manager {
            bool success = false;
            task_mutex mutex;
            task_condition_variable awaiter;

        public:
            await_cancel()
                : native_worker_handle(this) {}

            ~await_cancel() noexcept(false) override = default;

            void handle(native_worker_handle* _, int32_t res, uint32_t flags) override {
                fast_task::lock_guard<task_mutex> lock(mutex);
                success = res >= 0;
                awaiter.notify_all();
            }

            bool await_fd(int handle) {
                fast_task::mutex_unify unify(mutex);
                fast_task::unique_lock lock(unify);
                post_cancel_fd(this, handle);
                awaiter.wait(lock);
                return success;
            }

            bool await_fd_all(int handle) {
                fast_task::mutex_unify unify(mutex);
                fast_task::unique_lock lock(unify);
                post_cancel_fd_all(this, handle);
                awaiter.wait(lock);
                return success;
            }
        };

        static void sumbmit(native_worker_handle* handle, int hFile) {
            auto& instance = get_instance();
            if (!instance.probe_ops.test(handle->request_data.opcode))
                throw std::runtime_error("The opcode is not supported");

            size_t shard_index = handle % instance.io_pool.size();
            auto& shard = instance.io_pool[shard_index];
            auto& shard = get_shard(hFile);
            shard.queue.enqueue(handle);
            if (shard.is_sleeping.load(std::memory_order_relaxed)) {
                uint64_t val = 1;
                write(shard.wakeup_eventfd, &val, sizeof(val));
            }
        }

    public:
        ~native_workers_singleton() {
            io_uring_queue_exit(&m_ring);
        }

        static void post_readv(native_worker_handle* handle, int hFile, const iovec* pVec, uint32_t nVec, uint64_t offset) {
            handle->request_data.opcode = IORING_OP_READV;
            handle->request_data.fd = hFile;
            handle->request_data.v.iov = pVec;
            handle->request_data.v.iovcnt = nVec;
            handle->request_data.offset = offset;
            sumbmit(handle, hFile);
        }

        static void post_readv2(native_worker_handle* handle, int hFile, const iovec* pVec, uint32_t nVec, uint64_t offset, int32_t flags) {
            handle->request_data.opcode = IORING_OP_READV2;
            handle->request_data.fd = hFile;
            handle->request_data.v.iov = pVec;
            handle->request_data.v.iovcnt = nVec;
            handle->request_data.offset = offset;
            handle->request_data.flags = flags;
            sumbmit(handle, hFile);
        }

        static void post_writev(native_worker_handle* handle, int hFile, const iovec* pVec, uint32_t nVec, uint64_t offset) {
            handle->request_data.opcode = IORING_OP_WRITEV;
            handle->request_data.fd = hFile;
            handle->request_data.v.iov = pVec;
            handle->request_data.v.iovcnt = nVec;
            handle->request_data.offset = offset;
            handle->request_data.flags = flags;
            sumbmit(handle, hFile);
        }

        static void post_writev2(native_worker_handle* handle, int hFile, const iovec* pVec, uint32_t nVec, uint64_t offset, int32_t flags) {
            handle->request_data.opcode = IORING_OP_WRITEV2;
            handle->request_data.fd = hFile;
            handle->request_data.v.iov = pVec;
            handle->request_data.v.len = nVec;
            handle->request_data.offset = offset;
            handle->request_data.flags = flags;
            sumbmit(handle, hFile);
        }

        static void post_read(native_worker_handle* handle, int hFile, void* pBuffer, uint32_t nBuffer, uint64_t offset) {
            handle->request_data.opcode = IORING_OP_READ;
            handle->request_data.fd = hFile;
            handle->request_data.b.pBuffer = pBuffer;
            handle->request_data.b.len = nBuffer;
            handle->request_data.offset = offset;
            sumbmit(handle, hFile);
        }

        static void post_write(native_worker_handle* handle, int hFile, const void* pBuffer, uint32_t nBuffer, uint64_t offset) {
            handle->request_data.opcode = IORING_OP_WRITE;
            handle->request_data.fd = hFile;
            handle->request_data.b.pBuffer = pBuffer;
            handle->request_data.b.len = nBuffer;
            handle->request_data.offset = offset;
            sumbmit(handle, hFile);
        }

        static void post_read_fixed(native_worker_handle* handle, int hFile, void* pBuffer, uint32_t nBuffer, uint64_t offset, int32_t buf_index) {
            handle->request_data.opcode = IORING_OP_READ_FIXED;
            handle->request_data.fd = hFile;
            handle->request_data.b.pBuffer = pBuffer;
            handle->request_data.b.len = nBuffer;
            handle->request_data.b.buf_index = buf_index;
            handle->request_data.offset = offset;
            sumbmit(handle, hFile);
        }

        static void post_write_fixed(native_worker_handle* handle, int hFile, const void* pBuffer, uint32_t nBuffer, uint64_t offset, int32_t buf_index) {
            handle->request_data.opcode = IORING_OP_WRITE_FIXED;
            handle->request_data.fd = hFile;
            handle->request_data.b.pBuffer = pBuffer;
            handle->request_data.b.len = nBuffer;
            handle->request_data.b.buf_index = buf_index;
            handle->request_data.offset = offset;
            sumbmit(handle, hFile);
        }

        static void post_fsync(native_worker_handle* handle, int hFile, int32_t flags) {
            handle->request_data.opcode = IORING_OP_FSYNC;
            handle->request_data.fd = hFile;
            handle->request_data.flags = flags;
            sumbmit(handle, hFile);
        }

        static void post_fsync_range(native_worker_handle* handle, int hFile, uint64_t offset, uint64_t nbytes, int32_t flags) {
            handle->request_data.opcode = IORING_OP_SYNC_FILE_RANGE;
            handle->request_data.fd = hFile;
            handle->request_data.offset = offset;
            handle->request_data.range = nbytes;
            handle->request_data.flags = flags;
            sumbmit(handle, hFile);
        }

        static void post_recvmsg(native_worker_handle* handle, int hSocket, msghdr* pMsg, int32_t flags) {
            handle->request_data.opcode = IORING_OP_RECVMSG;
            handle->request_data.fd = hSocket;
            handle->request_data.pMsg = pMsg;
            handle->request_data.flags = flags;
            sumbmit(handle, hSocket);
        }

        static void post_sendmsg(native_worker_handle* handle, int hSocket, const msghdr* pMsg, int32_t flags) {
            handle->request_data.opcode = IORING_OP_SENDMSG;
            handle->request_data.fd = hSocket;
            handle->request_data.pMsg = pMsg;
            handle->request_data.flags = flags;
            sumbmit(handle, hSocket);
        }

        static void post_recv(native_worker_handle* handle, int hSocket, void* pBuffer, uint32_t nBuffer, int32_t flags) {
            handle->request_data.opcode = IORING_OP_RECV;
            handle->request_data.fd = hSocket;
            handle->request_data.b.pBuffer = pBuffer;
            handle->request_data.b.len = nBuffer;
            handle->request_data.flags = flags;
            sumbmit(handle, hSocket);
        }

        static void post_recvfrom(native_worker_handle* handle, int hSocket, const void* pBuffer, uint32_t nBuffer, int32_t flags, sockaddr* addr, socklen_t* addr_len) {
            handle->request_data.opcode = IORING_OP_RECVFROM;
            handle->request_data.fd = hSocket;
            handle->request_data.b.pBuffer = pBuffer;
            handle->request_data.b.len = nBuffer;
            handle->request_data.addr_recv.addr = addr;
            handle->request_data.addr_recv.len = addr_len;
            handle->request_data.flags = flags;
            sumbmit(handle, hSocket);
        }

        static void post_send(native_worker_handle* handle, int hSocket, const void* pBuffer, uint32_t nBuffer, int32_t flags) {
            handle->request_data.opcode = IORING_OP_SEND;
            handle->request_data.fd = hSocket;
            handle->request_data.b.pBuffer = pBuffer;
            handle->request_data.b.len = nBuffer;
            handle->request_data.flags = flags;
            sumbmit(handle, hSocket);
        }

        static void post_sendto(native_worker_handle* handle, int hSocket, const void* pBuffer, uint32_t nBuffer, int32_t flags, sockaddr* addr, socklen_t addr_len) {
            handle->request_data.opcode = IORING_OP_SENDTO;
            handle->request_data.fd = hSocket;
            handle->request_data.b.pBuffer = pBuffer;
            handle->request_data.b.len = nBuffer;
            handle->request_data.addr_target.addr = addr;
            handle->request_data.addr_target.len = addr_len;
            handle->request_data.flags = flags;
            sumbmit(handle, hSocket);
        }

        static void post_yield(native_worker_handle* handle) {
            handle->request_data.opcode = IORING_OP_NOP;
            sumbmit(handle, 0);
        }

        static void post_accept(native_worker_handle* handle, int hSocket, sockaddr* pAddr, socklen_t* pAddrLen, int32_t flags) {
            handle->request_data.opcode = IORING_OP_ACCEPT;
            handle->request_data.fd = hSocket;
            handle->request_data.addr_recv.addr = pAddr;
            handle->request_data.addr_recv.len = pAddrLen;
            handle->request_data.flags = flags;
            sumbmit(handle, hSocket);
        }

        static void post_connect(native_worker_handle* handle, int hSocket, const sockaddr* pAddr, socklen_t addrLen) {
            handle->request_data.opcode = IORING_OP_CONNECT;
            handle->request_data.fd = hSocket;
            handle->request_data.addr_target.addr = pAddr;
            handle->request_data.addr_target.len = addrLen;
            sumbmit(handle, hSocket);
        }

        static void post_shutdown(native_worker_handle* handle, int hSocket, int how) {
            handle->request_data.opcode = IORING_OP_SHUTDOWN;
            handle->request_data.fd = hSocket;
            handle->request_data.how = how;
            sumbmit(handle, hSocket);
        }

        static void post_close(native_worker_handle* handle, int hSocket) {
            handle->request_data.opcode = IORING_OP_CLOSE;
            handle->request_data.fd = hSocket;
            sumbmit(handle, hSocket);
        }

        static void post_timeout(native_worker_handle* handle, __kernel_timespec* pTimeSpec) {
            handle->request_data.opcode = IORING_OP_TIMEOUT;
            handle->request_data.timeout = pTimeSpec;
            sumbmit(handle, 0);
        }

        static void post_openat(native_worker_handle* handle, int hDir, const char* pPath, int flags, mode_t mode) {
            handle->request_data.opcode = IORING_OP_OPENAT;
            handle->request_data.fd = hDir;
            handle->request_data.f_o.pPath = pPath;
            handle->request_data.f_o.mode = mode;
            handle->request_data.flags = flags;
            sumbmit(handle, hDir);
        }

        static void post_statx(native_worker_handle* handle, int hDir, const char* pPath, int flags, unsigned int mask, struct statx* pStatxbuf) {
            handle->request_data.opcode = IORING_OP_STATX;
            handle->request_data.fd = hDir;
            handle->request_data.f_o.pPath = pPath;
            handle->request_data.mask = mode;
            handle->request_data.pStatxbuf = pStatxbuf;
            handle->request_data.flags = flags;
            sumbmit(handle, hDir);
        }

        //static void post_splice(native_worker_handle* handle, int hIn, loff_t pOffIn, int hOut, loff_t pOffOut, size_t nBytes, unsigned int flags) {
        //    auto& instance = get_instance();
        //    if (!instance.probe_ops.test(IORING_OP_SPLICE))
        //        throw std::runtime_error("IORING_OP_SPLICE not supported");
        //    io_uring_sqe* sqe = get_sqe(instance);
        //    io_uring_prep_splice(sqe, hIn, pOffIn, hOut, pOffOut, nBytes, flags);
        //    io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(handle));
        //    sumbmit(instance);
        //}
        //
        //static void post_tee(native_worker_handle* handle, int hIn, int hOut, size_t nBytes, unsigned int flags) {
        //    auto& instance = get_instance();
        //    if (!instance.probe_ops.test(IORING_OP_TEE))
        //        throw std::runtime_error("IORING_OP_TEE not supported");
        //    io_uring_sqe* sqe = get_sqe(instance);
        //    io_uring_prep_tee(sqe, hIn, hOut, nBytes, flags);
        //    io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(handle));
        //    sumbmit(instance);
        //}
        //
        //static void post_renameat(native_worker_handle* handle, int hOldDir, const char* pOldPath, int hNewDir, const char* pNewPath, unsigned int flags) {
        //    auto& instance = get_instance();
        //    if (!instance.probe_ops.test(IORING_OP_RENAMEAT))
        //        throw std::runtime_error("IORING_OP_RENAMEAT not supported");
        //    io_uring_sqe* sqe = get_sqe(instance);
        //    io_uring_prep_renameat(sqe, hOldDir, pOldPath, hNewDir, pNewPath, flags);
        //    io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(handle));
        //    sumbmit(instance);
        //}
        //
        //static void post_mkdirat(native_worker_handle* handle, int hDir, const char* pPath, mode_t mode) {
        //    auto& instance = get_instance();
        //    if (!instance.probe_ops.test(IORING_OP_MKDIRAT))
        //        throw std::runtime_error("IORING_OP_MKDIRAT not supported");
        //    io_uring_sqe* sqe = get_sqe(instance);
        //    io_uring_prep_mkdirat(sqe, hDir, pPath, mode);
        //    io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(handle));
        //    sumbmit(instance);
        //}
        //
        //static void post_symlinkat(native_worker_handle* handle, const char* pPath, int hDir, const char* pLink) {
        //    auto& instance = get_instance();
        //    if (!instance.probe_ops.test(IORING_OP_SYMLINKAT))
        //        throw std::runtime_error("IORING_OP_SYMLINKAT not supported");
        //    io_uring_sqe* sqe = get_sqe(instance);
        //    io_uring_prep_symlinkat(sqe, pPath, hDir, pLink);
        //    io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(handle));
        //    sumbmit(instance);
        //}
        //
        //static void post_linkat(native_worker_handle* handle, int hOldDir, const char* pOldPath, int hNewDir, const char* pNewPath, int flags) {
        //    auto& instance = get_instance();
        //    if (!instance.probe_ops.test(IORING_OP_LINKAT))
        //        throw std::runtime_error("IORING_OP_LINKAT not supported");
        //    io_uring_sqe* sqe = get_sqe(instance);
        //    io_uring_prep_linkat(sqe, hOldDir, pOldPath, hNewDir, pNewPath, flags);
        //    io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(handle));
        //    sumbmit(instance);
        //}
        //
        //static void post_unlinkat(native_worker_handle* handle, int hDir, const char* pPath, int flags) {
        //    auto& instance = get_instance();
        //    if (!instance.probe_ops.test(IORING_OP_UNLINKAT))
        //        throw std::runtime_error("IORING_OP_UNLINKAT not supported");
        //    io_uring_sqe* sqe = get_sqe(instance);
        //    io_uring_prep_unlinkat(sqe, hDir, pPath, flags);
        //    io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(handle));
        //    sumbmit(instance);
        //}
        //
        //static void post_fallocate(native_worker_handle* handle, int hFile, int mode, off_t pOffset, off_t nBytes) {
        //    auto& instance = get_instance();
        //    if (!instance.probe_ops.test(IORING_OP_FALLOCATE))
        //        throw std::runtime_error("IORING_OP_FALLOCATE not supported");
        //    io_uring_sqe* sqe = get_sqe(instance);
        //    io_uring_prep_fallocate(sqe, hFile, mode, pOffset, nBytes);
        //    io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(handle));
        //    sumbmit(instance);
        //}

        static void post_cancel(native_worker_handle* handle) {
            handle->request_data.opcode = IORING_ASYNC_CANCEL;
            handle->request_data.fd = hIn;
            handle->request_data.flags = 0;
            sumbmit(handle, hIn);
        }

        static void post_cancel_all(native_worker_handle* handle) {
            handle->request_data.opcode = IORING_ASYNC_CANCEL;
            handle->request_data.fd = hIn;
            handle->request_data.flags = IORING_ASYNC_CANCEL_ALL;
            sumbmit(handle, hIn);
        }

        static void post_cancel_fd(native_worker_handle* handle, int hIn) {
            handle->request_data.opcode = IORING_ASYNC_CANCEL;
            handle->request_data.fd = hIn;
            handle->request_data.flags = IORING_ASYNC_CANCEL_FD;
            sumbmit(handle, hIn);
        }

        static void post_cancel_fd_all(native_worker_handle* handle, int hIn) {
            handle->request_data.opcode = IORING_ASYNC_CANCEL;
            handle->request_data.fd = hIn;
            handle->request_data.flags = IORING_ASYNC_CANCEL_ALL | IORING_ASYNC_CANCEL_FD;
            sumbmit(handle, hIn);
        }

        static bool await_cancel_fd(int hIn) {
            await_cancel cancel;
            return cancel.await_fd(hIn);
        }

        static bool await_cancel_fd_all(int hIn) {
            await_cancel cancel;
            return cancel.await_fd_all(hIn);
        }
    };
}

#endif /* SRC_TASKS_UTIL_NATIVE_WORKERS_SINGLETON_LINUX */
