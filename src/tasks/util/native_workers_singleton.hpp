
// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#pragma once
#ifndef FAST_TASK_NATIVE_WORKERS_SINGLETON
    #define FAST_TASK_NATIVE_WORKERS_SINGLETON

    #include <chrono>
    #include <cstring>
    #include <list>
    #include <mutex>
    #include <shared.hpp>
    #include <thread>
    #include <vector>
    #ifdef _WIN64
        #define WIN32_LEAN_AND_MEAN
        #define NOMINMAX
        #include <Windows.h>

namespace fast_task::util {
    class FT_API_LOCAL native_worker_manager {
    public:
        virtual void handle(void* data, class native_worker_handle* overlapped, unsigned long dwBytesTransferred) = 0;
        virtual ~native_worker_manager() noexcept(false) = default;
    };

    class FT_API_LOCAL native_worker_handle {
        friend class native_workers_singleton;

    public:
        OVERLAPPED overlapped;

    private:
        native_worker_manager* manager;

    public:
        native_worker_handle(native_worker_manager* manager)
            : manager(manager) {
            SecureZeroMemory(&overlapped, sizeof(OVERLAPPED));
        }

        native_worker_handle() = delete;
        native_worker_handle(const native_worker_handle&) = delete;
        native_worker_handle(native_worker_handle&&) = delete;
        native_worker_handle& operator=(const native_worker_handle&) = delete;
        native_worker_handle& operator=(native_worker_handle&&) = delete;
    };

    class FT_API_LOCAL native_workers_singleton {
        static inline native_workers_singleton* instance = nullptr;
        static inline fast_task::mutex instance_mutex;
        std::shared_ptr<void> m_hCompletionPort;

        native_workers_singleton() {
            m_hCompletionPort.reset(CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0), CloseHandle);
            if (!m_hCompletionPort)
                throw std::runtime_error("CreateIoCompletionPort failed");
            fast_task::thread(&native_workers_singleton::dispatch, this).detach();
        }

        void dispatch() {
            SetThreadDescription(GetCurrentThread(), L"native_dispatcher");
            std::vector<OVERLAPPED_ENTRY> entries;
            entries.resize(std::min<size_t>(fast_task::thread::hardware_concurrency(), INT32_MAX));
            while (true) {
                ULONG entries_count = 0;
                auto status = GetQueuedCompletionStatusEx(m_hCompletionPort.get(), entries.data(), (ULONG)entries.size(), &entries_count, INFINITE, false);
                if (!status)
                    return;

                for (ULONG i = 0; i < entries_count; i++) {
                    task::run([entry = std::move(entries[i])]() {
                        auto overlap = ((native_worker_handle*)entry.lpOverlapped);
                        overlap->manager->handle(
                            (void*)entry.lpCompletionKey,
                            overlap,
                            entry.dwNumberOfBytesTransferred
                        );
                    });
                }
            }
        }

        bool _register_handle(HANDLE hFile, void* data) {
            if (!CreateIoCompletionPort(hFile, m_hCompletionPort.get(), (ULONG_PTR)data, 0)) {
                //"CreateIoCompletionPort failed with the error" (uint32_t)GetLastError()
                return false;
            }
            return true;
        }

        static native_workers_singleton& get_instance() {
            if (instance)
                return *instance;
            else {
                fast_task::lock_guard<fast_task::mutex> lock(instance_mutex);
                if (!instance)
                    instance = new native_workers_singleton();
                return *instance;
            }
        }

    public:
        ~native_workers_singleton() = default;

        static bool register_handle(HANDLE hFile, void* data) {
            return get_instance()._register_handle(hFile, data);
        }

        static bool post_work(native_worker_handle* overlapped, size_t completion_key, DWORD dwBytesTransferred = 0) {
            return PostQueuedCompletionStatus(get_instance().m_hCompletionPort.get(), dwBytesTransferred, completion_key, (OVERLAPPED*)overlapped);
        }
    };
}
    #else
        #include <bitset>
        #include <liburing.h>

namespace fast_task::util {
    class FT_API_LOCAL native_worker_manager {
    public:
        virtual void handle(class native_worker_handle* overlapped, io_uring_cqe* cqe) = 0;
        virtual ~native_worker_manager() noexcept(false) = default;
    };

    class FT_API_LOCAL native_worker_handle {
        friend class native_workers_singleton;

    private:
        native_worker_manager* manager;

    public:
        native_worker_handle(native_worker_manager* manager)
            : manager(manager) {}

        native_worker_handle() = delete;
        native_worker_handle(const native_worker_handle&) = delete;
        native_worker_handle(native_worker_handle&&) = delete;
        native_worker_handle& operator=(const native_worker_handle&) = delete;
        native_worker_handle& operator=(native_worker_handle&&) = delete;
    };

    //not consume resources if not used
    class FT_API_LOCAL native_workers_singleton {
        static inline native_workers_singleton* instance = nullptr;
        static inline fast_task::mutex instance_mutex;
        io_uring m_ring;
        unsigned cqe_count = 0;
        std::bitset<IORING_OP_LAST> probe_ops;

        native_workers_singleton() {
            struct io_uring_params params;
            std::memset(&params, 0, sizeof(params));

            if (int res = io_uring_queue_init_params(1024, &m_ring, &params); res < 0)
                throw std::runtime_error("io_uring_queue_init_params failed with the error");
            auto* probe = io_uring_get_probe_ring(&m_ring);
            for (int i = 0; i < probe->ops_len && i < IORING_OP_LAST; ++i) {
                if (probe->ops[i].flags & IO_URING_OP_SUPPORTED)
                    probe_ops.set(i);
            }
            io_uring_free_probe(probe);
            fast_task::thread(&native_workers_singleton::dispatch, this).detach();
        }

        std::pair<uint32_t, uint32_t> proceed_hill_climb([[maybe_unused]] double sample_seconds) {
            return {1, 1};
        }

        void dispatch() {
            pthread_setname_np(pthread_self(), "native_dispatcher");
            while (true) {
                io_uring_submit_and_wait(&m_ring, 1);

                io_uring_cqe* cqe;
                unsigned head;

                io_uring_for_each_cqe(&m_ring, head, cqe) {
                    ++cqe_count;
                    auto handle = static_cast<native_worker_handle*>(io_uring_cqe_get_data(cqe));
                    if (!handle) {
                        //"io_uring_wait_cqe returned undefined completion, skipping"
                        continue;
                    }
                    if (!handle->manager) {
                        //"io_uring_wait_cqe returned undefined undefined manager, skipping" handle
                        continue;
                    }
                    handle->manager->handle(handle, cqe);
                }

                io_uring_cq_advance(&m_ring, cqe_count);
                cqe_count = 0;
            }
        }

        static native_workers_singleton& get_instance() {
            if (instance)
                return *instance;
            else {
                fast_task::lock_guard<fast_task::mutex> lock(instance_mutex);
                if (!instance)
                    instance = new native_workers_singleton();
                return *instance;
            }
        }

        static auto get_sqe(native_workers_singleton& self) {
            auto* sqe = io_uring_get_sqe(&self.m_ring);
            if (sqe != nullptr) {
                return sqe;
            } else {
                io_uring_cq_advance(&self.m_ring, self.cqe_count);
                self.cqe_count = 0;
                sumbmit(self);
                sqe = io_uring_get_sqe(&self.m_ring);
                if (sqe != nullptr)
                    return sqe;
                throw std::bad_alloc();
            }
            return sqe;
        }

        static void sumbmit(native_workers_singleton& instance) {
            if (int res = io_uring_submit(&instance.m_ring); res < 0)
                throw std::runtime_error("io_uring_submit failed with the error: " + std::string(strerror(errno)));
        }

        class await_cancel : public native_worker_handle, native_worker_manager {
            bool success = false;
            task_mutex mutex;
            task_condition_variable awaiter;

        public:
            await_cancel()
                : native_worker_handle(this) {}

            ~await_cancel() noexcept(false) override = default;

            void handle(native_worker_handle* _, io_uring_cqe* cqe) override {
                fast_task::lock_guard<task_mutex> lock(mutex);
                success = cqe->res >= 0;
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

    public:
        ~native_workers_singleton() {
            io_uring_queue_exit(&m_ring);
        }

        static void post_readv(native_worker_handle* handle, int hFile, const iovec* pVec, uint32_t nVec, uint64_t offset) {
            auto& instance = get_instance();
            if (!instance.probe_ops.test(IORING_OP_READV))
                throw std::runtime_error("IORING_OP_READV not supported");
            io_uring_sqe* sqe = get_sqe(instance);
            io_uring_prep_readv(sqe, hFile, pVec, nVec, offset);
            io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(handle));
            sumbmit(instance);
        }

        static void post_readv2(native_worker_handle* handle, int hFile, const iovec* pVec, uint32_t nVec, uint64_t offset, int32_t flags) {
            auto& instance = get_instance();
            if (!instance.probe_ops.test(IORING_OP_READV))
                throw std::runtime_error("IORING_OP_READV not supported");
            io_uring_sqe* sqe = get_sqe(instance);
            io_uring_prep_readv2(sqe, hFile, pVec, nVec, offset, flags);
            io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(handle));
            sumbmit(instance);
        }

        static void post_writev(native_worker_handle* handle, int hFile, const iovec* pVec, uint32_t nVec, uint64_t offset) {
            auto& instance = get_instance();
            if (!instance.probe_ops.test(IORING_OP_WRITEV))
                throw std::runtime_error("IORING_OP_WRITEV not supported");
            io_uring_sqe* sqe = get_sqe(instance);
            io_uring_prep_writev(sqe, hFile, pVec, nVec, offset);
            io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(handle));
            sumbmit(instance);
        }

        static void post_writev2(native_worker_handle* handle, int hFile, const iovec* pVec, uint32_t nVec, uint64_t offset, int32_t flags) {
            auto& instance = get_instance();
            if (!instance.probe_ops.test(IORING_OP_WRITEV))
                throw std::runtime_error("IORING_OP_WRITEV not supported");
            io_uring_sqe* sqe = get_sqe(instance);
            io_uring_prep_writev2(sqe, hFile, pVec, nVec, offset, flags);
            io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(handle));
            sumbmit(instance);
        }

        static void post_read(native_worker_handle* handle, int hFile, void* pBuffer, uint32_t nBuffer, uint64_t offset) {
            auto& instance = get_instance();
            if (!instance.probe_ops.test(IORING_OP_READ))
                throw std::runtime_error("IORING_OP_READ not supported");
            io_uring_sqe* sqe = get_sqe(instance);
            io_uring_prep_read(sqe, hFile, pBuffer, nBuffer, offset);
            io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(handle));
            sumbmit(instance);
        }

        static void post_write(native_worker_handle* handle, int hFile, const void* pBuffer, uint32_t nBuffer, uint64_t offset) {
            auto& instance = get_instance();
            if (!instance.probe_ops.test(IORING_OP_WRITE))
                throw std::runtime_error("IORING_OP_WRITE not supported");
            io_uring_sqe* sqe = get_sqe(instance);
            io_uring_prep_write(sqe, hFile, pBuffer, nBuffer, offset);
            io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(handle));
            sumbmit(instance);
        }

        static void post_read_fixed(native_worker_handle* handle, int hFile, void* pBuffer, uint32_t nBuffer, uint64_t offset, int32_t buf_index) {
            auto& instance = get_instance();
            if (!instance.probe_ops.test(IORING_OP_READ_FIXED))
                throw std::runtime_error("IORING_OP_READ_FIXED not supported");
            io_uring_sqe* sqe = get_sqe(instance);
            io_uring_prep_read_fixed(sqe, hFile, pBuffer, nBuffer, offset, buf_index);
            io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(handle));
            sumbmit(instance);
        }

        static void post_write_fixed(native_worker_handle* handle, int hFile, const void* pBuffer, uint32_t nBuffer, uint64_t offset, int32_t buf_index) {
            auto& instance = get_instance();
            if (!instance.probe_ops.test(IORING_OP_WRITE_FIXED))
                throw std::runtime_error("IORING_OP_WRITE_FIXED not supported");
            io_uring_sqe* sqe = get_sqe(instance);
            io_uring_prep_write_fixed(sqe, hFile, pBuffer, nBuffer, offset, buf_index);
            io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(handle));
            sumbmit(instance);
        }

        static void post_fsync(native_worker_handle* handle, int hFile, int32_t flags) {
            auto& instance = get_instance();
            if (!instance.probe_ops.test(IORING_OP_FSYNC))
                throw std::runtime_error("IORING_OP_FSYNC not supported");
            io_uring_sqe* sqe = get_sqe(instance);
            io_uring_prep_fsync(sqe, hFile, flags);
            io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(handle));
            sumbmit(instance);
        }

        static void post_fsync_range(native_worker_handle* handle, int hFile, uint64_t offset, uint64_t nbytes, int32_t flags) {
            auto& instance = get_instance();
            if (!instance.probe_ops.test(IORING_OP_FSYNC))
                throw std::runtime_error("IORING_OP_FSYNC not supported");
            io_uring_sqe* sqe = get_sqe(instance);
            io_uring_prep_rw(IORING_OP_SYNC_FILE_RANGE, sqe, hFile, nullptr, offset, nbytes);
            sqe->sync_range_flags = flags;
            io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(handle));
            sumbmit(instance);
        }

        static void post_recvmsg(native_worker_handle* handle, int hSocket, msghdr* pMsg, int32_t flags) {
            auto& instance = get_instance();
            if (!instance.probe_ops.test(IORING_OP_RECVMSG))
                throw std::runtime_error("IORING_OP_RECVMSG not supported");
            io_uring_sqe* sqe = get_sqe(instance);
            io_uring_prep_recvmsg(sqe, hSocket, pMsg, flags);
            io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(handle));
            sumbmit(instance);
        }

        static void post_sendmsg(native_worker_handle* handle, int hSocket, const msghdr* pMsg, int32_t flags) {
            auto& instance = get_instance();
            if (!instance.probe_ops.test(IORING_OP_SENDMSG))
                throw std::runtime_error("IORING_OP_SENDMSG not supported");
            io_uring_sqe* sqe = get_sqe(instance);
            io_uring_prep_sendmsg(sqe, hSocket, pMsg, flags);
            io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(handle));
            sumbmit(instance);
        }

        static void post_recv(native_worker_handle* handle, int hSocket, void* pBuffer, uint32_t nBuffer, int32_t flags) {
            auto& instance = get_instance();
            if (!instance.probe_ops.test(IORING_OP_RECV))
                throw std::runtime_error("IORING_OP_RECV not supported");
            io_uring_sqe* sqe = get_sqe(instance);
            io_uring_prep_recv(sqe, hSocket, pBuffer, nBuffer, flags);
            io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(handle));
            sumbmit(instance);
        }

        static void post_recvfrom([[maybe_unused]] native_worker_handle* handle, [[maybe_unused]] int hSocket, [[maybe_unused]] const void* pBuffer, [[maybe_unused]] uint32_t nBuffer, [[maybe_unused]] int32_t flags, [[maybe_unused]] sockaddr* addr, [[maybe_unused]] socklen_t* addr_len) {
            throw std::runtime_error("IORING_OP_RECVFROM not supported");
        }

        static void post_send(native_worker_handle* handle, int hSocket, const void* pBuffer, uint32_t nBuffer, int32_t flags) {
            auto& instance = get_instance();
            if (!instance.probe_ops.test(IORING_OP_SEND))
                throw std::runtime_error("IORING_OP_SEND not supported");
            io_uring_sqe* sqe = get_sqe(instance);
            io_uring_prep_send(sqe, hSocket, pBuffer, nBuffer, flags);
            io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(handle));
            sumbmit(instance);
        }

        static void post_sendto([[maybe_unused]] native_worker_handle* handle, [[maybe_unused]] int hSocket, [[maybe_unused]] const void* pBuffer, [[maybe_unused]] uint32_t nBuffer, [[maybe_unused]] int32_t flags, [[maybe_unused]] sockaddr* addr, [[maybe_unused]] socklen_t addr_len) {
            throw std::runtime_error("IORING_OP_SENDTO not supported");
        }

        static void post_pool(native_worker_handle* handle, int hSocket, short mask) {
            auto& instance = get_instance();
            if (!instance.probe_ops.test(IORING_OP_POLL_ADD))
                throw std::runtime_error("IORING_OP_POLL_ADD not supported");
            io_uring_sqe* sqe = get_sqe(instance);
            io_uring_prep_poll_add(sqe, hSocket, mask);
            io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(handle));
            sumbmit(instance);
        }

        static void post_yield(native_worker_handle* handle) {
            auto& instance = get_instance();
            if (!instance.probe_ops.test(IORING_OP_NOP))
                throw std::runtime_error("IORING_OP_NOP not supported");
            io_uring_sqe* sqe = get_sqe(instance);
            io_uring_prep_nop(sqe);
            io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(handle));
            sumbmit(instance);
        }

        static void post_accept(native_worker_handle* handle, int hSocket, sockaddr* pAddr, socklen_t* pAddrLen, int32_t flags) {
            auto& instance = get_instance();
            if (!instance.probe_ops.test(IORING_OP_ACCEPT))
                throw std::runtime_error("IORING_OP_ACCEPT not supported");
            io_uring_sqe* sqe = get_sqe(instance);
            io_uring_prep_accept(sqe, hSocket, pAddr, pAddrLen, flags);
            io_uring_sqe_set_flags(sqe, flags);
            io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(handle));
            sumbmit(instance);
        }

        static void post_connect(native_worker_handle* handle, int hSocket, const sockaddr* pAddr, socklen_t addrLen) {
            auto& instance = get_instance();
            if (!instance.probe_ops.test(IORING_OP_CONNECT))
                throw std::runtime_error("IORING_OP_CONNECT not supported");
            io_uring_sqe* sqe = get_sqe(instance);
            io_uring_prep_connect(sqe, hSocket, pAddr, addrLen);
            io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(handle));
            sumbmit(instance);
        }

        static void post_shutdown(native_worker_handle* handle, int hSocket, int how) {
            auto& instance = get_instance();
            if (!instance.probe_ops.test(IORING_OP_SHUTDOWN))
                throw std::runtime_error("IORING_OP_SHUTDOWN not supported");
            io_uring_sqe* sqe = get_sqe(instance);
            io_uring_prep_shutdown(sqe, hSocket, how);
            io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(handle));
            sumbmit(instance);
        }

        static void post_close(native_worker_handle* handle, int hSocket) {
            auto& instance = get_instance();
            if (!instance.probe_ops.test(IORING_OP_CLOSE))
                throw std::runtime_error("IORING_OP_CLOSE not supported");
            io_uring_sqe* sqe = get_sqe(instance);
            io_uring_prep_close(sqe, hSocket);
            io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(handle));
            sumbmit(instance);
        }

        static void post_timeout(native_worker_handle* handle, __kernel_timespec* pTimeSpec) {
            auto& instance = get_instance();
            if (!instance.probe_ops.test(IORING_OP_TIMEOUT))
                throw std::runtime_error("IORING_OP_TIMEOUT not supported");
            io_uring_sqe* sqe = get_sqe(instance);
            io_uring_prep_timeout(sqe, pTimeSpec, 0, 0);
            io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(handle));
            sumbmit(instance);
        }

        static void post_openat(native_worker_handle* handle, int hDir, const char* pPath, int flags, mode_t mode) {
            auto& instance = get_instance();
            if (!instance.probe_ops.test(IORING_OP_OPENAT))
                throw std::runtime_error("IORING_OP_OPENAT not supported");
            io_uring_sqe* sqe = get_sqe(instance);
            io_uring_prep_openat(sqe, hDir, pPath, flags, mode);
            io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(handle));
            sumbmit(instance);
        }

        static void post_statx(native_worker_handle* handle, int hDir, const char* pPath, int flags, unsigned int mask, struct statx* pStatxbuf) {
            auto& instance = get_instance();
            if (!instance.probe_ops.test(IORING_OP_STATX))
                throw std::runtime_error("IORING_OP_STATX not supported");
            io_uring_sqe* sqe = get_sqe(instance);
            io_uring_prep_statx(sqe, hDir, pPath, flags, mask, pStatxbuf);
            io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(handle));
            sumbmit(instance);
        }

        static void post_splice(native_worker_handle* handle, int hIn, loff_t pOffIn, int hOut, loff_t pOffOut, size_t nBytes, unsigned int flags) {
            auto& instance = get_instance();
            if (!instance.probe_ops.test(IORING_OP_SPLICE))
                throw std::runtime_error("IORING_OP_SPLICE not supported");
            io_uring_sqe* sqe = get_sqe(instance);
            io_uring_prep_splice(sqe, hIn, pOffIn, hOut, pOffOut, nBytes, flags);
            io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(handle));
            sumbmit(instance);
        }

        static void post_tee(native_worker_handle* handle, int hIn, int hOut, size_t nBytes, unsigned int flags) {
            auto& instance = get_instance();
            if (!instance.probe_ops.test(IORING_OP_TEE))
                throw std::runtime_error("IORING_OP_TEE not supported");
            io_uring_sqe* sqe = get_sqe(instance);
            io_uring_prep_tee(sqe, hIn, hOut, nBytes, flags);
            io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(handle));
            sumbmit(instance);
        }

        static void post_renameat(native_worker_handle* handle, int hOldDir, const char* pOldPath, int hNewDir, const char* pNewPath, unsigned int flags) {
            auto& instance = get_instance();
            if (!instance.probe_ops.test(IORING_OP_RENAMEAT))
                throw std::runtime_error("IORING_OP_RENAMEAT not supported");
            io_uring_sqe* sqe = get_sqe(instance);
            io_uring_prep_renameat(sqe, hOldDir, pOldPath, hNewDir, pNewPath, flags);
            io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(handle));
            sumbmit(instance);
        }

        static void post_mkdirat(native_worker_handle* handle, int hDir, const char* pPath, mode_t mode) {
            auto& instance = get_instance();
            if (!instance.probe_ops.test(IORING_OP_MKDIRAT))
                throw std::runtime_error("IORING_OP_MKDIRAT not supported");
            io_uring_sqe* sqe = get_sqe(instance);
            io_uring_prep_mkdirat(sqe, hDir, pPath, mode);
            io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(handle));
            sumbmit(instance);
        }

        static void post_symlinkat(native_worker_handle* handle, const char* pPath, int hDir, const char* pLink) {
            auto& instance = get_instance();
            if (!instance.probe_ops.test(IORING_OP_SYMLINKAT))
                throw std::runtime_error("IORING_OP_SYMLINKAT not supported");
            io_uring_sqe* sqe = get_sqe(instance);
            io_uring_prep_symlinkat(sqe, pPath, hDir, pLink);
            io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(handle));
            sumbmit(instance);
        }

        static void post_linkat(native_worker_handle* handle, int hOldDir, const char* pOldPath, int hNewDir, const char* pNewPath, int flags) {
            auto& instance = get_instance();
            if (!instance.probe_ops.test(IORING_OP_LINKAT))
                throw std::runtime_error("IORING_OP_LINKAT not supported");
            io_uring_sqe* sqe = get_sqe(instance);
            io_uring_prep_linkat(sqe, hOldDir, pOldPath, hNewDir, pNewPath, flags);
            io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(handle));
            sumbmit(instance);
        }

        static void post_unlinkat(native_worker_handle* handle, int hDir, const char* pPath, int flags) {
            auto& instance = get_instance();
            if (!instance.probe_ops.test(IORING_OP_UNLINKAT))
                throw std::runtime_error("IORING_OP_UNLINKAT not supported");
            io_uring_sqe* sqe = get_sqe(instance);
            io_uring_prep_unlinkat(sqe, hDir, pPath, flags);
            io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(handle));
            sumbmit(instance);
        }

        static void post_fallocate(native_worker_handle* handle, int hFile, int mode, off_t pOffset, off_t nBytes) {
            auto& instance = get_instance();
            if (!instance.probe_ops.test(IORING_OP_FALLOCATE))
                throw std::runtime_error("IORING_OP_FALLOCATE not supported");
            io_uring_sqe* sqe = get_sqe(instance);
            io_uring_prep_fallocate(sqe, hFile, mode, pOffset, nBytes);
            io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(handle));
            sumbmit(instance);
        }

        static void post_cancel(native_worker_handle* handle) {
            auto& instance = get_instance();
            if (!instance.probe_ops.test(IORING_OP_ASYNC_CANCEL))
                throw std::runtime_error("IORING_OP_ASYNC_CANCEL not supported");
            io_uring_sqe* sqe = get_sqe(instance);
            io_uring_prep_cancel(sqe, handle, 0);
            sumbmit(instance);
        }

        static void post_cancel_all(native_worker_handle* handle) {
            auto& instance = get_instance();
            if (!instance.probe_ops.test(IORING_OP_ASYNC_CANCEL))
                throw std::runtime_error("IORING_OP_ASYNC_CANCEL not supported");
            io_uring_sqe* sqe = get_sqe(instance);
            io_uring_prep_cancel(sqe, handle, IORING_ASYNC_CANCEL_ALL);
            sumbmit(instance);
        }

        static void post_cancel_fd(native_worker_handle* handle, int hIn) {
            auto& instance = get_instance();
            if (!instance.probe_ops.test(IORING_OP_ASYNC_CANCEL))
                throw std::runtime_error("IORING_OP_ASYNC_CANCEL not supported");
            io_uring_sqe* sqe = get_sqe(instance);
            io_uring_prep_cancel_fd(sqe, hIn, 0);
            io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(handle));
            sumbmit(instance);
        }

        static void post_cancel_fd_all(native_worker_handle* handle, int hIn) {
            auto& instance = get_instance();
            if (!instance.probe_ops.test(IORING_OP_ASYNC_CANCEL))
                throw std::runtime_error("IORING_OP_ASYNC_CANCEL not supported");
            io_uring_sqe* sqe = get_sqe(instance);
            io_uring_prep_cancel_fd(sqe, hIn, IORING_ASYNC_CANCEL_ALL);
            io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(handle));
            sumbmit(instance);
        }

        static bool await_cancel_fd(int hIn) {
            await_cancel cancel;
            return cancel.await_fd(hIn);
        }

        static bool await_cancel_fd_all(int hIn) {
            await_cancel cancel;
            return cancel.await_fd_all(hIn);
        }

        static std::pair<uint32_t, uint32_t> hill_climb_proceed(std::chrono::high_resolution_clock::duration sample_time) {
            fast_task::lock_guard<fast_task::mutex> lock(instance_mutex);
            if (!instance)
                return {0, 0};
            else
                return instance->proceed_hill_climb(std::chrono::duration<double>(sample_time).count());
        }
    };
}
    #endif
#endif
