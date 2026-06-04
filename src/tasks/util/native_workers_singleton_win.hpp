
// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)
#ifndef SRC_TASKS_UTIL_NATIVE_WORKERS_SINGLETON_WIN
#define SRC_TASKS_UTIL_NATIVE_WORKERS_SINGLETON_WIN
#include <chrono>
#include <cstring>
#include <list>
#include <mutex>
#include <shared.hpp>
#include <thread>
#include <vector>
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
                    continue;
                for (ULONG i = 0; i < entries_count; i++) {
                    auto overlap = ((native_worker_handle*)entry.lpOverlapped);
                    overlap->manager->handle(
                        (void*)entry.lpCompletionKey,
                        overlap,
                        entry.dwNumberOfBytesTransferred
                    );
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
            static native_workers_singleton instance;
            return instance;
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

#endif /* SRC_TASKS_UTIL_NATIVE_WORKERS_SINGLETON_WIN */
