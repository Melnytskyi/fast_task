
// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)
#ifndef SRC_TASKS_UTIL_NATIVE_WORKERS_SINGLETON_WIN
#define SRC_TASKS_UTIL_NATIVE_WORKERS_SINGLETON_WIN
#include <algorithm>
#include <chrono>
#include <cstring>
#include <fast_task/native/thread.hpp>
#include <fast_task/shared.hpp>
#include <list>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <type_traits>
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
        native_worker_manager* manager;

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

    static_assert(std::is_standard_layout_v<native_worker_handle>, "native_worker_handle must be standard-layout");

    class FT_API_LOCAL native_workers_singleton {
        static constexpr ULONG_PTR WAKEUP_KEY = 0;

        std::shared_ptr<void> m_hCompletionPort;
        std::vector<OVERLAPPED_ENTRY> m_entries;

        native_workers_singleton() {
                HANDLE hPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
            if (hPort == NULL)
                throw std::runtime_error("CreateIoCompletionPort failed");
            m_hCompletionPort.reset(hPort, CloseHandle);
            unsigned hw = fast_task::native::thread::hardware_concurrency();
            size_t entries_cap = std::max<size_t>(16, static_cast<size_t>(hw) * 2);
            m_entries.resize(std::min<size_t>(entries_cap, static_cast<size_t>(INT32_MAX)));
        }

        bool poll_once(int timeout_ms) {
            bool processed = false;
            DWORD wait_ms = timeout_ms < 0 ? INFINITE : static_cast<DWORD>(timeout_ms);
            for (;;) {
                ULONG entries_count = 0;
                auto status = GetQueuedCompletionStatusEx(
                    m_hCompletionPort.get(),
                    m_entries.data(),
                    static_cast<ULONG>(m_entries.size()),
                    &entries_count,
                    wait_ms,
                    false
                );
                if (!status || entries_count == 0)
                    break;

                    for (ULONG i = 0; i < entries_count; i++) {
                        auto& entry = m_entries[i];
                        if (entry.lpCompletionKey == WAKEUP_KEY && entry.lpOverlapped == nullptr)
                            continue;
                        auto overlap = reinterpret_cast<native_worker_handle*>(entry.lpOverlapped);
                        if (!overlap || !overlap->manager)
                            continue;
                        overlap->manager->handle(
                            reinterpret_cast<void*>(entry.lpCompletionKey),
                            overlap,
                            entry.dwNumberOfBytesTransferred
                        );
                        processed = true;
                    }

                    if (entries_count < m_entries.size())
                        break;
                    wait_ms = 0;
                }
            return processed;
        }

        void wake() {
            PostQueuedCompletionStatus(m_hCompletionPort.get(), 0, WAKEUP_KEY, nullptr);
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

        static bool has_ready_work() {
            return false;
        }

        static bool poll_all(int timeout_ms) {
            return get_instance().poll_once(timeout_ms);
        }

        static void wake_all() {
            get_instance().wake();
        }

        static bool register_handle(HANDLE hFile, void* data) {
            return get_instance()._register_handle(hFile, data);
        }

        static bool post_work(native_worker_handle* overlapped, size_t completion_key, DWORD dwBytesTransferred = 0) {
            return PostQueuedCompletionStatus(get_instance().m_hCompletionPort.get(), dwBytesTransferred, completion_key, (OVERLAPPED*)overlapped);
        }
    };
}

#endif /* SRC_TASKS_UTIL_NATIVE_WORKERS_SINGLETON_WIN */
