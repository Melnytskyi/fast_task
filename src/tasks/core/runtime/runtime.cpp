// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <tasks/_internal.hpp>

#if PLATFORM_WINDOWS
    #define NOMINMAX
    #include <Windows.h>
    #include <locale>
    #include <vector>
#elif PLATFORM_LINUX
    #include <fstream>
    #include <iostream>
#endif

namespace fast_task {
    executors_local*& _get_loc() noexcept {
        static thread_local executors_local* loc;
        return loc;
    }

    NOINLINE executors_local* get_loc() noexcept {
        return _get_loc();
    }

    void set_loc(executors_local* loc) noexcept {
        _get_loc() = loc;
    }

    NOINLINE allocators_local_t& get_alloc_loc() noexcept {
        static thread_local allocators_local_t loc;
        return loc;
    }

    scheduler_runtime glob;

    bool alloc_globals_alive = true;

    namespace {
        std::atomic<bool> alloc_globals_alive_atomic{true};
    }

    allocators_local_t::allocators_local_t() = default;

    void allocators_local_t::drain_all() {
        if (!alloc_globals_alive_atomic.load(std::memory_order_acquire))
            return;
        auto& local = get_alloc_loc();
        local.task_cache.release();
        local.timing_cache.release();
    }

    void allocators_local_t::reset() {
        if (!alloc_globals_alive_atomic.load(std::memory_order_acquire)) {
            task_cache.free_list = nullptr;
            task_cache.free_count = 0;
            timing_cache.free_list = nullptr;
            timing_cache.free_count = 0;
            return;
        }
        task_cache.release();
        timing_cache.release();
    }

    allocators_local_t::~allocators_local_t() {
        reset();
    }

    pool_manager::pool_manager() noexcept {
        for (auto& slot : slots)
            slot.store(nullptr, std::memory_order_relaxed);
    }

    scheduler_runtime::scheduler_runtime() {
        auto* storage = ::new (static_cast<void*>(pools.global_storage_buffer)) global_pool_storage_type();
        storage->pool_index = global_pool_index;
        storage->is_global = true;
        storage->started = true;
        storage->explicitly_configured = false;
        storage->config.name = "global";
        storage->config.allow_driver_polling = true;
        pools.slots[global_pool_index].store(storage, std::memory_order_release);
    }

    scheduler_runtime::~scheduler_runtime() {
        allocators_local_t::drain_all();
        alloc_globals_alive_atomic.store(false, std::memory_order_release);
        alloc_globals_alive = false;

        if (auto* storage = pools.slots[global_pool_index].exchange(nullptr, std::memory_order_acq_rel))
            storage->ops.queue.destroy(*storage);
    }

#if PLATFORM_WINDOWS
    std::wstring s2ws(const std::string& str) {
        int len = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
        if (len == 0)
            return L"";

        std::vector<wchar_t> wstr(len);
        MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &wstr[0], len);
        return std::wstring(wstr.begin(), wstr.end() - 1);
    }

    std::string ws2s(const std::wstring& wstr) {
        int len = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, NULL, 0, nullptr, nullptr);
        if (len == 0)
            return "";

        std::vector<char> str(len);
        WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, str.data(), len, nullptr, nullptr);
        return std::string(str.begin(), str.end() - 1);
    }

    bool _set_name_thread_dbg(const std::string& name, unsigned long thread_id) {
        std::wstring wname = s2ws(name);
        HANDLE thread = OpenThread(THREAD_SET_LIMITED_INFORMATION, false, thread_id);
        if (!thread)
            return false;
        bool result = SUCCEEDED(SetThreadDescription(thread, wname.c_str()));
        CloseHandle(thread);
        return result;
    }

    bool _set_name_thread_dbg(const std::string& name) {
        std::wstring wname = s2ws(name);
        return SUCCEEDED(SetThreadDescription(GetCurrentThread(), wname.c_str()));
    }

    std::string _get_name_thread_dbg(unsigned long thread_id) {
        HANDLE thread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, false, thread_id);
        if (!thread)
            return "";
        WCHAR* res;
        if (SUCCEEDED(GetThreadDescription(thread, &res))) {
            std::string result = ws2s(res);
            LocalFree(res);
            CloseHandle(thread);
            return result;
        } else {
            CloseHandle(thread);
            return "";
        }
    }

    unsigned long _thread_id() {
        return GetCurrentThreadId();
    }

    bool is_debugger_attached() {
        return IsDebuggerPresent();
    }

#elif PLATFORM_LINUX
    bool _set_name_thread_dbg(const std::string& name) {
        if (name.size() > 15)
            return false;
        return pthread_setname_np(pthread_self(), name.c_str()) == 0;
    }

    bool _set_name_thread_dbg(const std::string& name, unsigned long id) {
        if (name.size() > 15)
            return false;
        return pthread_setname_np(id, name.c_str()) == 0;
    }

    std::string _get_name_thread_dbg(unsigned long thread_id) {
        char name[16];
        if (pthread_getname_np(pthread_t(thread_id), name, 16) != 0)
            return "";
        return name;
    }

    unsigned long _thread_id() {
        return pthread_self();
    }

    bool is_debugger_attached() {
        std::ifstream status_file("/proc/self/status");
        if (!status_file.is_open())
            return false;
        std::string line;
        while (std::getline(status_file, line))
            if (line.rfind("TracerPid:", 0) == 0)
                return std::stoi(line.substr(10)) != 0;
        return false;
    }
#endif
}
