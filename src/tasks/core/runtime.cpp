// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)
//
// Runtime implementation: global scheduler state, allocator cache registry and
// process-wide debug helpers. Moved verbatim out of tasks/_internal.cpp by S0b
// (plans/pool-architecture.md §4); no behaviour changes.

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
    NOINLINE allocators_local_t& get_alloc_loc() noexcept {
        static thread_local allocators_local_t loc;
        return loc;
    }

    scheduler_runtime glob;

    bool alloc_globals_alive = true;

    namespace {
        // Registry of live thread-local allocator caches. Guarded by a spin
        // lock because it is touched from every thread that creates or destroys
        // an allocators_local_t.
        fast_task::native::spin_lock alloc_registry_lock;
        allocators_local_t* alloc_registry_head = nullptr;

        void alloc_registry_push(allocators_local_t* node) noexcept {
            std::lock_guard<fast_task::native::spin_lock> guard(alloc_registry_lock);
            node->registry_next = alloc_registry_head;
            alloc_registry_head = node;
        }

        void alloc_registry_remove(allocators_local_t* node) noexcept {
            std::lock_guard<fast_task::native::spin_lock> guard(alloc_registry_lock);
            allocators_local_t** link = &alloc_registry_head;
            while (*link) {
                if (*link == node) {
                    *link = node->registry_next;
                    node->registry_next = nullptr;
                    return;
                }
                link = &(*link)->registry_next;
            }
        }
    }

    allocators_local_t::allocators_local_t() {
        alloc_registry_push(this);
    }

    void allocators_local_t::drain_all() {
        std::lock_guard<fast_task::native::spin_lock> guard(alloc_registry_lock);
        for (auto* node = alloc_registry_head; node; node = node->registry_next) {
            node->task_cache.release();
            node->timing_cache.release();
        }
    }

    void allocators_local_t::reset() {
        // During static destruction a surviving thread may still run its
        // thread_local destructor. Returning the free lists would touch the
        // already-destroyed glob.gba / glob.timing_alloc, so drop them instead.
        if (!alloc_globals_alive) {
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
        alloc_registry_remove(this);
    }

    scheduler_runtime::scheduler_runtime() {
        for (auto& slot : pools)
            slot.store(nullptr, std::memory_order_relaxed);

        // The global pool lives in the reserved buffer, never on the heap, so
        // its address -- and every pointer derived from it -- is stable for the
        // whole process (plans/pool-architecture.md §2.2).
        auto* storage = ::new (static_cast<void*>(global_pool_storage)) default_pool_storage();
        storage->pool_index = global_pool_index;
        storage->is_global = true;
        storage->started = true;
        storage->explicitly_configured = false;
        storage->config.name = "global";
        storage->config.allow_driver_polling = true;
        // The global pool's registry view points at the runtime's 1024-slot
        // registry; the inline 64-slot entry stays unused.
        storage->registry = global_registry.view();
        pools[global_pool_index].store(storage, std::memory_order_release);
    }

    scheduler_runtime::~scheduler_runtime() {
        // Runs before the members (gba, timing_alloc) are destroyed. Return
        // every live thread-local free list to the global allocators first:
        // otherwise the arena destructor's "still used" assert fires for nodes
        // that are merely sitting in some thread's cache. Only after that is it
        // safe to tell later cache destructors to drop their lists.
        allocators_local_t::drain_all();
        alloc_globals_alive = false;

        if (auto* storage = pools[global_pool_index].exchange(nullptr, std::memory_order_acq_rel)) {
            // The buffer is reserved in this object, so only the objects inside
            // it are destroyed -- `deallocate` would be wrong here.
            storage->ops.destroy(*storage);
        }
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
        const CHAR def[] = " ";
        BOOL used = true;
        int len = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, NULL, 0, def, &used);
        if (len == 0)
            return "";

        std::vector<char> str(len);
        WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, str.data(), len, def, &used);
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
