// Copyright Danyil Melnytskyi 2022-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <fast_task/native/thread.hpp>
#include <tasks/util/interrupt.hpp>
#include <cerrno>

#if _WIN32
    #include <tasks/util/cpu.hpp>

    #ifdef FT_INCLUDE_THREAD_INTERRUPT_CODE
extern "C" void thread_interrupter_asm_zmm();
extern "C" void thread_interrupter_asm_ymm();
extern "C" void thread_interrupter_asm_xmm();
extern "C" void thread_interrupter_asm_xmm_small();
extern "C" void thread_interrupter_asm();
void (*thread_interrupter_asm_ptr)() = []() {
    if (psnip_cpu_feature_check(PSNIP_CPU_FEATURE_X86_AVX512F))
        return thread_interrupter_asm_zmm;
    if (psnip_cpu_feature_check(PSNIP_CPU_FEATURE_X86_AVX))
        return thread_interrupter_asm_ymm;
    if (psnip_cpu_feature_check(PSNIP_CPU_FEATURE_X86_SSE2))
        return thread_interrupter_asm_xmm;
    return thread_interrupter_asm;
}();
    #endif

    #ifndef NOMINMAX
        #define NOMINMAX
    #endif
    #include <Windows.h>
    #include <process.h>

namespace fast_task::native {

    void thread::init_dat() {}

    namespace {
        bool apply_thread_affinity(HANDLE thread, std::span<const uint32_t> cpus);
        std::vector<uint32_t> read_thread_affinity(HANDLE thread);

        struct win32_thread_start_ctx {
            void (*function)(void*);
            void* arg;
        };

        unsigned __stdcall win32_thread_trampoline(void* raw) {
            std::unique_ptr<win32_thread_start_ctx> ctx(static_cast<win32_thread_start_ctx*>(raw));
            ctx->function(ctx->arg);
            return 0;
        }
    }

    void* thread::create(void (*function)(void*), void* arg, unsigned long& id, size_t stack_size, bool stack_reservation, const cpu_affinity* affinity, bool& affinity_applied, int& error_code) {
        error_code = 0;
        affinity_applied = true;
        interrupt_unsafe_region region;
        auto ctx = std::make_unique<win32_thread_start_ctx>(win32_thread_start_ctx{function, arg});
        void* handle = (void*)_beginthreadex(
            nullptr,
            (uint32_t)std::min<size_t>(stack_size, UINT32_MAX),
            &win32_thread_trampoline,
            ctx.get(),
            CREATE_SUSPENDED | (stack_reservation ? STACK_SIZE_PARAM_IS_A_RESERVATION : 0),
            (unsigned int*)&id
        );
        if (!handle) {
            error_code = errno;
            return nullptr;
        }
        ctx.release();
        if (affinity && !affinity->cpus.empty() && !apply_thread_affinity((HANDLE)handle, affinity->cpus))
            affinity_applied = false;
        ResumeThread(handle);
        return handle;
    }

    [[nodiscard]] unsigned int thread::hardware_concurrency() noexcept {
        interrupt_unsafe_region region;
        SYSTEM_INFO sysinfo;
        GetSystemInfo(&sysinfo);
        int numCPU = sysinfo.dwNumberOfProcessors;
        if (numCPU < 1)
            numCPU = 1;
        return (unsigned int)numCPU;
    }

    void thread::join() {
        if (_thread) {
            interrupt_unsafe_region region;
            WaitForSingleObject(_thread, INFINITE);
            CloseHandle(_thread);
            _thread = nullptr;
        }
    }

    void thread::detach() {
        if (_thread) {
            interrupt_unsafe_region region;
            CloseHandle(_thread);
            _thread = nullptr;
        }
    }

    bool thread::suspend() {
        return suspend(_id);
    }

    bool thread::resume() {
        return resume(_id);
    }

    void thread::insert_context(void (*inserted_context)(void*), void* arg) {
        insert_context(_id, inserted_context, arg);
    }

    struct HANDLE_CLOSER {
        HANDLE handle = nullptr;

        HANDLE_CLOSER(HANDLE handle)
            : handle(handle) {}

        ~HANDLE_CLOSER() {
            if (handle != nullptr) {
                interrupt_unsafe_region region;
                CloseHandle(handle);
            }
            handle = nullptr;
        }
    };

    namespace {
        bool apply_thread_affinity(HANDLE thread, std::span<const uint32_t> cpus) {
    #if defined(_WIN32_WINNT) && _WIN32_WINNT >= 0x0601
            GROUP_AFFINITY group{};
            group.Group = static_cast<WORD>(cpus.front() / 64);
            for (uint32_t cpu : cpus) {
                if (cpu / 64 != group.Group)
                    continue;
                group.Mask |= (KAFFINITY(1) << (cpu % 64));
            }
            if (group.Mask == 0)
                return false;
            return SetThreadGroupAffinity(thread, &group, nullptr) != 0;
    #else
            DWORD_PTR mask = 0;
            for (uint32_t cpu : cpus)
                if (cpu < 64)
                    mask |= (DWORD_PTR(1) << cpu);
            if (mask == 0)
                return false;
            return SetThreadAffinityMask(thread, mask) != 0;
    #endif
        }

        std::vector<uint32_t> read_thread_affinity(HANDLE thread) {
            std::vector<uint32_t> cpus;
    #if defined(_WIN32_WINNT) && _WIN32_WINNT >= 0x0601
            GROUP_AFFINITY group{};
            if (!GetThreadGroupAffinity(thread, &group))
                return cpus;
            for (int bit = 0; bit < 64; ++bit)
                if (group.Mask & (KAFFINITY(1) << bit))
                    cpus.push_back(static_cast<uint32_t>(group.Group) * 64 + static_cast<uint32_t>(bit));
    #else
            (void)thread;
    #endif
            return cpus;
        }
    }

    bool thread::suspend(id id) {
        interrupt_unsafe_region region;
        HANDLE_CLOSER thread_handle(OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, false, id._id));
        if (SuspendThread(thread_handle.handle) == DWORD(-1))
            return false;
        return true;
    }

    bool thread::resume(id id) {
        interrupt_unsafe_region region;
        HANDLE_CLOSER thread_handle(OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, false, id._id));
        if (ResumeThread(thread_handle.handle) == DWORD(-1))
            return false;
        return true;
    }

    bool thread::insert_context(id id, void (*inserted_context)(void*), void* arg) {
    #ifdef FT_INCLUDE_THREAD_INTERRUPT_CODE
        interrupt_unsafe_region region;
        HANDLE_CLOSER thread_handle(OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, false, id._id));
        if (SuspendThread(thread_handle.handle) == DWORD(-1))
            return false;

        CONTEXT context;
        context.ContextFlags = CONTEXT_CONTROL;
        if (GetThreadContext(thread_handle.handle, &context) == 0) {
            ResumeThread(thread_handle.handle);
            return false;
        }
        bool res = true;
        try {
            auto rsp = context.Rsp;
            rsp -= sizeof(DWORD64);
            *(DWORD64*)rsp = context.Rip; //return address
            rsp -= sizeof(DWORD64);
            *(DWORD64*)rsp = (DWORD64)inserted_context; //inserted_context
            rsp -= sizeof(DWORD64);
            *(DWORD64*)rsp = (DWORD64)arg; //arg
            context.Rsp = rsp;
            //set rip to trampoline
            context.Rip = (DWORD64)thread_interrupter_asm_ptr;
            res = SetThreadContext(thread_handle.handle, &context);
        } catch (...) {
        }
        ResumeThread(thread_handle.handle);
        return res;
    #else
        (void)id;
        (void)inserted_context;
        (void)arg;
        return false;
    #endif
    }

    bool thread::set_affinity(std::span<const uint32_t> cpus) {
        interrupt_unsafe_region region;
        if (!_thread || cpus.empty())
            return false;
        return apply_thread_affinity(static_cast<HANDLE>(_thread), cpus);
    }

    std::vector<uint32_t> thread::get_affinity() const {
        interrupt_unsafe_region region;
        if (!_thread)
            return {};
        return read_thread_affinity(static_cast<HANDLE>(_thread));
    }

    namespace this_thread {
        thread::id get_id() noexcept {
            interrupt_unsafe_region region;
            return thread::id(GetCurrentThreadId());
        }

        bool set_affinity(std::span<const uint32_t> cpus) {
            interrupt_unsafe_region region;
            if (cpus.empty())
                return false;
            return apply_thread_affinity(GetCurrentThread(), cpus);
        }

        std::vector<uint32_t> get_affinity() {
            interrupt_unsafe_region region;
            return read_thread_affinity(GetCurrentThread());
        }

        void yield() noexcept {
            interrupt_unsafe_region region;
            SwitchToThread();
        }

        void sleep_for(std::chrono::milliseconds ms) {
            if (ms.count() <= 0)
                return;
            interrupt_unsafe_region region;
            auto remaining = ms.count();
            while (remaining > 0) {
                const DWORD chunk = remaining > 0x7FFFFFFF ? 0x7FFFFFFF : static_cast<DWORD>(remaining);
                Sleep(chunk);
                remaining -= chunk;
            }
        }

        void sleep_until(fast_task::time_point time) {
            if (fast_task::is_no_deadline(time))
                return;
            interrupt_unsafe_region region;
            while (true) {
                const auto now = fast_task::clock::now();
                if (now >= time)
                    return;
                const auto ms = std::chrono::ceil<std::chrono::milliseconds>(time - now);
                const auto count = ms.count();
                const DWORD chunk = count > 0x7FFFFFFF ? 0x7FFFFFFF : (count <= 0 ? 1 : static_cast<DWORD>(count));
                Sleep(chunk);
            }
        }
    }
}
#else
    #include <pthread.h>
    #include <signal.h>
    #include <tasks/_internal.hpp>
    #include <ucontext.h>

namespace fast_task::native {
    void thread::init_dat() {
    }

    namespace {
        bool fill_cpu_set(std::span<const uint32_t> cpus, cpu_set_t& mask) {
            CPU_ZERO(&mask);
            bool any = false;
            for (uint32_t cpu : cpus) {
                if (cpu < static_cast<uint32_t>(CPU_SETSIZE)) {
                    CPU_SET(static_cast<int>(cpu), &mask);
                    any = true;
                }
            }
            return any;
        }

        std::vector<uint32_t> cpu_set_to_vector(const cpu_set_t& mask) {
            std::vector<uint32_t> cpus;
            for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu)
                if (CPU_ISSET(cpu, &mask))
                    cpus.push_back(static_cast<uint32_t>(cpu));
            return cpus;
        }

        struct posix_thread_start_ctx {
            void (*function)(void*);
            void* arg;
        };

        struct pthread_attr_guard {
            pthread_attr_t& attr;

            ~pthread_attr_guard() {
                pthread_attr_destroy(&attr);
            }
        };
    }

    extern "C" void* ft_posix_thread_trampoline(void* raw) {
        std::unique_ptr<posix_thread_start_ctx> ctx(static_cast<posix_thread_start_ctx*>(raw));
        ctx->function(ctx->arg);
        return nullptr;
    }

    void* thread::create(void (*function)(void*), void* arg, unsigned long& id, size_t stack_size, bool /*stack_reservation*/, const cpu_affinity* affinity, bool& affinity_applied, int& error_code) {
        interrupt_unsafe_region region;
        error_code = 0;
        affinity_applied = true;
        pthread_attr_t attr;
        if (int err = pthread_attr_init(&attr); err) {
            error_code = err;
            return nullptr;
        }
        pthread_attr_guard attr_guard{attr};
        if (int err = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE); err) {
            error_code = err;
            return nullptr;
        }
        if (stack_size > 0) {
            if (int err = pthread_attr_setstacksize(&attr, stack_size); err) {
                error_code = err;
                return nullptr;
            }
        }
        if (affinity && !affinity->cpus.empty()) {
            cpu_set_t mask;
            if (!fill_cpu_set(affinity->cpus, mask) ||
                pthread_attr_setaffinity_np(&attr, sizeof(mask), &mask) != 0)
                affinity_applied = false;
        }
        auto ctx = std::make_unique<posix_thread_start_ctx>(posix_thread_start_ctx{function, arg});
        pthread_t thread;
        if (int err = pthread_create(&thread, &attr, &ft_posix_thread_trampoline, ctx.get()); err) {
            error_code = err;
            return nullptr;
        }
        ctx.release();
        id = (unsigned long)thread;
        return (void*)thread;
    }

    [[nodiscard]] unsigned int thread::hardware_concurrency() noexcept {
        interrupt_unsafe_region region;
        return sysconf(_SC_NPROCESSORS_ONLN);
    }

    void thread::join() {
        interrupt_unsafe_region region;
        if (_thread) {
            if (int err = pthread_join((pthread_t)_thread, nullptr); err) {
                switch (err) {
                case EDEADLK:
                    throw std::logic_error("Thread::join() called on itself");
                case EINVAL:
                    throw std::logic_error("Thread::join() called on a non joinable/detachable thread");
                case ESRCH:
                    throw std::logic_error("Thread::join() called on a thread that does not exist or has already been joined/detached");
                default:
                    throw std::system_error(err, std::system_category());
                }
            }
            _thread = nullptr;
        }
    }

    void thread::detach() {
        interrupt_unsafe_region region;
        if (_thread) {
            if (int err = pthread_detach((pthread_t)_thread); err) {
                switch (err) {
                case EINVAL:
                    throw std::logic_error("Thread::detach() called on a non joinable/detachable thread");
                case ESRCH:
                    throw std::logic_error("Thread::detach() called on a thread that does not exist or has already been joined/detached");
                default:
                    throw std::system_error(err, std::system_category());
                }
            }
            _thread = nullptr;
        }
    }

    bool thread::suspend() {
        interrupt_unsafe_region region;
        return suspend(_id);
    }

    bool thread::resume() {
        interrupt_unsafe_region region;
        return resume(_id);
    }

    void thread::insert_context(void (*)(void*), void*) {
    }

    bool thread::suspend(id) {
        return false;
    }

    bool thread::resume(id) {
        return false;
    }

    bool thread::insert_context(id, void (*)(void*), void*) {
        return false;
    }

    bool thread::set_affinity(std::span<const uint32_t> cpus) {
        interrupt_unsafe_region region;
        if (!_thread || cpus.empty())
            return false;
        cpu_set_t mask;
        if (!fill_cpu_set(cpus, mask))
            return false;
        return pthread_setaffinity_np(reinterpret_cast<pthread_t>(_id), sizeof(mask), &mask) == 0;
    }

    std::vector<uint32_t> thread::get_affinity() const {
        interrupt_unsafe_region region;
        if (!_thread)
            return {};
        cpu_set_t mask;
        CPU_ZERO(&mask);
        if (pthread_getaffinity_np(reinterpret_cast<pthread_t>(_id), sizeof(mask), &mask) != 0)
            return {};
        return cpu_set_to_vector(mask);
    }

    namespace this_thread {
        thread::id get_id() noexcept {
            interrupt_unsafe_region region;
            return thread::id(pthread_self());
        }

        bool set_affinity(std::span<const uint32_t> cpus) {
            interrupt_unsafe_region region;
            if (cpus.empty())
                return false;
            cpu_set_t mask;
            if (!fill_cpu_set(cpus, mask))
                return false;
            return pthread_setaffinity_np(pthread_self(), sizeof(mask), &mask) == 0;
        }

        std::vector<uint32_t> get_affinity() {
            interrupt_unsafe_region region;
            cpu_set_t mask;
            CPU_ZERO(&mask);
            if (pthread_getaffinity_np(pthread_self(), sizeof(mask), &mask) != 0)
                return {};
            return cpu_set_to_vector(mask);
        }

        void yield() noexcept {
            interrupt_unsafe_region region;
            sched_yield();
        }

        void sleep_for(std::chrono::milliseconds ms) {
            if (ms.count() <= 0)
                return;
            interrupt_unsafe_region region;
            sleep_until(fast_task::deadline_after(ms));
        }

        void sleep_until(fast_task::time_point time) {
            if (fast_task::is_no_deadline(time))
                return;
            interrupt_unsafe_region region;
            while (true) {
                const auto now = fast_task::clock::now();
                if (now >= time)
                    return;
                const auto diff = time - now;
                const auto secs = std::chrono::duration_cast<std::chrono::seconds>(diff);
                const auto nsecs = std::chrono::duration_cast<std::chrono::nanoseconds>(diff - secs);
                timespec ts;
                ts.tv_sec = static_cast<time_t>(secs.count());
                ts.tv_nsec = static_cast<long>(nsecs.count());
                nanosleep(&ts, nullptr);
            }
        }
    }
}
#endif

namespace fast_task::native {
    [[nodiscard]] thread::id thread::get_id() const noexcept {
        return id(_id);
    }

    bool thread::id::operator==(const id& other) const noexcept {
        return _id == other._id;
    }

    bool thread::id::operator!=(const id& other) const noexcept {
        return _id != other._id;
    }

    bool thread::id::operator<(const id& other) const noexcept {
        return _id < other._id;
    }

    bool thread::id::operator<=(const id& other) const noexcept {
        return _id <= other._id;
    }

    bool thread::id::operator>(const id& other) const noexcept {
        return _id > other._id;
    }

    bool thread::id::operator>=(const id& other) const noexcept {
        return _id >= other._id;
    }

    thread::id::operator size_t() const noexcept {
        return (size_t)_id;
    }

    [[nodiscard]] bool thread::joinable() const noexcept {
        return _thread != nullptr;
    }
}
