// Copyright Danyil Melnytskyi 2022-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <native/thread.hpp>
#include <tasks/util/interrupt.hpp>

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

    #define NOMINMAX
    #include <Windows.h>
    #include <process.h>

namespace fast_task::native {

    void thread::init_dat() {}

    void* thread::create(void (*function)(void*), void* arg, unsigned long& id, size_t stack_size, bool stack_reservation, int& error_code) {
        error_code = 0;
        interrupt_unsafe_region region;
        void* handle = (void*)_beginthreadex(nullptr, (uint32_t)std::min<size_t>(stack_size, UINT32_MAX), reinterpret_cast<_beginthreadex_proc_type>(reinterpret_cast<void*>(function)), arg, CREATE_SUSPENDED | (stack_reservation ? STACK_SIZE_PARAM_IS_A_RESERVATION : 0), (unsigned int*)&id);
        if (!handle) {
            error_code = GetLastError();
            return nullptr;
        }
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
        return false;
    #endif
    }

    namespace this_thread {
        thread::id get_id() noexcept {
            interrupt_unsafe_region region;
            return thread::id(GetCurrentThreadId());
        }

        void yield() noexcept {
            interrupt_unsafe_region region;
            SwitchToThread();
        }

        void sleep_for(std::chrono::milliseconds ms) {
            interrupt_unsafe_region region;
            Sleep((DWORD)ms.count());
        }

        void sleep_until(std::chrono::high_resolution_clock::time_point time) {
            interrupt_unsafe_region region;
            auto diff = time - std::chrono::high_resolution_clock::now();
            while (diff.count() > 0) {
                std::chrono::milliseconds ms = std::chrono::duration_cast<std::chrono::milliseconds>(diff);
                Sleep((DWORD)ms.count());
                diff = time - std::chrono::high_resolution_clock::now();
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

    void* thread::create(void (*function)(void*), void* arg, unsigned long& id, size_t stack_size, bool stack_reservation, int& error_code) {
        interrupt_unsafe_region region;
        error_code = 0;
        pthread_attr_t attr;
        if (int err = pthread_attr_init(&attr); err) {
            error_code = err;
            return nullptr;
        }
        if (int err = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE); err) {
            error_code = err;
            return nullptr;
        }
        if (stack_reservation) {
            if (int err = pthread_attr_setstacksize(&attr, stack_size); err) {
                error_code = err;
                return nullptr;
            }
        }
        pthread_t thread;
        if (int err = pthread_create(&thread, &attr, reinterpret_cast<void* (*)(void*)>(function), arg); err) {
            error_code = err;
            return nullptr;
        }
        if (int err = pthread_attr_destroy(&attr); err) {
            error_code = err;
            return nullptr;
        }
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

    namespace this_thread {
        thread::id get_id() noexcept {
            interrupt_unsafe_region region;
            return thread::id(pthread_self());
        }

        void yield() noexcept {
            interrupt_unsafe_region region;
            sched_yield();
        }

        void sleep_for(std::chrono::milliseconds ms) {
            interrupt_unsafe_region region;
            sleep_until(std::chrono::high_resolution_clock::now() + ms);
        }

        void sleep_until(std::chrono::high_resolution_clock::time_point time) {
            interrupt_unsafe_region region;
            auto diff = time - std::chrono::high_resolution_clock::now();
            while (diff.count() > 0) {
                timespec ts;
                ts.tv_sec = diff.count() / 1000000000;
                ts.tv_nsec = diff.count() % 1000000000;
                nanosleep(&ts, nullptr);
                diff = time - std::chrono::high_resolution_clock::now();
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
