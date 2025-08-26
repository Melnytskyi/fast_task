// Copyright Danyil Melnytskyi 2022-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <cassert>
#include <tasks/util/cpu.hpp>
#include <tasks/util/interrupt.hpp>
#include <threading.hpp>

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

#ifdef _WIN32
    #define NOMINMAX
    #include <Windows.h>
    #include <process.h>
#else
    #include <pthread.h>
    #include <ucontext.h>
#endif
namespace fast_task {
#ifdef _WIN32
    mutex::mutex() {
        _mutex = SRWLOCK_INIT;
    }

    mutex::~mutex() noexcept(false) = default;

    void mutex::lock() {
        interrupt::interrupt_unsafe_region::lock();
        AcquireSRWLockExclusive((PSRWLOCK)&_mutex);
    }

    void mutex::unlock() {
        ReleaseSRWLockExclusive((PSRWLOCK)&_mutex);
        interrupt::interrupt_unsafe_region::unlock();
    }

    bool mutex::try_lock() {
        interrupt::interrupt_unsafe_region::lock();
        bool res = TryAcquireSRWLockExclusive((PSRWLOCK)&_mutex);
        if (!res)
            interrupt::interrupt_unsafe_region::unlock();
        return res;
    }

    rw_mutex::rw_mutex() {
        _mutex = SRWLOCK_INIT;
    }

    rw_mutex::~rw_mutex() noexcept(false) = default;

    void rw_mutex::lock() {
        interrupt::interrupt_unsafe_region::lock();
        AcquireSRWLockExclusive((PSRWLOCK)&_mutex);
    }

    void rw_mutex::unlock() {
        ReleaseSRWLockExclusive((PSRWLOCK)&_mutex);
        interrupt::interrupt_unsafe_region::unlock();
    }

    bool rw_mutex::try_lock() {
        interrupt::interrupt_unsafe_region::lock();
        bool res = TryAcquireSRWLockExclusive((PSRWLOCK)&_mutex);
        if (!res)
            interrupt::interrupt_unsafe_region::unlock();
        return res;
    }

    void rw_mutex::lock_shared() {
        interrupt::interrupt_unsafe_region::lock();
        AcquireSRWLockShared((PSRWLOCK)&_mutex);
    }

    void rw_mutex::unlock_shared() {
        ReleaseSRWLockShared((PSRWLOCK)&_mutex);
        interrupt::interrupt_unsafe_region::unlock();
    }

    bool rw_mutex::try_lock_shared() {
        interrupt::interrupt_unsafe_region::lock();
        bool res = TryAcquireSRWLockShared((PSRWLOCK)&_mutex);
        if (!res)
            interrupt::interrupt_unsafe_region::unlock();
        return res;
    }

    timed_mutex::timed_mutex() = default;

    timed_mutex::~timed_mutex() noexcept(false) {
        assert(locked == 0 && "Tried to destroy locked mutex");
    }

    void timed_mutex::lock() {
        fast_task::lock_guard<mutex> lock(_mutex);
        while (locked != 0)
            _cond.wait(_mutex);
        locked = UINT_MAX;
    }

    void timed_mutex::unlock() {
        {
            fast_task::lock_guard<mutex> lock(_mutex);
            locked = 0;
        }
        _cond.notify_one();
    }

    bool timed_mutex::try_lock() {
        fast_task::lock_guard<mutex> lock(_mutex);
        if (locked == 0) {
            locked = UINT_MAX;
            return true;
        } else
            return false;
    }

    bool timed_mutex::try_lock_for(std::chrono::milliseconds ms) {
        return try_lock_until(std::chrono::high_resolution_clock::now() + ms);
    }

    bool timed_mutex::try_lock_until(std::chrono::high_resolution_clock::time_point time) {
        fast_task::lock_guard<mutex> lock(_mutex);
        while (locked != 0)
            if (_cond.wait_until(_mutex, time) == cv_status::timeout)
                return false;
        locked = UINT_MAX;
        return true;
    }

    condition_variable::condition_variable() {
        _cond = CONDITION_VARIABLE_INIT;
    }

    condition_variable::~condition_variable() noexcept(false) = default;

    void condition_variable::notify_one() {
        interrupt::interrupt_unsafe_region region;
        WakeConditionVariable((PCONDITION_VARIABLE)&_cond);
    }

    void condition_variable::notify_all() {
        interrupt::interrupt_unsafe_region region;
        WakeAllConditionVariable((PCONDITION_VARIABLE)&_cond);
    }

    void condition_variable::wait(mutex& mtx) {
        interrupt::interrupt_unsafe_region region;
        if (SleepConditionVariableSRW((PCONDITION_VARIABLE)&_cond, (PSRWLOCK)&mtx._mutex, INFINITE, 0)) {
            DWORD err = GetLastError();
            if (err)
                throw std::system_error(err, std::system_category());
        }
    }

    cv_status condition_variable::wait_for(mutex& mtx, std::chrono::milliseconds ms) {
        return wait_until(mtx, std::chrono::high_resolution_clock::now() + ms);
    }

    cv_status condition_variable::wait_until(mutex& mtx, std::chrono::high_resolution_clock::time_point time) {
        while (true) {
            auto sleep_ms = std::chrono::duration_cast<std::chrono::milliseconds>(time - std::chrono::high_resolution_clock::now());
            if (sleep_ms.count() <= 0)
                return cv_status::timeout;
            DWORD wait_time = sleep_ms.count() > 0x7FFFFFFF ? 0x7FFFFFFF : (DWORD)sleep_ms.count();
            interrupt::interrupt_unsafe_region region;
            if (SleepConditionVariableSRW((PCONDITION_VARIABLE)&_cond, (PSRWLOCK)&mtx._mutex, wait_time, 0)) {
                auto err = GetLastError();
                switch (err) {
                case ERROR_TIMEOUT:
                    return cv_status::timeout;
                case ERROR_SUCCESS:
                    return cv_status::no_timeout;
                default:
                    throw std::system_error(err, std::system_category());
                }
            } else
                return cv_status::no_timeout;
        }
    }

    void condition_variable::wait(recursive_mutex& mtx) {
        interrupt::interrupt_unsafe_region region;
        auto state = mtx.relock_begin();
        if (SleepConditionVariableSRW((PCONDITION_VARIABLE)&_cond, (PSRWLOCK)&mtx.actual_mutex._mutex, INFINITE, 0)) {
            mtx.relock_end(state);
            DWORD err = GetLastError();
            if (err)
                throw std::system_error(err, std::system_category());
            else
                return;
        }
        mtx.relock_end(state);
    }

    cv_status condition_variable::wait_for(recursive_mutex& mtx, std::chrono::milliseconds ms) {
        return wait_until(mtx, std::chrono::high_resolution_clock::now() + ms);
    }

    cv_status condition_variable::wait_until(recursive_mutex& mtx, std::chrono::high_resolution_clock::time_point time) {
        auto state = mtx.relock_begin();
        while (true) {
            auto sleep_ms = std::chrono::duration_cast<std::chrono::milliseconds>(time - std::chrono::high_resolution_clock::now());
            if (sleep_ms.count() <= 0)
                return cv_status::timeout;
            DWORD wait_time = sleep_ms.count() > 0x7FFFFFFF ? 0x7FFFFFFF : (DWORD)sleep_ms.count();
            interrupt::interrupt_unsafe_region region;
            bool res = SleepConditionVariableSRW((PCONDITION_VARIABLE)&_cond, (PSRWLOCK)&mtx.actual_mutex._mutex, wait_time, 0);
            cv_status status = cv_status::no_timeout;
            mtx.relock_end(state);
            if (res) {
                auto err = GetLastError();
                switch (err) {
                case ERROR_TIMEOUT:
                    status = cv_status::timeout;
                    break;
                default:
                    throw std::system_error(err, std::system_category());

                case ERROR_SUCCESS:
                    break;
                }
            }
            return status;
        }
    }

    void* thread::create(void (*function)(void*), void* arg, unsigned long& id, size_t stack_size, bool stack_reservation, int& error_code) {
        error_code = 0;
        void* handle = (void*)_beginthreadex(nullptr, stack_size, (_beginthreadex_proc_type)function, arg, CREATE_SUSPENDED | (stack_reservation ? STACK_SIZE_PARAM_IS_A_RESERVATION : 0), (unsigned int*)&id);
        if (!handle) {
            error_code = GetLastError();
            return nullptr;
        }
        ResumeThread(handle);
        return handle;
    }

    [[nodiscard]] unsigned int thread::hardware_concurrency() noexcept {
        SYSTEM_INFO sysinfo;
        GetSystemInfo(&sysinfo);
        int numCPU = sysinfo.dwNumberOfProcessors;
        if (numCPU < 1)
            numCPU = 1;
        return (unsigned int)numCPU;
    }

    void thread::join() {
        if (_thread) {
            interrupt::interrupt_unsafe_region region;
            WaitForSingleObject(_thread, INFINITE);
            CloseHandle(_thread);
            _thread = nullptr;
        }
    }

    void thread::detach() {
        if (_thread) {
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
            if (handle != nullptr)
                CloseHandle(handle);
            handle = nullptr;
        }
    };

    bool thread::suspend(id id) {
        HANDLE_CLOSER thread_handle(OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, false, id._id));
        if (SuspendThread(thread_handle.handle) == -1)
            return false;
        return true;
    }

    bool thread::resume(id id) {
        HANDLE_CLOSER thread_handle(OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, false, id._id));
        if (ResumeThread(thread_handle.handle) == -1)
            return false;
        return true;
    }

    bool thread::insert_context(id id, void (*inserted_context)(void*), void* arg) {
        HANDLE_CLOSER thread_handle(OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, false, id._id));
        if (SuspendThread(thread_handle.handle) == -1)
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
    }

    namespace this_thread {
        thread::id get_id() noexcept {
            return thread::id(GetCurrentThreadId());
        }

        void yield() noexcept {
            SwitchToThread();
        }

        void sleep_for(std::chrono::milliseconds ms) {
            interrupt::interrupt_unsafe_region region;
            Sleep((DWORD)ms.count());
        }

        void sleep_until(std::chrono::high_resolution_clock::time_point time) {
            auto diff = time - std::chrono::high_resolution_clock::now();
            while (diff.count() > 0) {
                interrupt::interrupt_unsafe_region region;
                std::chrono::milliseconds ms = std::chrono::duration_cast<std::chrono::milliseconds>(diff);
                Sleep((DWORD)ms.count());
                diff = time - std::chrono::high_resolution_clock::now();
            }
        }
    }
#else
    mutex::mutex() {
        _mutex = new pthread_mutex_t;
        pthread_mutex_init(_mutex, nullptr);
    }

    mutex::~mutex() noexcept(false) {
        int res = pthread_mutex_destroy(_mutex);
        if (res == EBUSY) {
            assert(false && "Tried to destroy locked mutex");
            std::terminate();
        }
        if (res == EINVAL) {
            assert(false && "Tried to destroy locked mutex");
            std::terminate();
        }
        delete _mutex;
    }

    void mutex::lock() {
        int err = pthread_mutex_lock(_mutex);
        if (err) {
            if (err == EDEADLK)
                throw std::logic_error("Try lock already owned mutex");
            throw std::system_error(err, std::system_category());
        }
    }

    void mutex::unlock() {
        int err = pthread_mutex_unlock(_mutex);
        if (err) {
            if (err == EPERM)
                throw std::logic_error("Try unlock non-owned mutex");
            throw std::system_error(err, std::system_category());
        }
    }

    bool mutex::try_lock() {
        int err = pthread_mutex_trylock(_mutex);
        if (err) {
            if (err == EBUSY)
                return false;
            throw std::system_error(err, std::system_category());
        }
        return true;
    }

    rw_mutex::rw_mutex() {
        _mutex = new pthread_rwlock_t;
        pthread_rwlock_init(_mutex, nullptr);
    }

    rw_mutex::~rw_mutex() noexcept(false) {
        int res = pthread_rwlock_destroy(_mutex);

        if (res == EBUSY) {
            assert(false && "Tried to destroy locked mutex");
            std::terminate();
        }
        if (res == EINVAL) {
            assert(false && "Tried to destroy locked mutex");
            std::terminate();
        }
        delete _mutex;
    }

    void rw_mutex::lock() {
        interrupt::interrupt_unsafe_region::lock();
        pthread_rwlock_wrlock(_mutex);
    }

    void rw_mutex::unlock() {
        pthread_rwlock_unlock(_mutex);
        interrupt::interrupt_unsafe_region::unlock();
    }

    bool rw_mutex::try_lock() {
        interrupt::interrupt_unsafe_region::lock();
        bool res = pthread_rwlock_trywrlock(_mutex);
        if (!res)
            interrupt::interrupt_unsafe_region::unlock();
        return res;
    }

    void rw_mutex::lock_shared() {
        interrupt::interrupt_unsafe_region::lock();
        pthread_rwlock_rdlock(_mutex);
    }

    void rw_mutex::unlock_shared() {
        pthread_rwlock_unlock(_mutex);
        interrupt::interrupt_unsafe_region::unlock();
    }

    bool rw_mutex::try_lock_shared() {
        interrupt::interrupt_unsafe_region::lock();
        bool res = pthread_rwlock_tryrdlock(_mutex);
        if (!res)
            interrupt::interrupt_unsafe_region::unlock();
        return res;
    }

    timed_mutex::timed_mutex() {
        _mutex = new pthread_mutex_t;
        pthread_mutex_init(_mutex, nullptr);
    }

    timed_mutex::~timed_mutex() noexcept(false) {
        int res = pthread_mutex_destroy(_mutex);
        if (res == EBUSY) {
            assert(false && "Tried to destroy locked mutex");
            std::terminate();
        }
        if (res == EINVAL) {
            assert(false && "Tried to destroy locked mutex");
            std::terminate();
        }
        delete _mutex;
    }

    void timed_mutex::lock() {
        int err = pthread_mutex_lock(_mutex);
        if (err) {
            if (err == EDEADLK)
                throw std::logic_error("Try lock already owned mutex");
            throw std::system_error(err, std::system_category());
        }
    }

    void timed_mutex::unlock() {
        int err = pthread_mutex_unlock(_mutex);
        if (err) {
            if (err == EPERM)
                throw std::logic_error("Try unlock non-owned mutex");
            throw std::system_error(err, std::system_category());
        }
    }

    bool timed_mutex::try_lock() {
        int err = pthread_mutex_trylock(_mutex);
        if (err) {
            if (err == EBUSY)
                return false;
            throw std::system_error(err, std::system_category());
        }
        return true;
    }

    bool timed_mutex::try_lock_for(std::chrono::milliseconds ms) {
        return try_lock_until(std::chrono::high_resolution_clock::now() + ms);
    }

    bool timed_mutex::try_lock_until(std::chrono::high_resolution_clock::time_point time) {
        while (true) {
            auto sleep_ms = std::chrono::duration_cast<std::chrono::milliseconds>(time - std::chrono::high_resolution_clock::now());
            if (sleep_ms.count() <= 0)
                return false;
            timespec ts;
            ts.tv_sec = sleep_ms.count() / 1000000000;
            ts.tv_nsec = sleep_ms.count() % 1000000000;
            int err = pthread_mutex_timedlock(_mutex, &ts);
            if (err == 0)
                return true;
            if (err != ETIMEDOUT)
                throw std::system_error(err, std::system_category());
        }
    }

    condition_variable::condition_variable() {
        _cond = new pthread_cond_t;
        pthread_cond_init(_cond, nullptr);
    }

    condition_variable::~condition_variable() noexcept(false) {
        int res = pthread_cond_destroy(_cond);
        if (res == EBUSY)
            throw std::logic_error("Try destroy used condition variable(ie. some thread is waiting on it)");
        if (res == EINVAL)
            throw std::logic_error("Try destroy invalid condition variable");
        delete _cond;
    }

    void condition_variable::notify_one() {
        int err = pthread_cond_signal(_cond);
        if (err)
            throw std::system_error(err, std::system_category());
    }

    void condition_variable::notify_all() {
        int err = pthread_cond_broadcast(_cond);
        if (err)
            throw std::system_error(err, std::system_category());
    }

    void condition_variable::wait(mutex& mtx) {
        int err = pthread_cond_wait(_cond, mtx._mutex);
        if (err)
            throw std::system_error(err, std::system_category());
    }

    cv_status condition_variable::wait_for(mutex& mtx, std::chrono::milliseconds ms) {
        return wait_until(mtx, std::chrono::high_resolution_clock::now() + ms);
    }

    cv_status condition_variable::wait_until(mutex& mtx, std::chrono::high_resolution_clock::time_point time) {
        while (true) {
            auto sleep_ms = std::chrono::duration_cast<std::chrono::milliseconds>(time - std::chrono::high_resolution_clock::now());
            if (sleep_ms.count() <= 0) {
                return cv_status::timeout;
            }
            timespec ts;
            ts.tv_sec = sleep_ms.count() / 1000000000;
            ts.tv_nsec = sleep_ms.count() % 1000000000;
            if (pthread_cond_timedwait(_cond, mtx._mutex, &ts) == 0) {
                return cv_status::no_timeout;
            }
        }
        return cv_status::no_timeout;
    }

    void condition_variable::wait(recursive_mutex& mtx) {
        int err = pthread_cond_wait(_cond, mtx.actual_mutex._mutex);
        if (err)
            throw std::system_error(err, std::system_category());
    }

    cv_status condition_variable::wait_for(recursive_mutex& mtx, std::chrono::milliseconds ms) {
        return wait_until(mtx, std::chrono::high_resolution_clock::now() + ms);
    }

    cv_status condition_variable::wait_until(recursive_mutex& mtx, std::chrono::high_resolution_clock::time_point time) {
        while (true) {
            auto sleep_ms = std::chrono::duration_cast<std::chrono::milliseconds>(time - std::chrono::high_resolution_clock::now());
            if (sleep_ms.count() <= 0) {
                return cv_status::timeout;
            }
            timespec ts;
            ts.tv_sec = sleep_ms.count() / 1000000000;
            ts.tv_nsec = sleep_ms.count() % 1000000000;

            if (pthread_cond_timedwait(_cond, mtx.actual_mutex._mutex, &ts) == 0) {
                return cv_status::no_timeout;
            }
        }
        return cv_status::no_timeout;
    }

    void* thread::create(void (*function)(void*), void* arg, unsigned long& id, size_t stack_size, bool stack_reservation, int& error_code) {
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
        if (int err = pthread_create(&thread, &attr, (void* (*)(void*))function, arg); err) {
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
        return sysconf(_SC_NPROCESSORS_ONLN);
    }

    void thread::join() {
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
            delete (pthread_t*)_thread;
            _thread = nullptr;
        }
    }

    void thread::detach() {
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
        return suspend(_id);
    }

    bool thread::resume() {
        return resume(_id);
    }

    void thread::insert_context(void (*inserted_context)(void*), void* arg) {
        insert_context(_id, inserted_context, arg);
    }

    thread_local size_t locked_current = 0;
    struct {
        void (*inserted_context)(void*);
        void* arg;
    } context_install;

    sem_t pthread_pause_sem;
    bool ini = []() { sem_init(&pthread_pause_sem, 0, 1); return true; }();

    #define SIGNAL_STOP_THREAD (SIGRTMIN + 0)
    #define SIGNAL_CONTINUE_THREAD (SIGRTMIN + 1)
    #define SIGNAL_INSERT_THREAD (SIGRTMIN + 2)

    void pthread_pause_yield() {
        sem_wait(&pthread_pause_sem);
        sem_post(&pthread_pause_sem);
        pthread_yield();
    }

    void pthread_pause_handler(int signal, siginfo_t*, ucontext_t* context) {
        sem_post(&pthread_pause_sem);
        switch (signal) {
        case SIGNAL_STOP_THREAD:
            ++locked_current;
            break;
        case SIGNAL_CONTINUE_THREAD:
            --locked_current;
            break;
        case SIGNAL_INSERT_THREAD: {
            auto rsp = context->uc_mcontext.gregs[REG_RSP];
            rsp -= sizeof(size_t);
            *(size_t*)rsp = context->uc_mcontext.gregs[REG_RIP]; //return address
            rsp -= sizeof(size_t);
            *(size_t*)rsp = (size_t)inserted_context; //inserted_context
            rsp -= sizeof(size_t);
            *(size_t*)rsp = (size_t)arg; //arg
            context->uc_mcontext.gregs[REG_RSP] = rsp;
            //set rip to trampoline
            context->uc_mcontext.gregs[REG_RIP] = (size_t)thread_interrupter_asm_ptr;
            break;
        }
        default:
            break;
        };

        if (locked_current) {
            sigset_t sigset;
            sigfillset(&sigset);
            sigdelset(&sigset, SIGNAL_STOP_THREAD);
            sigdelset(&sigset, SIGNAL_CONTINUE_THREAD);
            sigdelset(&sigset, SIGNAL_INSERT_THREAD);
            sigsuspend(&sigset);
        } else
            return;
    }

    void pthread_pause_enable() {
        sigset_t sigset;
        sigemptyset(&sigset);
        sigaddset(&sigset, SIGNAL_STOP_THREAD);
        sigaddset(&sigset, SIGNAL_CONTINUE_THREAD);
        sigaddset(&sigset, SIGNAL_INSERT_THREAD);
        const struct sigaction pause_sa = {
            .sa_sigaction = pthread_pause_handler,
            .sa_mask = sigset,
            .sa_flags = SA_RESTART | SA_SIGINFO | SA_ONSTACK,
            .sa_restorer = NULL
        };
        sigaction(SIGNAL_STOP_THREAD, &pause_sa, NULL);
        sigaction(SIGNAL_CONTINUE_THREAD, &pause_sa, NULL);
        sigaction(SIGNAL_INSERT_THREAD, &pause_sa, NULL);
        pthread_sigmask(SIG_UNBLOCK, &sigset, NULL);
    }

    void pthread_pause_disable() {
        sem_wait(&pthread_pause_sem);
        sigset_t sigset;
        sigemptyset(&sigset);
        sigaddset(&sigset, SIGNAL_STOP_THREAD);
        sigaddset(&sigset, SIGNAL_CONTINUE_THREAD);
        sigaddset(&sigset, SIGNAL_INSERT_THREAD);
        pthread_sigmask(SIG_BLOCK, &sigset, NULL);

        sem_post(&pthread_pause_sem);
    }

    bool thread::suspend(id id) {
        sem_wait(&pthread_pause_sem);
        while (pthread_kill(thread, SIGNAL_CONTINUE_THREAD) == EAGAIN)
            usleep(1000);
        pthread_pause_yield();
        return true;
    }

    bool thread::resume(id id) {
        sem_wait(&pthread_pause_sem);
        while (pthread_kill(thread, SIGNAL_STOP_THREAD) == EAGAIN)
            usleep(1000);
        pthread_pause_yield();
        return true;
    }

    bool thread::insert_context(id id, void (*inserted_context)(void*), void* arg) {
        sem_wait(&pthread_pause_sem);
        
        while (pthread_kill(thread, SIGNAL_INSERT_THREAD) == EAGAIN)
            usleep(1000);
        return res;
    }

    namespace this_thread {
        thread::id get_id() noexcept {
            return thread::id(pthread_self());
        }

        void yield() noexcept {
            sched_yield();
        }

        void sleep_for(std::chrono::milliseconds ms) {
            sleep_until(std::chrono::high_resolution_clock::now() + ms);
        }

        void sleep_until(std::chrono::high_resolution_clock::time_point time) {
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
#endif
    recursive_mutex::recursive_mutex() {
        count = 0;
        owner = fast_task::thread::id();
    }

    recursive_mutex::~recursive_mutex() noexcept(false) {
        if (owner != fast_task::thread::id()) {
            assert(false && "Recursive mutex destroyed while locked");
            std::terminate();
        }
    }

    void recursive_mutex::lock() {
        if (owner == fast_task::this_thread::get_id()) {
            count++;
            if (count == 0) {
                count--;
                throw std::logic_error("Recursive mutex overflow");
            }
            return;
        }
        actual_mutex.lock();
        owner = fast_task::this_thread::get_id();
        count = 1;
    }

    void recursive_mutex::unlock() {
        if (owner != fast_task::this_thread::get_id()) {
            throw std::logic_error("Try unlock non-owned mutex");
        }
        count--;
        if (count == 0) {
            owner = fast_task::thread::id();
            actual_mutex.unlock();
        }
    }

    bool recursive_mutex::try_lock() {
        if (owner == fast_task::this_thread::get_id()) {
            count++;
            return true;
        }
        if (actual_mutex.try_lock()) {
            owner = fast_task::this_thread::get_id();
            count = 1;
            return true;
        }
        return false;
    }

    relock_state recursive_mutex::relock_begin() {
        if (owner != fast_task::this_thread::get_id())
            throw std::logic_error("Try relock non-owned mutex");
        unsigned int _count = count;
        count = 1;
        return relock_state(_count);
    }

    void recursive_mutex::relock_end(relock_state state) {
        if (owner != fast_task::this_thread::get_id())
            throw std::logic_error("Try relock non-owned mutex");
        count = state._state;
        owner = fast_task::this_thread::get_id();
    }

    void condition_variable_any::notify_one() {
        fast_task::lock_guard<mutex> lock(_mutex);
        _cond.notify_one();
    }

    void condition_variable_any::notify_all() {
        fast_task::lock_guard<mutex> lock(_mutex);
        _cond.notify_all();
    }

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
