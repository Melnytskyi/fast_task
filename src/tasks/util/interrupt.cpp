// Copyright Danyil Melnytskyi 2022-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <atomic>
#include <chrono>
#include <cstring>
#include <fast_task/native.hpp>
#include <list>
#include <memory>
#include <mutex>
#include <tasks/_internal.hpp>
#include <tasks/util/interrupt.hpp>
#include <tasks/util/native_workers_singleton.hpp>
#include <unordered_map>

#ifdef FT_ENABLE_PREEMPTIVE_SCHEDULER
    #if PLATFORM_WINDOWS
        #ifndef NOMINMAX
            #define NOMINMAX
        #endif
        #include <process.h>
        #include <windows.h>
    #else
        #include <signal.h>
        #include <sys/syscall.h>
        #include <tasks/util/cpu.hpp>
        #include <time.h>
        #include <ucontext.h>
        #include <unistd.h>
    #endif

    #if defined(__GNUC__) && !defined(__clang__)
        #define FT_TLS_NOINLINE __attribute__((noinline, noipa))
    #elif defined(__clang__)
        #define FT_TLS_NOINLINE __attribute__((noinline))
    #elif defined(_MSC_VER)
        #define FT_TLS_NOINLINE __declspec(noinline)
    #else
        #define FT_TLS_NOINLINE
    #endif

namespace fast_task::interrupt {
    void uninstall_timer_handle_local();
    struct handle;

    struct timer_handle {
        void (*interrupt)() = nullptr;
        itimerval timer_value = {};
        void* timer_handle_ = nullptr;
        fast_task::native::thread::id thread_id;
        std::atomic_size_t guard_zones{0};
        std::atomic<size_t> enabled_timers{0};
    #if PLATFORM_WINDOWS
        std::shared_ptr<struct handle> handle;
    #else
        timer_t timerid{};
        bool timer_created = false;
        std::atomic<bool> in_trampoline{false};
        #if defined(__linux__) && defined(__x86_64__)
        std::unique_ptr<char[]> alt_stack_mem;
        stack_t old_alt_stack{};
        bool alt_stack_installed = false;
        #endif
        #if defined(__linux__) && defined(__aarch64__)
        ucontext_t* restore_ucontext = nullptr;
        #endif
    #endif

        timer_handle();

        ~timer_handle() {
            guard_zones.fetch_add(1, std::memory_order_relaxed);
            interrupt = nullptr;
            uninstall_timer_handle_local();
    #if !PLATFORM_WINDOWS
            if (timer_created) {
                timer_delete(timerid);
                timer_created = false;
            }
        #if defined(__linux__) && defined(__x86_64__)
            if (alt_stack_installed) {
                sigaltstack(&old_alt_stack, nullptr);
                alt_stack_installed = false;
                alt_stack_mem.reset();
            }
        #endif
    #endif
        }
    };

    thread_local timer_handle timer;

    FT_TLS_NOINLINE timer_handle& get_timer() noexcept {
        timer_handle* ptr = &timer;
    #if defined(__GNUC__) || defined(__clang__)
        asm volatile("" : "+r"(ptr));
    #endif
        return *ptr;
    }
}

namespace fast_task {
    interrupt_unsafe_region::interrupt_unsafe_region() {
        lock();
    }

    interrupt_unsafe_region::~interrupt_unsafe_region() {
        unlock();
    }

    FT_TLS_NOINLINE size_t interrupt_unsafe_region::lock_swap(size_t other) {
        return interrupt::get_timer().guard_zones.exchange(other, std::memory_order_acq_rel);
    }

    FT_TLS_NOINLINE void interrupt_unsafe_region::lock() {
        interrupt::get_timer().guard_zones.fetch_add(1, std::memory_order_acq_rel);
    }

    FT_TLS_NOINLINE void interrupt_unsafe_region::unlock() {
        interrupt::get_timer().guard_zones.fetch_sub(1, std::memory_order_acq_rel);
    }
}

    #if PLATFORM_WINDOWS
namespace fast_task::interrupt {
    struct handle {
        std::list<timer_handle*> await_timers;
        CONDITION_VARIABLE timer_signal = CONDITION_VARIABLE_INIT;
        CONDITION_VARIABLE active_done = CONDITION_VARIABLE_INIT;
        SRWLOCK timer_signal_mutex = SRWLOCK_INIT;
        timer_handle* active_timer = nullptr;
        HANDLE processor_thread = nullptr;
        bool processor_started = false;
        std::atomic<bool> shutdown{false};

        void stop_processor() noexcept {
            AcquireSRWLockExclusive(&timer_signal_mutex);
            shutdown.store(true, std::memory_order_release);
            WakeAllConditionVariable(&timer_signal);
            HANDLE th = processor_thread;
            processor_thread = nullptr;
            ReleaseSRWLockExclusive(&timer_signal_mutex);
            if (th != nullptr) {
                WaitForSingleObject(th, INFINITE);
                CloseHandle(th);
            }
        }

        ~handle() {
            AcquireSRWLockExclusive(&timer_signal_mutex);
            shutdown.store(true, std::memory_order_release);
            WakeAllConditionVariable(&timer_signal);
            HANDLE th = processor_thread;
            processor_thread = nullptr;
            ReleaseSRWLockExclusive(&timer_signal_mutex);
            if (th != nullptr) {
                CloseHandle(th);
            }
        }
    };

    struct global_handle_holder {
        std::shared_ptr<handle> ptr = std::make_shared<handle>();

        ~global_handle_holder() {
            if (ptr)
                ptr->stop_processor();
        }
    };

    global_handle_holder global_holder;

    timer_handle::timer_handle() = default;

    unsigned __stdcall interrupt_processor_main(void* raw) {
        auto* h = static_cast<handle*>(raw);
        while (true) {
            AcquireSRWLockExclusive(&h->timer_signal_mutex);
            while (!h->shutdown.load(std::memory_order_acquire) && h->await_timers.empty())
                SleepConditionVariableSRW(&h->timer_signal, &h->timer_signal_mutex, INFINITE, 0);
            if (h->shutdown.load(std::memory_order_acquire)) {
                ReleaseSRWLockExclusive(&h->timer_signal_mutex);
                break;
            }
            timer_handle* data = h->await_timers.front();
            h->await_timers.pop_front();
            if (data == nullptr) {
                ReleaseSRWLockExclusive(&h->timer_signal_mutex);
                continue;
            }
            h->active_timer = data;
            ReleaseSRWLockExclusive(&h->timer_signal_mutex);

            bool requeue = false;
            if (data->enabled_timers.load(std::memory_order_acquire) != 0) {
                auto id = data->thread_id;
                if (fast_task::native::thread::suspend(id)) {
                    if (data->enabled_timers.load(std::memory_order_acquire) == 0) {
                        fast_task::native::thread::resume(id);
                    } else if (data->guard_zones.load(std::memory_order_acquire) != 0) {
                        fast_task::native::thread::resume(id);
                        requeue = true;
                    } else {
                        auto cb = data->interrupt;
                        if (cb != nullptr)
                            fast_task::native::thread::insert_context(id, (void (*)(void*))cb, nullptr);
                        fast_task::native::thread::resume(id);
                    }
                }
            }

            if (requeue && !h->shutdown.load(std::memory_order_acquire) && data->enabled_timers.load(std::memory_order_acquire) != 0) {
                Sleep(1);
            }

            AcquireSRWLockExclusive(&h->timer_signal_mutex);
            if (requeue && !h->shutdown.load(std::memory_order_acquire) && data->enabled_timers.load(std::memory_order_acquire) != 0) {
                h->await_timers.push_back(data);
            }
            h->active_timer = nullptr;
            WakeAllConditionVariable(&h->active_done);
            ReleaseSRWLockExclusive(&h->timer_signal_mutex);
        }
        return 0;
    }

    VOID NTAPI timer_callback_fun(void* callback, BOOLEAN) {
        timer_handle* result = (timer_handle*)callback;
        if (result->thread_id == fast_task::native::this_thread::get_id())
            return;
        auto* h = result->handle.get();
        if (!h)
            return;
        AcquireSRWLockExclusive(&h->timer_signal_mutex);
        if (h->shutdown.load(std::memory_order_acquire)) {
            ReleaseSRWLockExclusive(&h->timer_signal_mutex);
            return;
        }
        if (!h->processor_started) {
            h->processor_started = true;
            h->processor_thread = reinterpret_cast<HANDLE>(_beginthreadex(nullptr, 0, &interrupt_processor_main, h, 0, nullptr));
        }
        h->await_timers.push_back(result);
        WakeAllConditionVariable(&h->timer_signal);
        ReleaseSRWLockExclusive(&h->timer_signal_mutex);
    }

    bool timer_callback(void (*interrupter)()) {
        interrupt_unsafe_region guard;
        timer.interrupt = interrupter;
        return true;
    }

    bool setitimer(const struct itimerval* new_value, struct itimerval* old_value) {
        interrupt_unsafe_region guard;
        if (old_value)
            *old_value = timer.timer_value;
        if (new_value == nullptr)
            return false;

        if (!timer.handle)
            timer.handle = global_holder.ptr;
        if (!timer.handle || timer.handle->shutdown.load(std::memory_order_acquire))
            return false;

        timer.timer_value = *new_value;
        timer.thread_id = fast_task::native::this_thread::get_id();
        if (timer.timer_handle_ != nullptr) {
            DeleteTimerQueueTimer(NULL, timer.timer_handle_, INVALID_HANDLE_VALUE);
            timer.timer_handle_ = nullptr;
        }
        if (CreateTimerQueueTimer(
                &timer.timer_handle_,
                NULL,
                timer_callback_fun,
                &timer,
                new_value->it_value.tv_sec * 1000 + new_value->it_value.tv_usec / 1000,
                new_value->it_interval.tv_sec * 1000 + new_value->it_interval.tv_usec / 1000,
                WT_EXECUTEINTIMERTHREAD
            ) == 0) {
            return false;
        }
        timer.enabled_timers.store(1, std::memory_order_release);
        return true;
    }

    void stop_timer() {
        interrupt_unsafe_region region;
        if (timer.timer_handle_ != nullptr) {
            DeleteTimerQueueTimer(NULL, timer.timer_handle_, INVALID_HANDLE_VALUE);
            timer.timer_handle_ = nullptr;
        }
        timer.enabled_timers.store(0, std::memory_order_release);
    }

    void uninstall_timer_handle_local() {
        fast_task::interrupt::stop_timer();
        if (!fast_task::interrupt::timer.handle)
            return;
        auto& h = *fast_task::interrupt::timer.handle;
        AcquireSRWLockExclusive(&h.timer_signal_mutex);
        auto* self = &fast_task::interrupt::timer;
        std::erase_if(
            h.await_timers,
            [self](fast_task::interrupt::timer_handle* _timer) {
                return _timer == self;
            }
        );
        while (h.active_timer == self) {
            SleepConditionVariableSRW(&h.active_done, &h.timer_signal_mutex, INFINITE, 0);
        }
        ReleaseSRWLockExclusive(&h.timer_signal_mutex);
    }
}

    #else
    #if defined(__linux__) && defined(__x86_64__)
extern "C" {
    void ft_linux_preempt_trampoline_sse();
    void ft_linux_preempt_trampoline_avx();
    void ft_linux_preempt_trampoline_avx512();

    __attribute__((used, noinline)) void ft_linux_preempt_entry() {
        auto& t = fast_task::interrupt::get_timer();
        auto cb = t.interrupt;
        const bool should_call = (cb != nullptr &&
                                  t.enabled_timers.exchange(0, std::memory_order_acq_rel) != 0 &&
                                  t.guard_zones.load(std::memory_order_acquire) == 0);
        t.in_trampoline.store(false, std::memory_order_release);
        if (should_call) {
            cb();
        }
    }
}
    #endif

namespace fast_task::interrupt {
    void uninstall_timer_handle_local() {
        fast_task::interrupt::stop_timer();
    }

        #define PREEMPTION_SIGNAL (SIGRTMIN + 5)
        #if defined(__linux__) && defined(__aarch64__)
            #define PREEMPTION_RESTORE_SIGNAL (SIGRTMIN + 6)
        #endif

    timer_handle::timer_handle() = default;

    #if defined(__linux__) && defined(__x86_64__)
    static void (*select_linux_preempt_trampoline())() {
        if (psnip_cpu_feature_check(PSNIP_CPU_FEATURE_X86_AVX512F))
            return ft_linux_preempt_trampoline_avx512;
        if (psnip_cpu_feature_check(PSNIP_CPU_FEATURE_X86_AVX))
            return ft_linux_preempt_trampoline_avx;
        return ft_linux_preempt_trampoline_sse;
    }

    static void (*linux_preempt_trampoline_ptr)() = select_linux_preempt_trampoline();
    #elif defined(__linux__) && defined(__aarch64__)
    namespace {
        struct aarch64_ctx_header {
            uint32_t magic;
            uint32_t size;
        };

        constexpr uint32_t aarch64_fpsimd_magic = 0x46508001u;

        const aarch64_ctx_header* find_aarch64_fpsimd(const mcontext_t& mc) noexcept {
            const auto* base = reinterpret_cast<const uint8_t*>(mc.__reserved);
            size_t offset = 0;
            while (offset + sizeof(aarch64_ctx_header) <= sizeof(mc.__reserved)) {
                const auto* hdr = reinterpret_cast<const aarch64_ctx_header*>(base + offset);
                if (hdr->magic == 0 || hdr->size == 0)
                    break;
                if (offset + hdr->size > sizeof(mc.__reserved))
                    break;
                if (hdr->magic == aarch64_fpsimd_magic)
                    return hdr;
                offset += hdr->size;
            }
            return nullptr;
        }

        aarch64_ctx_header* find_aarch64_fpsimd_mut(mcontext_t& mc) noexcept {
            return const_cast<aarch64_ctx_header*>(find_aarch64_fpsimd(mc));
        }

        void copy_aarch64_mcontext(mcontext_t& dst, const mcontext_t& src) noexcept {
            std::memcpy(dst.regs, src.regs, sizeof(dst.regs));
            dst.sp = src.sp;
            dst.pc = src.pc;
            dst.pstate = src.pstate;
            const auto* src_fp = find_aarch64_fpsimd(src);
            auto* dst_fp = find_aarch64_fpsimd_mut(dst);
            if (src_fp && dst_fp && src_fp->size == dst_fp->size)
                std::memcpy(dst_fp, src_fp, src_fp->size);
        }

        void posix_restore_signal_handler([[maybe_unused]] int signum, [[maybe_unused]] siginfo_t* info, void* uctx_raw) {
            auto& t = get_timer();
            ucontext_t* saved = t.restore_ucontext;
            t.restore_ucontext = nullptr;
            if (saved && uctx_raw) {
                auto* dst = static_cast<ucontext_t*>(uctx_raw);
                copy_aarch64_mcontext(dst->uc_mcontext, saved->uc_mcontext);
            }
            t.in_trampoline.store(false, std::memory_order_release);
        }

        [[noreturn]] void ft_linux_aarch64_preempt_entry(ucontext_t* saved_uc) {
            auto& t = get_timer();
            auto cb = t.interrupt;
            const bool should_call = (cb != nullptr &&
                                      t.enabled_timers.exchange(0, std::memory_order_acq_rel) != 0 &&
                                      t.guard_zones.load(std::memory_order_acquire) == 0);
            t.in_trampoline.store(false, std::memory_order_release);
            if (should_call) {
                cb();
            }
            auto& cur = get_timer();
            cur.in_trampoline.store(true, std::memory_order_relaxed);
            cur.restore_ucontext = saved_uc;
            syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), PREEMPTION_RESTORE_SIGNAL);
            std::terminate();
        }
    }
    #endif

    void posix_signal_handler([[maybe_unused]] int signum, [[maybe_unused]] siginfo_t* info, void* uctx_raw) {
        auto& t = get_timer();
        if (t.interrupt == nullptr || t.enabled_timers.load(std::memory_order_relaxed) == 0)
            return;
        if (t.in_trampoline.load(std::memory_order_relaxed))
            return;
        if (t.guard_zones.load(std::memory_order_relaxed) != 0)
            return;

    #if defined(__linux__) && (defined(__x86_64__) || defined(__aarch64__))
        auto* loc = fast_task::get_loc();
        if (!loc || !loc->is_task_thread || loc->context_in_swap || !loc->curr_task)
            return;
        auto& task_obj = fast_task::get_data(loc->curr_task);
        if (task_obj.get_is_on_scheduler())
            return;
        auto* ex = task_obj.exdata.load(std::memory_order_relaxed);
        if (!ex || !ex->stack_ptr || ex->stack_size == 0)
            return;

        auto* uc = static_cast<ucontext_t*>(uctx_raw);
        if (!uc)
            return;

        const uintptr_t stack_low = reinterpret_cast<uintptr_t>(ex->stack_ptr);
        const uintptr_t stack_high = stack_low + ex->stack_size;
        #if defined(__x86_64__)
        if (!t.alt_stack_installed)
            return;
        const uintptr_t orig_rsp = static_cast<uintptr_t>(uc->uc_mcontext.gregs[REG_RSP]);
        const uintptr_t orig_rip = static_cast<uintptr_t>(uc->uc_mcontext.gregs[REG_RIP]);

        constexpr uintptr_t min_headroom = 8192;
        if (orig_rsp <= stack_low + min_headroom || orig_rsp > stack_high)
            return;

        const uintptr_t new_rsp = orig_rsp - 128 - sizeof(uintptr_t);
        *reinterpret_cast<uintptr_t*>(new_rsp) = orig_rip;

        t.in_trampoline.store(true, std::memory_order_relaxed);
        uc->uc_mcontext.gregs[REG_RSP] = static_cast<greg_t>(new_rsp);
        uc->uc_mcontext.gregs[REG_RIP] = reinterpret_cast<greg_t>(linux_preempt_trampoline_ptr);
        #elif defined(__aarch64__)
        const uintptr_t orig_sp = static_cast<uintptr_t>(uc->uc_mcontext.sp);

        volatile uintptr_t handler_sp_anchor = 0;
        const uintptr_t handler_sp = reinterpret_cast<uintptr_t>(&handler_sp_anchor);
        const uintptr_t safe_top = (handler_sp < orig_sp) ? handler_sp : orig_sp;
        const uintptr_t new_sp = (safe_top - 1024 - sizeof(ucontext_t)) & ~uintptr_t(15);

        constexpr uintptr_t min_headroom = 8192;
        if (orig_sp <= stack_low || orig_sp > stack_high ||
            safe_top <= stack_low + 1024 + sizeof(ucontext_t) + min_headroom ||
            new_sp <= stack_low + min_headroom || new_sp >= safe_top)
            return;

        auto* saved_uc = reinterpret_cast<ucontext_t*>(new_sp);
        std::memcpy(saved_uc, uc, sizeof(ucontext_t));

        t.in_trampoline.store(true, std::memory_order_relaxed);
        uc->uc_mcontext.sp = static_cast<uint64_t>(new_sp);
        uc->uc_mcontext.regs[0] = static_cast<uint64_t>(new_sp);
        uc->uc_mcontext.regs[30] = 0;
        uc->uc_mcontext.pc = reinterpret_cast<uint64_t>(&ft_linux_aarch64_preempt_entry);
        #endif
    #else
        (void)uctx_raw;
    #endif
    }

    void setup_signal_handler() {
        struct sigaction sa;
        std::memset(&sa, 0, sizeof(sa));
        sa.sa_sigaction = posix_signal_handler;
    #if defined(__linux__) && defined(__x86_64__)
        sa.sa_flags = SA_SIGINFO | SA_RESTART | SA_ONSTACK;
    #else
        sa.sa_flags = SA_SIGINFO | SA_RESTART;
    #endif
        sigemptyset(&sa.sa_mask);
        sigaction(PREEMPTION_SIGNAL, &sa, NULL);

    #if defined(__linux__) && defined(__aarch64__)
        struct sigaction sa_restore;
        std::memset(&sa_restore, 0, sizeof(sa_restore));
        sa_restore.sa_sigaction = posix_restore_signal_handler;
        sa_restore.sa_flags = SA_SIGINFO | SA_RESTART;
        sigemptyset(&sa_restore.sa_mask);
        sigaddset(&sa_restore.sa_mask, PREEMPTION_SIGNAL);
        sigaction(PREEMPTION_RESTORE_SIGNAL, &sa_restore, NULL);
    #endif
    }

    auto signal_handler_setup_once = std::once_flag{};

    bool timer_callback(void (*interrupter)()) {
        interrupt_unsafe_region guard;
        timer.interrupt = interrupter;
        return true;
    }

    bool setitimer(const struct itimerval* new_value, struct itimerval* old_value) {
        interrupt_unsafe_region guard;
        std::call_once(signal_handler_setup_once, setup_signal_handler);

        if (old_value)
            *old_value = timer.timer_value;
        if (!new_value) {
            stop_timer();
            timer.timer_value = {};
            return true;
        }
        timer.timer_value = *new_value;
    #if defined(__linux__) && defined(__x86_64__)
        if (!timer.alt_stack_installed) {
            constexpr size_t alt_stack_size = 64 * 1024;
            timer.alt_stack_mem = std::make_unique<char[]>(alt_stack_size);
            stack_t ss{};
            ss.ss_sp = timer.alt_stack_mem.get();
            ss.ss_size = alt_stack_size;
            ss.ss_flags = 0;
            if (sigaltstack(&ss, &timer.old_alt_stack) == 0) {
                timer.alt_stack_installed = true;
            } else {
                timer.alt_stack_mem.reset();
            }
        }
    #endif
        if (!timer.timer_created) {
            struct sigevent sev;
            std::memset(&sev, 0, sizeof(sev));
            sev.sigev_notify = SIGEV_THREAD_ID;
            sev.sigev_signo = PREEMPTION_SIGNAL;
            sev._sigev_un._tid = syscall(SYS_gettid);

            if (timer_create(CLOCK_MONOTONIC, &sev, &timer.timerid) == -1)
                return false;
            timer.timer_created = true;
        }

        struct itimerspec its;
        its.it_value.tv_sec = new_value->it_value.tv_sec;
        its.it_value.tv_nsec = new_value->it_value.tv_usec * 1000;
        its.it_interval.tv_sec = new_value->it_interval.tv_sec;
        its.it_interval.tv_nsec = new_value->it_interval.tv_usec * 1000;

        if (its.it_interval.tv_sec == 0 && its.it_interval.tv_nsec == 0 &&
            (its.it_value.tv_sec != 0 || its.it_value.tv_nsec != 0)) {
            its.it_interval.tv_nsec = 1'000'000;
        }
        auto& t = get_timer();
        t.enabled_timers.store(1, std::memory_order_release);
        if (timer_settime(t.timerid, 0, &its, NULL) == -1) {
            t.enabled_timers.store(0, std::memory_order_release);
            return false;
        }
        return true;
    }

    void stop_timer() {
        interrupt_unsafe_region guard;
        auto& t = get_timer();
        t.enabled_timers.store(0, std::memory_order_release);
        if (t.timer_created) {
            struct itimerspec its;
            std::memset(&its, 0, sizeof(its));
            timer_settime(t.timerid, 0, &its, NULL);
        }
    }
}
    #endif
#else
namespace fast_task::interrupt {
    bool timer_callback(void (*)()) {
        return false;
    }

    bool setitimer(const struct itimerval*, struct itimerval*) {
        return false;
    }

    void stop_timer() {}
}

namespace fast_task {
    interrupt_unsafe_region::interrupt_unsafe_region() {}

    interrupt_unsafe_region::~interrupt_unsafe_region() {}

    size_t interrupt_unsafe_region::lock_swap(size_t) {
        return 0;
    }

    void interrupt_unsafe_region::lock() {}

    void interrupt_unsafe_region::unlock() {}
}

#endif