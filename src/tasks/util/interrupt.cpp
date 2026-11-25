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
        #define NOMINMAX
        #include <process.h>
        #include <windows.h>
    #else
        #include <signal.h>
        #include <sys/syscall.h>
        #include <time.h>
        #include <unistd.h>
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
    #endif
        }
    };

    thread_local timer_handle timer;
}

namespace fast_task {
    interrupt_unsafe_region::interrupt_unsafe_region() {
        lock();
    }

    interrupt_unsafe_region::~interrupt_unsafe_region() {
        unlock();
    }

    size_t interrupt_unsafe_region::lock_swap(size_t other) {
        return interrupt::timer.guard_zones.exchange(other);
    }

    void interrupt_unsafe_region::lock() {
        interrupt::timer.guard_zones++;
    }

    void interrupt_unsafe_region::unlock() {
        interrupt::timer.guard_zones--;
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

        ~handle() {
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
    };

    std::shared_ptr<handle> global = std::make_shared<handle>();

    // Lazily attach to global in setitimer() so threads that only enter
    // interrupt_unsafe_region (including processor_thread) do not create a
    // shared_ptr<handle> reference cycle.
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
            timer.handle = global;
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
namespace fast_task::interrupt {
    void uninstall_timer_handle_local() {
        fast_task::interrupt::stop_timer();
    }

        #define PREEMPTION_SIGNAL (SIGRTMIN + 5)

    timer_handle::timer_handle() = default;

    void posix_signal_handler([[maybe_unused]] int signum) {
        if (timer.interrupt != nullptr && timer.guard_zones.load(std::memory_order_relaxed) == 0)
            timer.interrupt();
    }

    void setup_signal_handler() {
        struct sigaction sa;
        std::memset(&sa, 0, sizeof(sa));
        sa.sa_handler = posix_signal_handler;
        sa.sa_flags = SA_RESTART | SA_NODEFER;
        sigemptyset(&sa.sa_mask);
        sigaction(PREEMPTION_SIGNAL, &sa, NULL);
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
        if (!timer.timer_created) {
            struct sigevent sev;
            std::memset(&sev, 0, sizeof(sev));
            sev.sigev_notify = SIGEV_THREAD_ID;
            sev.sigev_signo = PREEMPTION_SIGNAL;
            sev._sigev_un._tid = syscall(SYS_gettid);
            // CLOCK_MONOTONIC: the preemption quantum must not change length
            // when the wall clock is stepped.
            if (timer_create(CLOCK_MONOTONIC, &sev, &timer.timerid) == -1)
                return false;
            timer.timer_created = true;
        }

        struct itimerspec its;
        its.it_value.tv_sec = new_value->it_value.tv_sec;
        its.it_value.tv_nsec = new_value->it_value.tv_usec * 1000;
        its.it_interval.tv_sec = new_value->it_interval.tv_sec;
        its.it_interval.tv_nsec = new_value->it_interval.tv_usec * 1000;
        return timer_settime(timer.timerid, 0, &its, NULL) != -1;
    }

    void stop_timer() {
        interrupt_unsafe_region guard;
        if (timer.timer_created) {
            struct itimerspec its;
            std::memset(&its, 0, sizeof(its));
            timer_settime(timer.timerid, 0, &its, NULL);
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