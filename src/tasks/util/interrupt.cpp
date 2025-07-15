// Copyright Danyil Melnytskyi 2022-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <tasks/_internal.hpp>
#include <tasks/util/interrupt.hpp>
#include <tasks/util/native_workers_singleton.hpp>
#include <threading.hpp>
#include <unordered_map>

namespace fast_task::interrupt {
    void uninstall_timer_handle_local();
    struct handle;

    struct timer_handle {
        void (*interrupt)() = nullptr;
        itimerval timer_value = {0};
        void* timer_handle_ = nullptr;
        thread::id thread_id;
        std::atomic_size_t guard_zones = 0;
        bool enabled_timers = true;
        std::shared_ptr<handle> handle;

        timer_handle();

        ~timer_handle() {
            uninstall_timer_handle_local();
        }
    };

    thread_local timer_handle timer;

    interrupt_unsafe_region::interrupt_unsafe_region() {
        lock();
    }

    interrupt_unsafe_region::~interrupt_unsafe_region() {
        unlock();
    }

    size_t interrupt_unsafe_region::lock_swap(size_t other) {
        return timer.guard_zones.exchange(other);
    }

    void interrupt_unsafe_region::lock() {
        timer.guard_zones++;
    }

    void interrupt_unsafe_region::unlock() {
        timer.guard_zones--;
    }
}

#if PLATFORM_WINDOWS
    #define NOMINMAX
    #include <windows.h>

namespace fast_task::interrupt {
    struct handle {
        std::list<timer_handle*> await_timers;
        fast_task::condition_variable timer_signal;
        fast_task::mutex timer_signal_mutex;
    };

    std::shared_ptr<handle> global = std::make_shared<handle>();

    timer_handle::timer_handle() : handle(global) {}

    bool auto_ini = []() {
        fast_task::thread([]() {
            fast_task::unique_lock<fast_task::mutex> lock(timer.handle->timer_signal_mutex, fast_task::defer_lock);
            while (true) {
                lock.lock();
                while (timer.handle->await_timers.empty())
                    timer.handle->timer_signal.wait(lock);
                timer_handle* data = timer.handle->await_timers.front();
                timer.handle->await_timers.pop_front();
                lock.unlock();
                if (data != nullptr) {
                    //get thread handle
                    auto id = data->thread_id;
                    if (fast_task::thread::suspend(id) == false)
                        continue;

                    if (!data->enabled_timers) {
                        fast_task::thread::resume(id);
                        continue;
                    }
                    if (data->guard_zones != 0) {
                        fast_task::thread::resume(id);
                        lock.lock();
                        timer.handle->await_timers.push_back(data);
                        lock.unlock();
                        continue;
                    }
                    fast_task::thread::insert_context(id, (void (*)(void*))data->interrupt, nullptr);
                    fast_task::thread::resume(id);
                }
            }
        });
        return true;
    }();

    VOID NTAPI timer_callback_fun(void* callback, BOOLEAN) {
        timer_handle* timer = (timer_handle*)callback;
        if (timer->thread_id == this_thread::get_id())
            return;
        fast_task::lock_guard<fast_task::mutex> lock(timer->handle->timer_signal_mutex);
        timer->handle->await_timers.push_back(timer);
        timer->handle->timer_signal.notify_all();
    }

    bool timer_callback(void (*interrupter)()) {
        timer.interrupt = interrupter;
        return true;
    }

    bool setitimer(const struct itimerval* new_value, struct itimerval* old_value) {
        interrupt_unsafe_region guard;
        if (old_value)
            *old_value = timer.timer_value;
        if (new_value == nullptr)
            return false;

        timer.timer_value = *new_value;
        timer.thread_id = this_thread::get_id();
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
        timer.enabled_timers = true;
        return true;
    }

    void stop_timer() {
        interrupt_unsafe_region region;
        if (timer.timer_handle_ != nullptr) {
            DeleteTimerQueueTimer(NULL, timer.timer_handle_, INVALID_HANDLE_VALUE);
            timer.timer_handle_ = nullptr;
        }
        timer.enabled_timers = false;
    }

    void uninstall_timer_handle_local() {
        fast_task::interrupt::stop_timer();
        if (!fast_task::interrupt::timer.handle)
            return;
        fast_task::lock_guard<fast_task::mutex> lock(fast_task::interrupt::timer.handle->timer_signal_mutex);
        auto cur_id = fast_task::this_thread::get_id();
        std::erase_if(
            fast_task::interrupt::timer.handle->await_timers,
            [cur_id](fast_task::interrupt::timer_handle* timer) {
                return timer->thread_id == cur_id;
            }
        );
    }
}

#else
    #include <signal.h>
    #include <sys/time.h>

namespace fast_task::interrupt {
    void install_on_stack() {
    }

    void init_signals_handler() {}

    bool timer_callback(void (*interrupter)()) {
        return false;
    }

    bool setitimer(const struct itimerval* new_value, struct itimerval* old_value) {
        return false;
    }

    void stop_timer() {}
}

#endif

void* operator new(std::size_t n) noexcept(false) {
    fast_task::interrupt::interrupt_unsafe_region region;
    void* ptr = malloc(n);
    if (ptr == nullptr)
        throw std::bad_alloc();
    return ptr;
}

void operator delete(void* p) noexcept {
    fast_task::interrupt::interrupt_unsafe_region region;
    free(p);
}

void* operator new[](std::size_t s) noexcept(false) {
    fast_task::interrupt::interrupt_unsafe_region region;
    void* ptr = malloc(s);
    if (ptr == nullptr)
        throw std::bad_alloc();
    return ptr;
}

void operator delete[](void* p) noexcept {
    fast_task::interrupt::interrupt_unsafe_region region;
    free(p);
}