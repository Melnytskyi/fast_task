// Copyright Danyil Melnytskyi 2022-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <native/condition_variable.hpp>
#include <native/mutex.hpp>
#include <tasks/util/interrupt.hpp>

#include <cassert>
#include <errno.h>
#include <exception>

#ifdef _WIN32
    #define NOMINMAX
    #include <Windows.h>
#else
    #include <chrono>

    #include <pthread.h>
    #include <semaphore.h>
    #include <signal.h>
    #include <ucontext.h>

static timespec to_abs_timespec(std::chrono::high_resolution_clock::time_point time) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(time - std::chrono::high_resolution_clock::now());
    ts.tv_sec += ns.count() / 1000000000;
    ts.tv_nsec += ns.count() % 1000000000;
    if (ts.tv_nsec >= 1000000000) {
        ts.tv_sec++;
        ts.tv_nsec -= 1000000000;
    } else if (ts.tv_nsec < 0) {
        ts.tv_sec--;
        ts.tv_nsec += 1000000000;
    }
    return ts;
}
#endif

namespace fast_task::native {
#ifdef _WIN32
    mutex::mutex() {
        _mutex = SRWLOCK_INIT;
    }

    mutex::~mutex() noexcept = default;

    void mutex::lock() {
        interrupt_unsafe_region::lock();
        AcquireSRWLockExclusive((PSRWLOCK)&_mutex);
    }

    void mutex::unlock() {
        ReleaseSRWLockExclusive((PSRWLOCK)&_mutex);
        interrupt_unsafe_region::unlock();
    }

    bool mutex::try_lock() {
        interrupt_unsafe_region::lock();
        bool res = TryAcquireSRWLockExclusive((PSRWLOCK)&_mutex);
        if (!res)
            interrupt_unsafe_region::unlock();
        return res;
    }

    rw_mutex::rw_mutex() {
        _mutex = SRWLOCK_INIT;
    }

    rw_mutex::~rw_mutex() noexcept = default;

    void rw_mutex::lock() {
        interrupt_unsafe_region::lock();
        AcquireSRWLockExclusive((PSRWLOCK)&_mutex);
    }

    void rw_mutex::unlock() {
        ReleaseSRWLockExclusive((PSRWLOCK)&_mutex);
        interrupt_unsafe_region::unlock();
    }

    bool rw_mutex::try_lock() {
        interrupt_unsafe_region::lock();
        bool res = TryAcquireSRWLockExclusive((PSRWLOCK)&_mutex);
        if (!res)
            interrupt_unsafe_region::unlock();
        return res;
    }

    void rw_mutex::lock_shared() {
        interrupt_unsafe_region::lock();
        AcquireSRWLockShared((PSRWLOCK)&_mutex);
    }

    void rw_mutex::unlock_shared() {
        ReleaseSRWLockShared((PSRWLOCK)&_mutex);
        interrupt_unsafe_region::unlock();
    }

    bool rw_mutex::try_lock_shared() {
        interrupt_unsafe_region::lock();
        bool res = TryAcquireSRWLockShared((PSRWLOCK)&_mutex);
        if (!res)
            interrupt_unsafe_region::unlock();
        return res;
    }

    timed_mutex::timed_mutex() = default;

    timed_mutex::~timed_mutex() noexcept {
        assert(locked == 0 && "Thread tried to destroy locked mutex");
    }

    void timed_mutex::lock() {
        lock_guard<mutex> lock(_mutex);
        while (locked != 0)
            _cond.wait(_mutex);
        locked = UINT_MAX;
        interrupt_unsafe_region::lock();
    }

    void timed_mutex::unlock() {
        {
            lock_guard<mutex> lock(_mutex);
            locked = 0;
            interrupt_unsafe_region::unlock();
        }
        _cond.notify_one();
    }

    bool timed_mutex::try_lock() {
        lock_guard<mutex> lock(_mutex);
        if (locked == 0) {
            locked = UINT_MAX;
            interrupt_unsafe_region::lock();
            return true;
        } else
            return false;
    }

    bool timed_mutex::try_lock_for(std::chrono::milliseconds ms) {
        return try_lock_until(std::chrono::high_resolution_clock::now() + ms);
    }

    bool timed_mutex::try_lock_until(std::chrono::high_resolution_clock::time_point time) {
        lock_guard<mutex> lock(_mutex);
        while (locked != 0)
            if (_cond.wait_until(_mutex, time) == cv_status::timeout)
                return false;
        locked = UINT_MAX;
        interrupt_unsafe_region::lock();
        return true;
    }

    condition_variable::condition_variable() {
        _cond = CONDITION_VARIABLE_INIT;
    }

    condition_variable::~condition_variable() noexcept = default;

    void condition_variable::notify_one() {
        interrupt_unsafe_region region;
        WakeConditionVariable((PCONDITION_VARIABLE)&_cond);
    }

    void condition_variable::notify_all() {
        interrupt_unsafe_region region;
        WakeAllConditionVariable((PCONDITION_VARIABLE)&_cond);
    }

    void condition_variable::wait(mutex& mtx) {
        interrupt_unsafe_region region;
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
            interrupt_unsafe_region region;
            if (SleepConditionVariableSRW((PCONDITION_VARIABLE)&_cond, (PSRWLOCK)&mtx._mutex, wait_time, 0)) {
                return cv_status::no_timeout;
            } else {
                auto err = GetLastError();
                if (err == ERROR_TIMEOUT)
                    return cv_status::timeout;
                throw std::system_error(err, std::system_category());
            }
        }
    }

    void condition_variable::wait(recursive_mutex& mtx) {
        interrupt_unsafe_region region;
        auto state = mtx.relock_begin();
        if (SleepConditionVariableSRW((PCONDITION_VARIABLE)&_cond, (PSRWLOCK)&mtx.actual_mutex._mutex, INFINITE, 0)) {
            mtx.lock();
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
        interrupt_unsafe_region region;
        auto state = mtx.relock_begin();
        while (true) {
            auto sleep_ms = std::chrono::duration_cast<std::chrono::milliseconds>(time - std::chrono::high_resolution_clock::now());
            if (sleep_ms.count() <= 0)
                return cv_status::timeout;
            DWORD wait_time = sleep_ms.count() > 0x7FFFFFFF ? 0x7FFFFFFF : (DWORD)sleep_ms.count();
            bool res = SleepConditionVariableSRW((PCONDITION_VARIABLE)&_cond, (PSRWLOCK)&mtx.actual_mutex._mutex, wait_time, 0);
            DWORD err = res ? 0 : GetLastError();
            cv_status status = res ? cv_status::no_timeout : (err == ERROR_TIMEOUT ? cv_status::timeout : cv_status::no_timeout);
            mtx.lock();
            mtx.relock_end(state);
            if (!res && err != ERROR_TIMEOUT)
                throw std::system_error(err, std::system_category());
            return status;
        }
    }
#else
    mutex::mutex() {
        _mutex = new pthread_mutex_t;
        interrupt_unsafe_region region;
        pthread_mutex_init(_mutex, nullptr);
    }

    mutex::~mutex() noexcept {
        interrupt_unsafe_region region;
        int res = pthread_mutex_destroy(_mutex);
        if (res == EBUSY) {
            assert(false && "Thread tried todestroy locked mutex");
            std::terminate();
        }
        if (res == EINVAL) {
            assert(false && "Thread tried todestroy locked mutex");
            std::terminate();
        }
        delete _mutex;
    }

    void mutex::lock() {
        interrupt_unsafe_region::lock();
        int err = pthread_mutex_lock(_mutex);
        if (err) {
            if (err == EDEADLK)
                throw std::logic_error("Thread tried to lock already owned mutex");
            throw std::system_error(err, std::system_category());
        }
    }

    void mutex::unlock() {
        int err = pthread_mutex_unlock(_mutex);
        interrupt_unsafe_region::unlock();
        if (err) {
            if (err == EPERM)
                throw std::logic_error("Thread tried to unlock non-owned mutex");
            throw std::system_error(err, std::system_category());
        }
    }

    bool mutex::try_lock() {
        interrupt_unsafe_region::lock();
        int err = pthread_mutex_trylock(_mutex);
        if (err) {
            interrupt_unsafe_region::unlock();
            if (err == EBUSY)
                return false;
            throw std::system_error(err, std::system_category());
        }
        return true;
    }

    rw_mutex::rw_mutex() {
        interrupt_unsafe_region region;
        _mutex = new pthread_rwlock_t;
        pthread_rwlock_init(_mutex, nullptr);
    }

    rw_mutex::~rw_mutex() noexcept {
        interrupt_unsafe_region region;
        int res = pthread_rwlock_destroy(_mutex);

        if (res == EBUSY) {
            assert(false && "Thread tried to destroy locked mutex");
            std::terminate();
        }
        if (res == EINVAL) {
            assert(false && "Thread tried to destroy locked mutex");
            std::terminate();
        }
        delete _mutex;
    }

    void rw_mutex::lock() {
        interrupt_unsafe_region::lock();
        pthread_rwlock_wrlock(_mutex);
    }

    void rw_mutex::unlock() {
        pthread_rwlock_unlock(_mutex);
        interrupt_unsafe_region::unlock();
    }

    bool rw_mutex::try_lock() {
        interrupt_unsafe_region::lock();
        int err = pthread_rwlock_trywrlock(_mutex);
        if (err) {
            interrupt_unsafe_region::unlock();
            if (err == EBUSY || err == EAGAIN)
                return false;
            throw std::system_error(err, std::system_category());
        }
        return true;
    }

    void rw_mutex::lock_shared() {
        interrupt_unsafe_region::lock();
        pthread_rwlock_rdlock(_mutex);
    }

    void rw_mutex::unlock_shared() {
        pthread_rwlock_unlock(_mutex);
        interrupt_unsafe_region::unlock();
    }

    bool rw_mutex::try_lock_shared() {
        interrupt_unsafe_region::lock();
        int err = pthread_rwlock_tryrdlock(_mutex);
        if (err) {
            interrupt_unsafe_region::unlock();
            if (err == EBUSY || err == EAGAIN)
                return false;
            throw std::system_error(err, std::system_category());
        }
        return true;
    }

    timed_mutex::timed_mutex() {
        interrupt_unsafe_region region;
        _mutex = new pthread_mutex_t;
        pthread_mutex_init(_mutex, nullptr);
    }

    timed_mutex::~timed_mutex() noexcept {
        interrupt_unsafe_region region;
        int res = pthread_mutex_destroy(_mutex);
        if (res == EBUSY) {
            assert(false && "Thread tried to destroy locked mutex");
            std::terminate();
        }
        if (res == EINVAL) {
            assert(false && "Thread tried to destroy locked mutex");
            std::terminate();
        }
        delete _mutex;
    }

    void timed_mutex::lock() {
        interrupt_unsafe_region::lock();
        int err = pthread_mutex_lock(_mutex);
        if (err) {
            if (err == EDEADLK)
                throw std::logic_error("Thread tried to lock already owned mutex");
            throw std::system_error(err, std::system_category());
        }
    }

    void timed_mutex::unlock() {
        int err = pthread_mutex_unlock(_mutex);
        interrupt_unsafe_region::unlock();
        if (err) {
            if (err == EPERM)
                throw std::logic_error("Thread tried to unlock non-owned mutex");
            throw std::system_error(err, std::system_category());
        }
    }

    bool timed_mutex::try_lock() {
        interrupt_unsafe_region::lock();
        int err = pthread_mutex_trylock(_mutex);
        if (err) {
            interrupt_unsafe_region::unlock();
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
        interrupt_unsafe_region region;
        while (true) {
            if (time <= std::chrono::high_resolution_clock::now())
                return false;
            timespec ts = to_abs_timespec(time);
            int err = pthread_mutex_timedlock(_mutex, &ts);
            if (err == 0) {
                interrupt_unsafe_region::lock();
                return true;
            }
            if (err != ETIMEDOUT)
                throw std::system_error(err, std::system_category());
        }
    }

    condition_variable::condition_variable() {
        interrupt_unsafe_region region;
        _cond = new pthread_cond_t;
        pthread_cond_init(_cond, nullptr);
    }

    condition_variable::~condition_variable() noexcept {
        interrupt_unsafe_region region;
        int res = pthread_cond_destroy(_cond);
        if (res == EBUSY)
            assert(false && "Thread tried to destroy used condition variable(ie. some thread is waiting on it)");
        if (res == EINVAL)
            assert(false && "Thread tried to destroy invalid condition variable");
        delete _cond;
    }

    void condition_variable::notify_one() {
        interrupt_unsafe_region region;
        int err = pthread_cond_signal(_cond);
        if (err)
            throw std::system_error(err, std::system_category());
    }

    void condition_variable::notify_all() {
        interrupt_unsafe_region region;
        int err = pthread_cond_broadcast(_cond);
        if (err)
            throw std::system_error(err, std::system_category());
    }

    void condition_variable::wait(mutex& mtx) {
        interrupt_unsafe_region region;
        int err = pthread_cond_wait(_cond, mtx._mutex);
        if (err)
            throw std::system_error(err, std::system_category());
    }

    cv_status condition_variable::wait_for(mutex& mtx, std::chrono::milliseconds ms) {
        return wait_until(mtx, std::chrono::high_resolution_clock::now() + ms);
    }

    cv_status condition_variable::wait_until(mutex& mtx, std::chrono::high_resolution_clock::time_point time) {
        interrupt_unsafe_region region;
        while (true) {
            if (time <= std::chrono::high_resolution_clock::now())
                return cv_status::timeout;
            timespec ts = to_abs_timespec(time);
            if (pthread_cond_timedwait(_cond, mtx._mutex, &ts) == 0)
                return cv_status::no_timeout;
        }
        return cv_status::no_timeout;
    }

    void condition_variable::wait(recursive_mutex& mtx) {
        interrupt_unsafe_region region;
        int err = pthread_cond_wait(_cond, mtx.actual_mutex._mutex);
        if (err)
            throw std::system_error(err, std::system_category());
    }

    cv_status condition_variable::wait_for(recursive_mutex& mtx, std::chrono::milliseconds ms) {
        return wait_until(mtx, std::chrono::high_resolution_clock::now() + ms);
    }

    cv_status condition_variable::wait_until(recursive_mutex& mtx, std::chrono::high_resolution_clock::time_point time) {
        interrupt_unsafe_region region;
        while (true) {
            if (time <= std::chrono::high_resolution_clock::now())
                return cv_status::timeout;
            timespec ts = to_abs_timespec(time);
            if (pthread_cond_timedwait(_cond, mtx.actual_mutex._mutex, &ts) == 0)
                return cv_status::no_timeout;
        }
        return cv_status::no_timeout;
    }
#endif

    recursive_mutex::recursive_mutex() {
        count = 0;
        owner = thread::id();
    }

    recursive_mutex::~recursive_mutex() noexcept {
        if (owner != thread::id()) {
            assert(false && "Recursive mutex destroyed while locked");
            std::terminate();
        }
    }

    void recursive_mutex::lock() {
        interrupt_unsafe_region region;
        if (owner == this_thread::get_id()) {
            count++;
            if (count == 0) {
                count--;
                throw std::logic_error("Recursive mutex overflow");
            }
            return;
        }
        actual_mutex.lock();
        owner = this_thread::get_id();
        count = 1;
    }

    void recursive_mutex::unlock() {
        interrupt_unsafe_region region;
        if (owner != this_thread::get_id()) {
            throw std::logic_error("Thread tried to unlock non-owned mutex");
        }
        count--;
        if (count == 0) {
            owner = thread::id();
            actual_mutex.unlock();
        }
    }

    bool recursive_mutex::try_lock() {
        interrupt_unsafe_region region;
        if (owner == this_thread::get_id()) {
            count++;
            return true;
        }
        if (actual_mutex.try_lock()) {
            owner = this_thread::get_id();
            count = 1;
            return true;
        }
        return false;
    }

    recursive_mutex::relock_state recursive_mutex::relock_begin() {
        if (owner != this_thread::get_id())
            throw std::logic_error("Thread tried to relock non-owned mutex");
        size_t _count = count;
        count = 1;
        return relock_state(_count);
    }

    void recursive_mutex::relock_end(relock_state state) {
        if (owner != this_thread::get_id())
            throw std::logic_error("Thread tried to relock non-owned mutex");
        count = state._state;
        owner = this_thread::get_id();
    }

    void condition_variable_any::notify_one() {
        interrupt_unsafe_region region;
        lock_guard<mutex> lock(_mutex);
        _cond.notify_one();
    }

    void condition_variable_any::notify_all() {
        interrupt_unsafe_region region;
        lock_guard<mutex> lock(_mutex);
        _cond.notify_all();
    }

    void condition_variable_any::unsafe_notify_one() {
        _cond.notify_one();
    }

    void condition_variable_any::unsafe_notify_all() {
        _cond.notify_all();
    }
}