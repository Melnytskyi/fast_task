// Copyright Danyil Melnytskyi 2022-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <fast_task/native/condition_variable.hpp>
#include <fast_task/native/mutex.hpp>
#include <tasks/util/interrupt.hpp>

#include <cassert>
#include <errno.h>
#include <exception>

#ifdef _WIN32
    #ifndef NOMINMAX
        #define NOMINMAX
    #endif
    #include <Windows.h>
#else
    #include <chrono>
    #include <limits>

    #include <pthread.h>
    #include <semaphore.h>
    #include <signal.h>
    #include <time.h>
    #include <ucontext.h>

// Absolute CLOCK_MONOTONIC timespec for a fast_task::time_point. The
// condition_variable objects below are created with
// pthread_condattr_setclock(CLOCK_MONOTONIC) whenever the libc allows it, so
// their absolute deadlines and fast_task::clock share one time base.
// Returns false for the "no deadline" sentinel.
static bool to_abs_timespec(fast_task::time_point time, timespec& ts) {
    if (fast_task::is_no_deadline(time))
        return false;
    if (time == fast_task::time_point::max()) {
        // Far future, but still representable as a timespec.
        ts.tv_sec = static_cast<time_t>(std::numeric_limits<time_t>::max() / 2);
        ts.tv_nsec = 999999999L;
        return true;
    }
    const auto since_epoch = time.time_since_epoch();
    const auto secs = std::chrono::duration_cast<std::chrono::seconds>(since_epoch);
    const auto nsecs = std::chrono::duration_cast<std::chrono::nanoseconds>(since_epoch - secs);
    ts.tv_sec = static_cast<time_t>(secs.count());
    ts.tv_nsec = static_cast<long>(nsecs.count());
    if (ts.tv_nsec < 0) {
        ts.tv_sec -= 1;
        ts.tv_nsec += 1000000000L;
    }
    return true;
}

// Absolute CLOCK_REALTIME timespec for the same monotonic deadline. Used by the
// pthread primitives that have no monotonic variant here, and by condition
// variables whose setclock() call failed. The wall-clock step risk is confined
// to those two paths.
static bool to_abs_realtime_timespec(fast_task::time_point time, timespec& ts) {
    if (fast_task::is_no_deadline(time))
        return false;
    if (time == fast_task::time_point::max()) {
        ts.tv_sec = static_cast<time_t>(std::numeric_limits<time_t>::max() / 2);
        ts.tv_nsec = 999999999L;
        return true;
    }
    clock_gettime(CLOCK_REALTIME, &ts);
    const auto remaining = time - fast_task::clock::now();
    if (remaining <= fast_task::duration::zero())
        return true; // already expired, callers re-check the clock
    const auto secs = std::chrono::duration_cast<std::chrono::seconds>(remaining);
    const auto nsecs = std::chrono::duration_cast<std::chrono::nanoseconds>(remaining - secs);
    ts.tv_sec += static_cast<time_t>(secs.count());
    ts.tv_nsec += static_cast<long>(nsecs.count());
    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec += 1;
        ts.tv_nsec -= 1000000000L;
    }
    return true;
}

// Whether pthread_condattr_setclock(CLOCK_MONOTONIC) works on this libc. The
// answer is process wide, so it is probed exactly once.
static bool condvar_monotonic() noexcept {
    static const bool supported = [] {
        pthread_condattr_t attr;
        if (pthread_condattr_init(&attr) != 0)
            return false;
        const bool ok = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC) == 0;
        pthread_condattr_destroy(&attr);
        return ok;
    }();
    return supported;
}

    // pthread_mutex_clocklock landed in glibc 2.30 and is only declared when
    // _GNU_SOURCE is visible. Everything else converts the monotonic deadline to a
    // realtime one and uses pthread_mutex_timedlock.
    #if defined(__linux__) && defined(_GNU_SOURCE) && defined(__GLIBC__) && \
        (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 30))
        #define FAST_TASK_HAS_PTHREAD_MUTEX_CLOCKLOCK 1
    #else
        #define FAST_TASK_HAS_PTHREAD_MUTEX_CLOCKLOCK 0
    #endif
#endif

namespace fast_task::native {
#ifdef _WIN32
    static cv_status win32_wait_until_srw(void* cond_ptr, void* srw_ptr, fast_task::time_point time) {
        if (fast_task::is_no_deadline(time))
            return cv_status::timeout;
        if (time == fast_task::time_point::max()) {
            interrupt_unsafe_region region;
            if (!SleepConditionVariableSRW((PCONDITION_VARIABLE)cond_ptr, (PSRWLOCK)srw_ptr, INFINITE, 0))
                throw std::system_error(static_cast<int>(GetLastError()), std::system_category());
            return cv_status::no_timeout;
        }
        while (true) {
            const auto now = fast_task::clock::now();
            if (now >= time)
                return cv_status::timeout;
            const auto sleep_ms = std::chrono::ceil<std::chrono::milliseconds>(time - now);
            const auto count = sleep_ms.count();
            const DWORD wait_time = count > 0x7FFFFFFF ? 0x7FFFFFFF : (count <= 0 ? 1 : static_cast<DWORD>(count));
            interrupt_unsafe_region region;
            if (SleepConditionVariableSRW((PCONDITION_VARIABLE)cond_ptr, (PSRWLOCK)srw_ptr, wait_time, 0))
                return cv_status::no_timeout;
            const DWORD err = GetLastError();
            if (err == ERROR_TIMEOUT) {
                if (fast_task::clock::now() >= time)
                    return cv_status::timeout;
                continue;
            }
            throw std::system_error(static_cast<int>(err), std::system_category());
        }
    }

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

    timed_mutex::timed_mutex()
        : _cond(nullptr) {
        InitializeConditionVariable(reinterpret_cast<PCONDITION_VARIABLE>(&_cond));
    }

    timed_mutex::~timed_mutex() noexcept {
        assert(locked == 0 && "Thread tried to destroy locked mutex");
    }

    void timed_mutex::lock() {
        lock_guard<mutex> lock(_mutex);
        while (locked != 0) {
            interrupt_unsafe_region region;
            if (!SleepConditionVariableSRW((PCONDITION_VARIABLE)&_cond, (PSRWLOCK)&_mutex._mutex, INFINITE, 0))
                throw std::system_error(static_cast<int>(GetLastError()), std::system_category());
        }
        locked = UINT_MAX;
        interrupt_unsafe_region::lock();
    }

    void timed_mutex::unlock() {
        {
            lock_guard<mutex> lock(_mutex);
            locked = 0;
            interrupt_unsafe_region::unlock();
        }
        interrupt_unsafe_region region;
        WakeConditionVariable((PCONDITION_VARIABLE)&_cond);
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
        return try_lock_until(fast_task::clock::now() + ms);
    }

    bool timed_mutex::try_lock_until(fast_task::time_point time) {
        lock_guard<mutex> lock(_mutex);
        while (locked != 0)
            if (win32_wait_until_srw(&_cond, &_mutex._mutex, time) == cv_status::timeout)
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
        // SleepConditionVariableSRW returns non-zero on success, so GetLastError
        // is only meaningful after a failure. The previous check threw whenever
        // the leftover error code of an earlier call was non-zero.
        if (!SleepConditionVariableSRW((PCONDITION_VARIABLE)&_cond, (PSRWLOCK)&mtx._mutex, INFINITE, 0))
            throw std::system_error(static_cast<int>(GetLastError()), std::system_category());
    }

    cv_status condition_variable::wait_for(mutex& mtx, std::chrono::milliseconds ms) {
        return wait_until(mtx, fast_task::clock::now() + ms);
    }

    cv_status condition_variable::wait_until(mutex& mtx, fast_task::time_point time) {
        return win32_wait_until_srw(&_cond, &mtx._mutex, time);
    }

    void condition_variable::wait(recursive_mutex& mtx) {
        struct recursive_cv_wait_guard {
            recursive_mutex& m;
            unsigned long self;
            recursive_mutex::relock_state state;

            explicit recursive_cv_wait_guard(recursive_mutex& rm)
                : m(rm), self(this_thread::get_id()._id), state(rm.relock_begin()) {
                m.count = 0;
                m.owner.store(0, std::memory_order_release);
            }

            ~recursive_cv_wait_guard() {
                m.owner.store(self, std::memory_order_release);
                m.relock_end(state);
            }
        };

        interrupt_unsafe_region region;
        recursive_cv_wait_guard guard(mtx);
        // SleepConditionVariableSRW atomically releases and reacquires actual_mutex._mutex.
        if (!SleepConditionVariableSRW((PCONDITION_VARIABLE)&_cond, (PSRWLOCK)&mtx.actual_mutex._mutex, INFINITE, 0))
            throw std::system_error(static_cast<int>(GetLastError()), std::system_category());
    }

    cv_status condition_variable::wait_for(recursive_mutex& mtx, std::chrono::milliseconds ms) {
        return wait_until(mtx, fast_task::clock::now() + ms);
    }

    cv_status condition_variable::wait_until(recursive_mutex& mtx, fast_task::time_point time) {
        struct recursive_cv_wait_guard {
            recursive_mutex& m;
            unsigned long self;
            recursive_mutex::relock_state state;

            explicit recursive_cv_wait_guard(recursive_mutex& rm)
                : m(rm), self(this_thread::get_id()._id), state(rm.relock_begin()) {
                m.count = 0;
                m.owner.store(0, std::memory_order_release);
            }

            ~recursive_cv_wait_guard() {
                m.owner.store(self, std::memory_order_release);
                m.relock_end(state);
            }
        };

        recursive_cv_wait_guard guard(mtx);
        return win32_wait_until_srw(&_cond, &mtx.actual_mutex._mutex, time);
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
            interrupt_unsafe_region::unlock();
            if (err == EDEADLK)
                throw std::logic_error("Thread tried to lock already owned mutex");
            throw std::system_error(err, std::system_category());
        }
    }

    void mutex::unlock() {
        int err = pthread_mutex_unlock(_mutex);
        if (err) {
            if (err == EPERM)
                throw std::logic_error("Thread tried to unlock non-owned mutex");
            throw std::system_error(err, std::system_category());
        }
        interrupt_unsafe_region::unlock();
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
        int err = pthread_rwlock_wrlock(_mutex);
        if (err) {
            interrupt_unsafe_region::unlock();
            if (err == EDEADLK)
                throw std::logic_error("Thread tried to lock already owned mutex");
            throw std::system_error(err, std::system_category());
        }
    }

    void rw_mutex::unlock() {
        int err = pthread_rwlock_unlock(_mutex);
        if (err) {
            if (err == EPERM)
                throw std::logic_error("Thread tried to unlock non-owned mutex");
            throw std::system_error(err, std::system_category());
        }
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
        int err = pthread_rwlock_rdlock(_mutex);
        if (err) {
            interrupt_unsafe_region::unlock();
            if (err == EDEADLK)
                throw std::logic_error("Thread tried to lock already owned mutex");
            throw std::system_error(err, std::system_category());
        }
    }

    void rw_mutex::unlock_shared() {
        int err = pthread_rwlock_unlock(_mutex);
        if (err) {
            if (err == EPERM)
                throw std::logic_error("Thread tried to unlock non-owned mutex");
            throw std::system_error(err, std::system_category());
        }
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
            interrupt_unsafe_region::unlock();
            if (err == EDEADLK)
                throw std::logic_error("Thread tried to lock already owned mutex");
            throw std::system_error(err, std::system_category());
        }
    }

    void timed_mutex::unlock() {
        int err = pthread_mutex_unlock(_mutex);
        if (err) {
            if (err == EPERM)
                throw std::logic_error("Thread tried to unlock non-owned mutex");
            throw std::system_error(err, std::system_category());
        }
        interrupt_unsafe_region::unlock();
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
        return try_lock_until(fast_task::clock::now() + ms);
    }

    bool timed_mutex::try_lock_until(fast_task::time_point time) {
        interrupt_unsafe_region region;
        if (time == fast_task::time_point::max()) {
            int err = pthread_mutex_lock(_mutex);
            if (err)
                throw std::system_error(err, std::system_category());
            interrupt_unsafe_region::lock();
            return true;
        }
        while (true) {
            if (time <= fast_task::clock::now())
                return false;
            timespec ts;
    #if FAST_TASK_HAS_PTHREAD_MUTEX_CLOCKLOCK
            to_abs_timespec(time, ts);
            int err = pthread_mutex_clocklock(_mutex, CLOCK_MONOTONIC, &ts);
    #else
            to_abs_realtime_timespec(time, ts);
            int err = pthread_mutex_timedlock(_mutex, &ts);
    #endif
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
        // pthread_cond_timedwait takes an absolute deadline, so the condition
        // variable must be created on CLOCK_MONOTONIC: that is the only way its
        // deadline base matches fast_task::clock, and it keeps the wait immune
        // to wall-clock steps.
        if (condvar_monotonic()) {
            pthread_condattr_t attr;
            pthread_condattr_init(&attr);
            pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
            pthread_cond_init(_cond, &attr);
            pthread_condattr_destroy(&attr);
        } else {
            pthread_cond_init(_cond, nullptr);
        }
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
        return wait_until(mtx, fast_task::clock::now() + ms);
    }

    cv_status condition_variable::wait_until(mutex& mtx, fast_task::time_point time) {
        interrupt_unsafe_region region;
        if (fast_task::is_no_deadline(time))
            return cv_status::timeout;
        if (time == fast_task::time_point::max()) {
            // A "no deadline" wait must block, not spin on an overflown timespec.
            int err = pthread_cond_wait(_cond, mtx._mutex);
            if (err)
                throw std::system_error(err, std::system_category());
            return cv_status::no_timeout;
        }
        while (true) {
            if (time <= fast_task::clock::now())
                return cv_status::timeout;
            timespec ts;
            if (condvar_monotonic())
                to_abs_timespec(time, ts);
            else
                to_abs_realtime_timespec(time, ts);
            int err = pthread_cond_timedwait(_cond, mtx._mutex, &ts);
            if (err == 0)
                return cv_status::no_timeout;
            if (err != ETIMEDOUT)
                throw std::system_error(err, std::system_category());
        }
    }

    void condition_variable::wait(recursive_mutex& mtx) {
        struct recursive_cv_wait_guard {
            recursive_mutex& m;
            unsigned long self;
            recursive_mutex::relock_state state;

            explicit recursive_cv_wait_guard(recursive_mutex& rm)
                : m(rm), self(this_thread::get_id()._id), state(rm.relock_begin()) {
                m.count = 0;
                m.owner.store(0, std::memory_order_release);
            }

            ~recursive_cv_wait_guard() {
                m.owner.store(self, std::memory_order_release);
                m.relock_end(state);
            }
        };

        interrupt_unsafe_region region;
        recursive_cv_wait_guard guard(mtx);
        int err = pthread_cond_wait(_cond, mtx.actual_mutex._mutex);
        if (err)
            throw std::system_error(err, std::system_category());
    }

    cv_status condition_variable::wait_for(recursive_mutex& mtx, std::chrono::milliseconds ms) {
        return wait_until(mtx, fast_task::clock::now() + ms);
    }

    cv_status condition_variable::wait_until(recursive_mutex& mtx, fast_task::time_point time) {
        struct recursive_cv_wait_guard {
            recursive_mutex& m;
            unsigned long self;
            recursive_mutex::relock_state state;

            explicit recursive_cv_wait_guard(recursive_mutex& rm)
                : m(rm), self(this_thread::get_id()._id), state(rm.relock_begin()) {
                m.count = 0;
                m.owner.store(0, std::memory_order_release);
            }

            ~recursive_cv_wait_guard() {
                m.owner.store(self, std::memory_order_release);
                m.relock_end(state);
            }
        };

        interrupt_unsafe_region region;
        recursive_cv_wait_guard guard(mtx);
        if (fast_task::is_no_deadline(time))
            return cv_status::timeout;
        if (time == fast_task::time_point::max()) {
            int err = pthread_cond_wait(_cond, mtx.actual_mutex._mutex);
            if (err)
                throw std::system_error(err, std::system_category());
            return cv_status::no_timeout;
        }
        while (true) {
            if (time <= fast_task::clock::now())
                return cv_status::timeout;
            timespec ts;
            if (condvar_monotonic())
                to_abs_timespec(time, ts);
            else
                to_abs_realtime_timespec(time, ts);
            int err = pthread_cond_timedwait(_cond, mtx.actual_mutex._mutex, &ts);
            if (err == 0)
                return cv_status::no_timeout;
            if (err != ETIMEDOUT)
                throw std::system_error(err, std::system_category());
        }
    }
#endif

    recursive_mutex::recursive_mutex() {
        count = 0;
        owner.store(0, std::memory_order_relaxed);
    }

    recursive_mutex::~recursive_mutex() noexcept {
        if (owner.load(std::memory_order_acquire) != 0) {
            assert(false && "Recursive mutex destroyed while locked");
            std::terminate();
        }
    }

    void recursive_mutex::lock() {
        interrupt_unsafe_region region;
        const unsigned long self = this_thread::get_id()._id;
        if (owner.load(std::memory_order_acquire) == self) {
            count++;
            if (count == 0) {
                count--;
                throw std::logic_error("Recursive mutex overflow");
            }
            return;
        }
        actual_mutex.lock();
        owner.store(self, std::memory_order_release);
        count = 1;
    }

    void recursive_mutex::unlock() {
        interrupt_unsafe_region region;
        const unsigned long self = this_thread::get_id()._id;
        if (owner.load(std::memory_order_acquire) != self) {
            throw std::logic_error("Thread tried to unlock non-owned mutex");
        }
        count--;
        if (count == 0) {
            owner.store(0, std::memory_order_release);
            actual_mutex.unlock();
        }
    }

    bool recursive_mutex::try_lock() {
        interrupt_unsafe_region region;
        const unsigned long self = this_thread::get_id()._id;
        if (owner.load(std::memory_order_acquire) == self) {
            count++;
            if (count == 0) {
                count--;
                throw std::logic_error("Recursive mutex overflow");
            }
            return true;
        }
        if (actual_mutex.try_lock()) {
            owner.store(self, std::memory_order_release);
            count = 1;
            return true;
        }
        return false;
    }

    recursive_mutex::relock_state recursive_mutex::relock_begin() {
        if (owner.load(std::memory_order_acquire) != this_thread::get_id()._id)
            throw std::logic_error("Thread tried to relock non-owned mutex");
        size_t _count = count;
        count = 1;
        return relock_state(_count);
    }

    void recursive_mutex::relock_end(relock_state state) {
        const unsigned long self = this_thread::get_id()._id;
        if (owner.load(std::memory_order_acquire) != self)
            throw std::logic_error("Thread tried to relock non-owned mutex");
        count = state._state;
        owner.store(self, std::memory_order_release);
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