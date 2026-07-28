// Copyright Danyil Melnytskyi 2022-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_INCLUDE_NATIVE_MUTEX
#define FAST_TASK_INCLUDE_NATIVE_MUTEX
#include "../shared.hpp"
#include "../shared/primitives.hpp"
#include "thread.hpp"
#include <chrono>
#include <cstdint>
#include <memory>
#include <tuple>
#include <type_traits>

namespace fast_task::native {
    class FT_API mutex {
        friend class condition_variable;
#ifdef _WIN32
        void* _mutex;
#else
        pthread_mutex_t* _mutex;
#endif
    public:
        mutex();
        mutex(const mutex& other) = delete;
        mutex(mutex&& other) = delete;
        mutex& operator=(const mutex& other) = delete;
        mutex& operator=(mutex&& other) = delete;
        ~mutex() noexcept;
        void lock();
        void unlock();
        bool try_lock();
    };

    class FT_API rw_mutex {
        friend class condition_variable;
#ifdef _WIN32
        void* _mutex;
#else
        pthread_rwlock_t* _mutex;
#endif
    public:
        using read_write_mutex = void;
        rw_mutex();
        rw_mutex(const rw_mutex& other) = delete;
        rw_mutex(rw_mutex&& other) = delete;
        rw_mutex& operator=(const rw_mutex& other) = delete;
        rw_mutex& operator=(rw_mutex&& other) = delete;
        ~rw_mutex() noexcept;
        void lock();
        void unlock();
        bool try_lock();

        void lock_shared();
        void unlock_shared();
        bool try_lock_shared();
    };

    class FT_API recursive_mutex {
        friend class condition_variable;
        mutex actual_mutex;
        size_t count = 0;
        thread::id owner;

    public:
        struct FT_API relock_state {
            size_t _state;
        };
        recursive_mutex();
        recursive_mutex(const recursive_mutex& other) = delete;
        recursive_mutex(recursive_mutex&& other) = delete;
        recursive_mutex& operator=(const recursive_mutex& other) = delete;
        recursive_mutex& operator=(recursive_mutex&& other) = delete;
        ~recursive_mutex() noexcept;
        void lock();
        void unlock();
        bool try_lock();

        relock_state relock_begin();
        void relock_end(relock_state state);
    };

    class FT_API timed_mutex {
        friend class condition_variable;
#ifdef _WIN32
        condition_variable _cond;
        mutex _mutex;
        unsigned int locked = 0;
#else
        pthread_mutex_t* _mutex;
#endif
    public:
        timed_mutex();
        timed_mutex(const timed_mutex& other) = delete;
        timed_mutex(timed_mutex&& other) = delete;
        timed_mutex& operator=(const timed_mutex& other) = delete;
        timed_mutex& operator=(timed_mutex&& other) = delete;
        ~timed_mutex() noexcept;
        void lock();
        void unlock();
        bool try_lock();
        bool try_lock_for(std::chrono::milliseconds ms);
        bool try_lock_until(std::chrono::high_resolution_clock::time_point time);
    };
}

#endif /* FAST_TASK_INCLUDE_NATIVE_MUTEX */