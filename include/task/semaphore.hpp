// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_INCLUDE_TASK_SEMAPHORE
#define FAST_TASK_INCLUDE_TASK_SEMAPHORE

#include "../native.hpp"
#include "enter_state.hpp"
#include "fwd.hpp"
#include <atomic>
#include <list>

namespace fast_task {
    class FT_API semaphore {
        friend struct debug::_debug_collect;

        struct private_values {
            std::atomic_size_t state;
            std::atomic_size_t max_threshold;
        } values;

    public:
        semaphore();
        ~semaphore();

        void set_max_threshold(size_t val);
        void lock();
        bool try_lock();
        bool try_lock_until(std::chrono::high_resolution_clock::time_point time_point);
        void release();
        void release_all();
        bool is_locked();

        bool enter_wait(const task&, enter_state& task);
        bool enter_wait_until(const task&, enter_state& task, std::chrono::high_resolution_clock::time_point);

        template <class Rep, class Period>
        bool try_lock_for(const std::chrono::duration<Rep, Period>& duration) {
            return try_lock_until(std::chrono::high_resolution_clock::now() + duration);
        }
    };

    //same as semaphore but with checks
    class FT_API limiter {
        friend struct debug::_debug_collect;
        friend class mutex_unify;

        struct private_values {
            std::list<size_t> lock_check;
            fast_task::native::spin_lock lock_check_lock;
            std::atomic_size_t state;
            std::atomic_size_t max_threshold;
        } values;

        void unchecked_unlock();
        void check_deadlock(size_t lock_id);

    public:
        limiter();
        ~limiter();

        void set_max_threshold(size_t val);
        void lock();
        bool try_lock();
        bool try_lock_until(std::chrono::high_resolution_clock::time_point time_point);
        void unlock();
        bool is_locked();

        bool enter_wait(const task&, enter_state& task);
        bool enter_wait_until(const task&, enter_state& task, std::chrono::high_resolution_clock::time_point);

        template <class Rep, class Period>
        bool try_lock_for(const std::chrono::duration<Rep, Period>& duration) {
            return try_lock_until(std::chrono::high_resolution_clock::now() + duration);
        }
    };
}

#endif /* FAST_TASK_INCLUDE_TASK_SEMAPHORE */
