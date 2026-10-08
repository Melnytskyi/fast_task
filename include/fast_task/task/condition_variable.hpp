// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_INCLUDE_TASK_CONDITION_VARIABLE
#define FAST_TASK_INCLUDE_TASK_CONDITION_VARIABLE
#include "enter_state.hpp"
#include "fwd.hpp"
#include "mutex.hpp"
#include <mutex>

namespace fast_task {
    class FT_API condition_variable {
        friend struct debug::_debug_collect;
        std::atomic_uint8_t address;

    public:
        condition_variable();
        ~condition_variable();
        void wait(fast_task::unique_lock<mutex>& lock);
        bool wait_until(fast_task::unique_lock<mutex>& lock, std::chrono::high_resolution_clock::time_point time_point);
        void wait(std::unique_lock<mutex>& lock);
        bool wait_until(std::unique_lock<mutex>& lock, std::chrono::high_resolution_clock::time_point time_point);
        void notify_one();
        void notify_all();
        bool has_waiters();

        void callback(fast_task::unique_lock<mutex>& mut, const task& task);
        void callback(std::unique_lock<mutex>& mut, const task& task);

        bool enter_wait(mutex& mut, const task& task, enter_state&);                                                       //always returns false, requires mut to be locked
        bool enter_wait_until(mutex& mut, const task& task, enter_state&, std::chrono::high_resolution_clock::time_point); //could return true on early timeout, requires mut to be locked

        template <class Rep, class Period>
        bool wait_for(fast_task::unique_lock<mutex>& lock, const std::chrono::duration<Rep, Period>& duration) {
            return wait_until(lock, std::chrono::high_resolution_clock::now() + duration);
        }

        template <class Rep, class Period>
        bool wait_for(std::unique_lock<mutex>& lock, const std::chrono::duration<Rep, Period>& duration) {
            return wait_until(lock, std::chrono::high_resolution_clock::now() + duration);
        }
    };

    class FT_API condition_variable_any {
        mutex _mutex;
        condition_variable _cond;

    public:
        condition_variable_any() = default;

        void notify_one() {
            lock_guard<mutex> lock(_mutex);
            _cond.notify_one();
        }

        void notify_all() {
            lock_guard<mutex> lock(_mutex);
            _cond.notify_all();
        }

        bool has_waiters() {
            return _cond.has_waiters();
        }

        template <class mut>
        void wait(mut& mtx) {
            fast_task::unique_lock<mutex> lock(_mutex);
            relock_guard<mut> relock(mtx);
            _cond.wait(lock);
            lock.unlock();
        }

        template <class mut>
        bool wait_for(mut& mtx, std::chrono::milliseconds ms) {
            return wait_until(mtx, std::chrono::high_resolution_clock::now() + ms);
        }

        template <class mut>
        bool wait_until(mut& mtx, std::chrono::high_resolution_clock::time_point time) {
            fast_task::unique_lock<mutex> lock(_mutex);
            relock_guard<mut> relock(mtx);
            bool ret = _cond.wait_until(lock, time);
            lock.unlock();
            return ret;
        }
    };
}

#endif /* FAST_TASK_INCLUDE_TASK_CONDITION_VARIABLE */
