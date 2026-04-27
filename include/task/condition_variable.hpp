// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef INCLUDE_TASK_CONDITION_VARIABLE
#define INCLUDE_TASK_CONDITION_VARIABLE
#include "fwd.hpp"
#include "mutex_unify.hpp"
#include <list>
#include <mutex>

namespace fast_task {
    class FT_API task_condition_variable {
        friend struct debug::_debug_collect;
        struct FT_API_LOCAL resume_task;

        struct FT_API_LOCAL private_values {
            std::list<struct resume_task> resume_task;
            fast_task::mutex no_race;
        } values;

    public:
        task_condition_variable();
        ~task_condition_variable();
        void wait(fast_task::unique_lock<mutex_unify>& lock);
        bool wait_until(fast_task::unique_lock<mutex_unify>& lock, std::chrono::high_resolution_clock::time_point time_point);
        void wait(std::unique_lock<mutex_unify>& lock);
        bool wait_until(std::unique_lock<mutex_unify>& lock, std::chrono::high_resolution_clock::time_point time_point);
        void notify_one();
        void notify_all();
        bool has_waiters();
        void callback(fast_task::unique_lock<mutex_unify>& mut, const std::shared_ptr<task>& task);
        void callback(std::unique_lock<mutex_unify>& mut, const std::shared_ptr<task>& task);

        bool enter_wait(mutex_unify& mut, const std::shared_ptr<task>& task);                                                       //always returns false, requires mut to be locked
        bool enter_wait_until(mutex_unify& mut, const std::shared_ptr<task>& task, std::chrono::high_resolution_clock::time_point); //could return true on early timeout, requires mut to be locked

        template <class Rep, class Period>
        bool wait_for(fast_task::unique_lock<mutex_unify>& lock, const std::chrono::duration<Rep, Period>& duration) {
            return wait_until(lock, std::chrono::high_resolution_clock::now() + duration);
        }

        template <class Rep, class Period>
        bool wait_for(std::unique_lock<mutex_unify>& lock, const std::chrono::duration<Rep, Period>& duration) {
            return wait_until(lock, std::chrono::high_resolution_clock::now() + duration);
        }
    };
}

#endif /* INCLUDE_TASK_CONDITION_VARIABLE */
