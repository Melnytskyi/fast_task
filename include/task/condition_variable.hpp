// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef INCLUDE_TASK_CONDITION_VARIABLE
#define INCLUDE_TASK_CONDITION_VARIABLE
#include "enter_state.hpp"
#include "fwd.hpp"
#include "threading.hpp"
#include <mutex>

namespace fast_task {
    class FT_API task_condition_variable {
        friend struct debug::_debug_collect;
        struct FT_API_LOCAL resume_task;

        struct FT_API_LOCAL private_values {
            fast_task::spin_lock no_race;
            struct resume_task* begin;
            struct resume_task* end;
        } values;

        static void push_back(private_values& values, resume_task* node);
        static void erase(private_values& values, resume_task* node);

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

        // For use when the caller already holds glob.task_thread_safety shared.
        // Snapshotting resume_task under that shared lock closes the lost-wakeup
        // window that exists when notify_all() is called without any outer
        // synchronisation on glob.task_thread_safety.  Must NOT be called while
        // holding glob.task_thread_safety exclusively.
        FT_API_LOCAL void notify_all_guarded();
        void callback(fast_task::unique_lock<mutex_unify>& mut, const task& task);
        void callback(std::unique_lock<mutex_unify>& mut, const task& task);

        bool enter_wait(mutex_unify& mut, const task& task, enter_state&);                                                       //always returns false, requires mut to be locked
        bool enter_wait_until(mutex_unify& mut, const task& task, enter_state&, std::chrono::high_resolution_clock::time_point); //could return true on early timeout, requires mut to be locked

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
