// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef INCLUDE_TASK_DEADLINE_TIMER
#define INCLUDE_TASK_DEADLINE_TIMER
#include "fwd.hpp"
#include "mutex_unify.hpp"
#include <functional>
#include <mutex>

namespace fast_task {
    class FT_API deadline_timer {
        friend struct debug::_debug_collect;
        struct handle;
        handle* hh;

    public:
        enum class status {
            timeouted, //normal timeout
            canceled,  //set when used cancel,cancel_one, expires_from_now or expires_at
            shutdown,  //set when deadline_timer is destructed
        };
        deadline_timer();
        deadline_timer(std::chrono::high_resolution_clock::duration);
        deadline_timer(std::chrono::high_resolution_clock::time_point);
        deadline_timer(deadline_timer&&);
        ~deadline_timer();

        deadline_timer& operator=(deadline_timer&&) = delete;

        size_t cancel();
        bool cancel_one();

        //awoken when timeouted
        void async_wait(const std::shared_ptr<task>&);

        //true if got timeout
        void async_wait(std::function<void(status)>&&);
        void async_wait(const std::function<void(status)>&);

        //returns count of canceled tasks
        size_t expires_at(std::chrono::high_resolution_clock::time_point dur);

        status wait();
        status wait(fast_task::unique_lock<mutex_unify>& lock);
        status wait(std::unique_lock<mutex_unify>& lock);

        bool timed_out();

        //for coroutines
        bool enter_wait(const std::shared_ptr<task>& task, std::chrono::high_resolution_clock::time_point& out_time);
        bool enter_wait(mutex_unify& mut, const std::shared_ptr<task>& task, std::chrono::high_resolution_clock::time_point& out_time);
        status get_status(const std::shared_ptr<task>& task, std::chrono::high_resolution_clock::time_point timeout_time);

        template <class Rep, class Period>
        size_t expires_from_now(const std::chrono::duration<Rep, Period>& duration) {
            return expires_at(std::chrono::high_resolution_clock::now() + duration);
        }
    };
}
#endif /* INCLUDE_TASK_DEADLINE_TIMER */
