// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef INCLUDE_TASK_QUEUE
#define INCLUDE_TASK_QUEUE
#include "enter_state.hpp"
#include "task.hpp"

namespace fast_task {
    class FT_API task_queue {
        friend struct debug::_debug_collect;
        struct task_queue_handle* handle;
        friend void __TaskQueue_add_task_leave(struct task_queue_handle* tqh);

    public:
        task_queue(size_t at_execution_max = 1);
        ~task_queue();
        void add(task&);
        void add(task&&);
        void enable();
        void disable();
        bool in_queue(const task& task);
        void set_max_at_execution(size_t val);
        size_t get_max_at_execution();
        void wait();
        bool wait_until(std::chrono::high_resolution_clock::time_point time_point);

        template <class Rep, class Period>
        bool wait_for(const std::chrono::duration<Rep, Period>& duration) {
            return wait_until(std::chrono::high_resolution_clock::now() + duration);
        }

        bool enter_wait(const task&, enter_state& task);
        bool enter_wait_until(const task&, enter_state& task, std::chrono::high_resolution_clock::time_point);
    };
}


#endif /* INCLUDE_TASK_QUEUE */
