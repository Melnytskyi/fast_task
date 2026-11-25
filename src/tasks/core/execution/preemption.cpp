// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <fast_task/native.hpp>
#include <fast_task/task.hpp>
#include <tasks/_internal.hpp>
#include <tasks/util/interrupt.hpp>
#include <tasks/util/light_stack.hpp>

namespace fast_task {
#ifdef FT_ENABLE_PREEMPTIVE_SCHEDULER
    void timer_reinit() {
        auto* loc = get_loc();
        assert(loc && "timer_reinit requires a worker context");
        if (loc->policy == scheduler::preemption_policy::cooperative_only)
            return;
        auto& exec = get_execution_data(loc->curr_task);
        if (exec.priority == task_priority::semi_realtime)
            return;
        std::chrono::nanoseconds interval = next_quantum(exec.priority, exec.current_available_quantum);
        if (interval <= std::chrono::nanoseconds::zero())
            return;
        interrupt::itimerval timer;
        timer.it_interval.tv_sec = 0;
        timer.it_interval.tv_usec = 0;
        timer.it_value.tv_sec = interval.count() / 1000000000;
        timer.it_value.tv_usec = (interval.count() % 1000000000) / 1000;
        interrupt::setitimer(&timer, nullptr);
    }

    void swapCtx();

    void interruptTask() {
        auto* loc = get_loc();
        assert(loc && "interruptTask requires a worker context");
        if (loc->policy == scheduler::preemption_policy::cooperative_only)
            return;
    #ifdef FT_EXCEPTION_POLICY_CHECK
        if (std::uncaught_exceptions())
            return;
    #endif
        {
            auto& task_data = get_data(loc->curr_task);
            worker_pool_storage* pool = task_data.get_pool_assigned()
                                            ? pool_for_index(task_data.pool_index)
                                            : nullptr;
            if (!pool)
                pool = &global_storage();
            if (!has_queued_work(pool, loc)) {
                timer_reinit();
                return;
            }
            if (pool->is_global && task::max_running_tasks && !can_be_scheduled_task_to_hot()) {
                timer_reinit();
                return;
            }
        }

        ++glob.interrupts;
        auto curr_task = loc->curr_task;
        ++get_execution_data(curr_task).interrupt_count;
        auto old_relock = get_data(curr_task).get_relock();
        get_data(curr_task).set_relock(nullptr);
        loc->yield_request = true;
        swapCtx();
        get_data(curr_task).set_relock(old_relock);
    }

    void set_interruptTask() {
        interrupt::timer_callback(interruptTask);
    }

    void stop_timer() {
        interrupt::stop_timer();
    }

    void preserve_interrupt_data() {
        auto* loc = get_loc();
        if (!loc || !loc->curr_task)
            return;
        get_execution_data(loc->curr_task).interrupt_data = interrupt_unsafe_region::lock_swap(0);
    }

    void restore_interrupt_data() {
        auto* loc = get_loc();
        if (!loc || !loc->curr_task)
            return;
        interrupt_unsafe_region::lock_swap(get_execution_data(loc->curr_task).interrupt_data);
    }

    void flush_interrupt_data() {
        interrupt_unsafe_region::lock_swap(0);
    }
#else
#endif
}
