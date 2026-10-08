// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_INCLUDE_TASK_SCHEDULER
#define FAST_TASK_INCLUDE_TASK_SCHEDULER
#include "task.hpp"
#include <functional>
#include <list>
#include <variant>
#include <vector>

namespace fast_task {
    namespace scheduler {
        enum class preemption_policy {
            allows_preempt = 0,   //if fast_task built with preemptive scheduling disabled it would behave like cooperative_only
            cooperative_only = 1, //forces the scheduler to disable preemption for this executor


            default_policy = allows_preempt,
        };

        void FT_API schedule_until(task&& task, std::chrono::high_resolution_clock::time_point time_point);
        void FT_API schedule_until(const task& task, std::chrono::high_resolution_clock::time_point time_point);

        template <class Dur_resolution, class Dur_type>
        void schedule(task&& task, std::chrono::duration<Dur_resolution, Dur_type> duration) {
            schedule_until(std::move(task), std::chrono::high_resolution_clock::now() + duration);
        }

        template <class Dur_resolution, class Dur_type>
        void schedule(const task& task, std::chrono::duration<Dur_resolution, Dur_type> duration) {
            schedule_until(task, std::chrono::high_resolution_clock::now() + duration);
        }

        void FT_API start(task&& lgr_task);
        void FT_API start(std::list<task>& lgr_task);
        void FT_API start(std::vector<task>& lgr_task);
        void FT_API start(const task& lgr_task);

        uint16_t FT_API create_bind_only_executor(uint16_t fixed_count, bool allow_implicit_start, preemption_policy policy = preemption_policy::default_policy);
        void FT_API assign_bind_only_executor(uint16_t id, uint16_t fixed_count, bool allow_implicit_start, preemption_policy policy = preemption_policy::default_policy);
        void FT_API close_bind_only_executor(uint16_t id, bool abort_tasks = false);

        void FT_API create_executor(size_t count = 1);
        size_t FT_API total_executors();
        void FT_API reduce_executor(size_t count = 1);

        void FT_API become_task_executor();
        void FT_API await_no_tasks(bool be_executor = false);
        void FT_API await_end_tasks(bool be_executor = false);

        void FT_API explicit_start_timer();
        void FT_API shut_down();

        const task& FT_API current_context_task();


        /**
         * @brief requests stop the world to scheduler and the scheduler would stop its execution 
         *         and including internal threads and then runs the function. 
         *         This means the function is allowed only and only in native threads.
         *         
         *  @note Could be used for GC or debugging purposes
         *  @param func The function to execute when all workers stopped
         *  @throws `invalid_native_context` in task context
         *  @returns nothing
         */
        void FT_API request_stw(const std::function<void()>& func);

        //clean ups the unused memory
        void FT_API clean_up();
        void FT_API local_clean_up();

        bool FT_API preemption_enabled();
    }
}

#endif /* FAST_TASK_INCLUDE_TASK_SCHEDULER */
