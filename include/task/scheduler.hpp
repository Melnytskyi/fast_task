// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef INCLUDE_TASK_SCHEDULER
#define INCLUDE_TASK_SCHEDULER
#include "task.hpp"
#include <functional>
#include <list>
#include <vector>

namespace fast_task {
    namespace scheduler {
        enum class executor_policy {
            allows_preempt = 0,   //if fast_task built with preemptive scheduling disabled it would behave like cooperative_only
            cooperative_only = 1, //forces the scheduler to disable preemption for this executor


            default_policy = allows_preempt,
        };

        namespace config {
            inline constexpr long long background_basic_quantum_ns = 15 * 1000000;
            inline constexpr long long low_basic_quantum_ns = 30 * 1000000;
            inline constexpr long long lower_basic_quantum_ns = 40 * 1000000;
            inline constexpr long long normal_basic_quantum_ns = 80 * 1000000;
            inline constexpr long long higher_basic_quantum_ns = 90 * 1000000;
            inline constexpr long long high_basic_quantum_ns = 120 * 1000000;

            inline constexpr long long background_max_quantum_ns = 30 * 1000000;
            inline constexpr long long low_max_quantum_ns = 60 * 1000000;
            inline constexpr long long lower_max_quantum_ns = 80 * 1000000;
            inline constexpr long long normal_max_quantum_ns = 160 * 1000000;
            inline constexpr long long higher_max_quantum_ns = 180 * 1000000;
            inline constexpr long long high_max_quantum_ns = 240 * 1000000;
        };

        void FT_API schedule_until(std::shared_ptr<task>&& task, std::chrono::high_resolution_clock::time_point time_point);
        void FT_API schedule_until(const std::shared_ptr<task>& task, std::chrono::high_resolution_clock::time_point time_point);

        template <class Dur_resolution, class Dur_type>
        void schedule(std::shared_ptr<task>&& task, std::chrono::duration<Dur_resolution, Dur_type> duration) {
            schedule_until(std::move(task), std::chrono::high_resolution_clock::now() + duration);
        }

        template <class Dur_resolution, class Dur_type>
        void schedule(const std::shared_ptr<task>& task, std::chrono::duration<Dur_resolution, Dur_type> duration) {
            schedule_until(task, std::chrono::high_resolution_clock::now() + duration);
        }

        void FT_API start(std::shared_ptr<task>&& lgr_task);
        void FT_API start(std::list<std::shared_ptr<task>>& lgr_task);
        void FT_API start(std::vector<std::shared_ptr<task>>& lgr_task);
        void FT_API start(const std::shared_ptr<task>& lgr_task);

        uint16_t FT_API create_bind_only_executor(uint16_t fixed_count, bool allow_implicit_start, executor_policy policy = executor_policy::default_policy);
        void FT_API assign_bind_only_executor(uint16_t id, uint16_t fixed_count, bool allow_implicit_start, executor_policy policy = executor_policy::default_policy);
        void FT_API close_bind_only_executor(uint16_t id);

        void FT_API create_executor(size_t count = 1);
        size_t FT_API total_executors();
        void FT_API reduce_executor(size_t count = 1);

        void FT_API become_task_executor();
        void FT_API await_no_tasks(bool be_executor = false);
        void FT_API await_end_tasks(bool be_executor = false);

        void FT_API explicit_start_timer();
        void FT_API shut_down();

        const std::shared_ptr<task>& FT_API current_context_task();


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

        //DEBUG ONLY, not recommended use in production
        void FT_API clean_up();
        //DEBUG ONLY, not recommended use in production
    }
}

#endif /* INCLUDE_TASK_SCHEDULER */
