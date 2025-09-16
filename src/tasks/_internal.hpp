// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#pragma once
#ifndef FAST_TASK_INTERNAL
    #define FAST_TASK_INTERNAL

    //platforms: windows, linux, macos, ios, android, unknown
    #if defined(_WIN32) || defined(_WIN64)
        #define PLATFORM_WINDOWS 1
    #elif defined(__linux__) || defined(__unix__) || defined(__posix__) || defined(__LINUX__) || defined(__linux) || defined(__gnu_linux__)
        #define PLATFORM_LINUX 1
    #elif defined(__APPLE__) || defined(__MACH__)
        #define PLATFORM_MACOS 1
    #elif defined(__ANDROID__) || defined(__ANDROID_API__) || defined(ANDROID)
        #define PLATFORM_ANDROID 1
    #elif defined(__IPHONE_OS_VERSION_MIN_REQUIRED) || defined(__IPHONE_OS_VERSION_MAX_ALLOWED) || defined(__IPHONE_OS_VERSION_MAX_REQUIRED) || defined(__IPHONE_OS_VERSION_MAX_ALLOWED)
        #define PLATFORM_IOS 1
    #else
        #define PLATFORM_UNKNOWN
    #endif


    #include <boost/context/continuation.hpp>
    #include <exception>
    #include <queue>

    #include <shared.hpp>
    #include <task.hpp>

namespace fast_task {

    inline auto FT_API_LOCAL get_data(std::shared_ptr<task>& task) -> task::data& {
        return task->data_;
    }

    inline auto FT_API_LOCAL get_data(const std::shared_ptr<task>& task) -> task::data& {
        return task->data_;
    }

    inline static constexpr std::chrono::nanoseconds priority_quantum_basic[] = {
        std::chrono::nanoseconds(scheduler::config::background_basic_quantum_ns),
        std::chrono::nanoseconds(scheduler::config::low_basic_quantum_ns),
        std::chrono::nanoseconds(scheduler::config::lower_basic_quantum_ns),
        std::chrono::nanoseconds(scheduler::config::normal_basic_quantum_ns),
        std::chrono::nanoseconds(scheduler::config::higher_basic_quantum_ns),
        std::chrono::nanoseconds(scheduler::config::high_basic_quantum_ns),
        std::chrono::nanoseconds::min()
    };

    inline static constexpr std::chrono::nanoseconds priority_quantum_max[] = {
        std::chrono::nanoseconds(scheduler::config::background_max_quantum_ns),
        std::chrono::nanoseconds(scheduler::config::low_max_quantum_ns),
        std::chrono::nanoseconds(scheduler::config::lower_max_quantum_ns),
        std::chrono::nanoseconds(scheduler::config::normal_max_quantum_ns),
        std::chrono::nanoseconds(scheduler::config::higher_max_quantum_ns),
        std::chrono::nanoseconds(scheduler::config::high_max_quantum_ns),
        std::chrono::nanoseconds::min()
    };

    //per task has n quantum(ms) to execute depends on priority
    //if task spend it all it will be suspended
    //if task not spend it all, unused quantum will be added to next task quantum(ms limited by priority)
    //after resume if quantum is not more basic quantum, limit will be set to basic quantum
    //semi_realtime tasks has no limits
    //std::chrono::nanoseconds::min(); means no limit
    //std::chrono::nanoseconds(0); means no quantum, task last time spend more quantum than it has
    std::chrono::nanoseconds FT_API_LOCAL next_quantum(task_priority priority, std::chrono::nanoseconds& current_available_quantum);
    std::chrono::nanoseconds FT_API_LOCAL peek_quantum(task_priority priority, std::chrono::nanoseconds current_available_quantum);
    void FT_API_LOCAL task_switch(task_priority priority, std::chrono::nanoseconds& current_available_quantum, std::chrono::nanoseconds elapsed);
    std::chrono::nanoseconds FT_API_LOCAL init_quantum(task_priority priority);

    struct FT_API_LOCAL executors_local {
        std::exception_ptr ex_ptr;
        std::shared_ptr<task> curr_task = nullptr;
        boost::context::continuation* stack_current_context = nullptr;
        void* current_context = nullptr;
        bool is_task_thread : 1 = false;
        bool context_in_swap : 1 = false;
    };

    struct FT_API_LOCAL timing {
        std::chrono::high_resolution_clock::time_point wait_timepoint;
        std::shared_ptr<task> awake_task;
        uint16_t check_id;
    };

    struct FT_API_LOCAL binded_context {
        std::list<uint32_t> completions;
        std::list<std::shared_ptr<task>> tasks;
        task_condition_variable on_closed_notifier;
        fast_task::recursive_mutex no_race;
        fast_task::condition_variable_any new_task_notifier;
        uint16_t executors = 0;
        bool in_close : 1 = false;
        bool allow_implicit_start : 1 = false;
        bool fixed_size : 1 = false;
    };

    struct FT_API_LOCAL executor_global {
        task_condition_variable no_tasks_notifier;
        task_condition_variable no_tasks_execute_notifier;

        std::queue<std::shared_ptr<task>> tasks;
        std::queue<std::shared_ptr<task>> cold_tasks;
        std::deque<timing> timed_tasks;
        std::deque<timing> cold_timed_tasks;

        fast_task::recursive_mutex task_thread_safety;
        fast_task::mutex task_timer_safety;

        fast_task::condition_variable_any tasks_notifier;
        fast_task::condition_variable time_notifier;
        fast_task::condition_variable_any executor_shutdown_notifier;

        bool time_control_enabled = false;

        std::atomic_size_t interrupts = 0;
        std::atomic_size_t executors = 0;
        std::atomic_size_t tasks_in_swap = 0;
        std::atomic_size_t in_run_tasks = 0;

        task_condition_variable can_started_new_notifier;
        task_condition_variable can_planned_new_notifier;

        fast_task::mutex binded_workers_safety;
        std::unordered_map<uint16_t, binded_context, std::hash<uint16_t>> binded_workers;
    };

    void FT_API_LOCAL startTimeController();
    void FT_API_LOCAL swapCtx();
    bool FT_API_LOCAL checkCancellation() noexcept;
    void FT_API_LOCAL swapCtxRelock(const mutex_unify& mut0);
    void FT_API_LOCAL swapCtxRelock(const mutex_unify& mut0, const mutex_unify& mut1, const mutex_unify& mut2);
    void FT_API_LOCAL swapCtxRelock(const mutex_unify& mut0, const mutex_unify& mut1);
    void FT_API_LOCAL transfer_task(std::shared_ptr<task>& task);
    void FT_API_LOCAL makeTimeWait(std::chrono::high_resolution_clock::time_point t);
    void FT_API_LOCAL taskExecutor(bool end_in_task_out = false, bool prevent_naming = false);
    void FT_API_LOCAL bindedTaskExecutor(uint16_t id);
    void FT_API_LOCAL unsafe_put_task_to_timed_queue(std::deque<timing>& queue, std::chrono::high_resolution_clock::time_point t, std::shared_ptr<task>& task);
    bool FT_API_LOCAL can_be_scheduled_task_to_hot();
    void FT_API_LOCAL forceCancelCancellation(const task_cancellation& restart);


    bool FT_API_LOCAL _set_name_thread_dbg(const std::string& name, unsigned long thread_id);
    bool FT_API_LOCAL _set_name_thread_dbg(const std::string& name);
    std::string FT_API_LOCAL _get_name_thread_dbg(unsigned long thread_id);
    unsigned long FT_API_LOCAL _thread_id();


    extern thread_local FT_API_LOCAL executors_local loc;
    extern FT_API_LOCAL executor_global glob;
    constexpr size_t native_thread_flag = size_t(1) << (sizeof(size_t) * 8 - 1);
}

#endif
