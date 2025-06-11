// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef SRC_RUN_TIME_TASKS_INTERNAL
#define SRC_RUN_TIME_TASKS_INTERNAL

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

#include <tasks.hpp>

namespace fast_task {

    struct executors_local {
        boost::context::continuation* stack_current_context = nullptr;
        void* current_context = nullptr;
        std::exception_ptr ex_ptr;
        std::shared_ptr<task> curr_task = nullptr;
        bool is_task_thread = false;
        bool context_in_swap = false;

        bool in_exec_decreased = false;
    };

    struct timing {
        std::chrono::high_resolution_clock::time_point wait_timepoint;
        std::shared_ptr<task> awake_task;
        uint16_t check_id;
    };

    struct binded_context {
        std::list<uint32_t> completions;
        std::list<std::shared_ptr<task>> tasks;
        task_condition_variable on_closed_notifier;
        std::recursive_mutex no_race;
        std::condition_variable_any new_task_notifier;
        uint16_t executors = 0;
        bool in_close = false;
        bool allow_implicit_start = false;
        bool fixed_size = false;
    };

    struct executor_global {
        task_condition_variable no_tasks_notifier;
        task_condition_variable no_tasks_execute_notifier;

        std::queue<std::shared_ptr<task>> tasks;
        std::queue<std::shared_ptr<task>> cold_tasks;
        std::deque<timing> timed_tasks;
        std::deque<timing> cold_timed_tasks;

        std::recursive_mutex task_thread_safety;
        std::mutex task_timer_safety;

        std::condition_variable_any tasks_notifier;
        std::condition_variable time_notifier;
        std::condition_variable_any executor_shutdown_notifier;

        size_t executors = 0;
        size_t in_exec = 0;
        bool time_control_enabled = false;

        std::atomic_size_t tasks_in_swap = 0;
        std::atomic_size_t in_run_tasks = 0;
        std::atomic_size_t planned_tasks = 0;

        task_condition_variable can_started_new_notifier;
        task_condition_variable can_planned_new_notifier;

        std::mutex binded_workers_safety;
        std::unordered_map<uint16_t, binded_context, std::hash<uint16_t>> binded_workers;
    };

    void startTimeController();
    void swapCtx();
    void checkCancellation();
    void swapCtxRelock(const mutex_unify& mut0);
    void swapCtxRelock(const mutex_unify& mut0, const mutex_unify& mut1, const mutex_unify& mut2);
    void swapCtxRelock(const mutex_unify& mut0, const mutex_unify& mut1);
    void transfer_task(std::shared_ptr<task>& task);
    void makeTimeWait(std::chrono::high_resolution_clock::time_point t);
    void taskExecutor(bool end_in_task_out = false);
    void bindedTaskExecutor(uint16_t id);
    void unsafe_put_task_to_timed_queue(std::deque<timing>& queue, std::chrono::high_resolution_clock::time_point t, std::shared_ptr<task>& task);
    bool can_be_scheduled_task_to_hot();
    void forceCancelCancellation(task_cancellation& restart);


    bool _set_name_thread_dbg(const std::string& name, unsigned long thread_id);
    bool _set_name_thread_dbg(const std::string& name);
    std::string _get_name_thread_dbg(unsigned long thread_id);
    unsigned long _thread_id();


    extern thread_local executors_local loc;
    extern executor_global glob;
    constexpr size_t native_thread_flag = size_t(1) << (sizeof(size_t) * 8 - 1);
}

#endif /* SRC_RUN_TIME_TASKS_INTERNAL */
