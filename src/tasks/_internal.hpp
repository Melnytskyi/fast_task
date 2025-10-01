// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#pragma once
#ifndef FAST_TASK_INTERNAL
    #define FAST_TASK_INTERNAL
    #ifndef tasks_enable_preemptive_scheduler_preview
        #define tasks_enable_preemptive_scheduler_preview false
    #endif
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


    #include <barrier>
    #include <boost/context/continuation.hpp>
    #include <exception>
    #include <queue>
    #include <unordered_set>

    #include <shared.hpp>
    #include <task.hpp>
    #include <tasks/util/_dbg_macro.hpp>

namespace fast_task {
    struct task::execution_data {
        boost::context::continuation context;
        size_t context_switch_count = 0;
    #if tasks_enable_preemptive_scheduler_preview
        std::chrono::nanoseconds current_available_quantum = std::chrono::nanoseconds(0);
        task_priority priority = task_priority::high;
        size_t interrupt_count = 0;
        size_t interrupt_data = 0; //used only when task requested switch but it has interrupt lock
    #endif
    #if PLATFORM_LINUX
        void* stack_ptr = nullptr;
        size_t stack_size = 0;
        unsigned int valgrind_stack_id = 0;
    #endif
    };

    struct task_condition_variable::resume_task {
        std::shared_ptr<task> task;
        uint16_t awake_check = 0;
        fast_task::condition_variable_any* native_cv = nullptr;
        bool* native_check = nullptr;
    };

    struct task_limiter::resume_task {
        std::shared_ptr<task> task;
        uint16_t awake_check;
    };

    struct task_mutex::resume_task {
        std::shared_ptr<task> task;
        uint16_t awake_check = 0;
        fast_task::condition_variable_any* native_cv = nullptr;
        bool* native_check = nullptr;
    };

    struct task_query_handle {                  //128 [sizeof]
        task_mutex no_race;                     //40
        task_condition_variable end_of_query;   //32
        std::list<std::shared_ptr<task>> tasks; //24
        task_query* tq = nullptr;               //8
        size_t now_at_execution = 0;            //8
        size_t at_execution_max = 0;            //8
        bool destructed = false;                //1
        bool is_running = false;                //1
                                                //6 [padding]
    };

    struct task_rw_mutex::resume_task {
        std::shared_ptr<task> task;
        uint16_t awake_check = 0;
        fast_task::condition_variable_any* native_cv = nullptr;
        bool* native_check = nullptr;
    };

    struct task_semaphore::resume_task {
        std::shared_ptr<task> task;
        uint16_t awake_check;
    };

    struct deadline_timer::handle {
        std::atomic_size_t usage_count{1}; // The reference counter
        task_mutex no_race;
        std::chrono::high_resolution_clock::time_point time_point;
        std::unordered_set<void*> canceled_tasks; //fast_task::task
        std::list<task*> scheduled_tasks;
        bool shutdown = false;

        static handle* create() {
            return new handle{};
        }

        handle* acquire() {
            usage_count.fetch_add(1, std::memory_order_relaxed);
            return this;
        }

        void release() {
            if (usage_count.fetch_sub(1, std::memory_order_release) == 1) {
                std::atomic_thread_fence(std::memory_order_acquire);
                delete this;
            }
        }
    };

    inline auto FT_API_LOCAL get_data(task* task) -> task::data& {
        return task->data_;
    }

    inline auto FT_API_LOCAL get_data(std::shared_ptr<task>& task) -> task::data& {
        return task->data_;
    }

    inline auto FT_API_LOCAL get_data(const std::shared_ptr<task>& task) -> task::data& {
        return task->data_;
    }

    inline auto FT_API_LOCAL get_execution_data(task* task) -> task::execution_data& {
        auto& it = get_data(task).exdata;
        if (!it)
            it = new task::execution_data{};
        return *it;
    }


    inline auto FT_API_LOCAL get_execution_data(std::shared_ptr<task>& task) -> task::execution_data& {
        auto& it = get_data(task).exdata;
        if (!it)
            it = new task::execution_data{};
        return *it;
    }

    inline auto FT_API_LOCAL get_execution_data(const std::shared_ptr<task>& task) -> task::execution_data& {
        auto& it = get_data(task).exdata;
        if (!it)
            it = new task::execution_data{};
        return *it;
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


        std::atomic<bool> stw_request{false};
        std::unique_ptr<std::barrier<>> stw_barrier_enter;
        std::unique_ptr<std::barrier<>> stw_barrier_exit;
        std::atomic<size_t> thread_count{0}; //including native worker and timer
        fast_task::mutex stw_mutex;
    };

    extern thread_local FT_API_LOCAL executors_local loc;
    extern FT_API_LOCAL executor_global glob;
    constexpr size_t native_thread_flag = size_t(1) << (sizeof(size_t) * 8 - 1);

    inline void FT_API_LOCAL unsafe_perform_stop_the_world(const std::function<void()>& work) {
        std::lock_guard lock(glob.stw_mutex);
        size_t thread_count = glob.thread_count.load(std::memory_order_relaxed);
        if (thread_count == 0) {
            work();
            return;
        }

        glob.stw_barrier_enter = std::make_unique<std::barrier<>>(thread_count + 1); // +1 for this thread
        glob.stw_barrier_exit = std::make_unique<std::barrier<>>(thread_count + 1);
        glob.stw_request.store(true, std::memory_order_release);
        glob.time_notifier.notify_all();
        glob.stw_barrier_enter->arrive_and_wait(); // Wait for all executors to pause
        work();                                    // Execute the dump
        glob.stw_request.store(false, std::memory_order_relaxed);
        glob.stw_barrier_exit->arrive_and_wait(); // Signal executors to resume
    }

    template <class Mut>
    void FT_API_LOCAL check_stw(Mut& mut) {
        if (glob.stw_request.load(std::memory_order_acquire)) {
            relock_guard rlck(mut);
            glob.stw_barrier_enter->arrive_and_wait();
            glob.stw_barrier_exit->arrive_and_wait();
        }
    }

    inline void FT_API_LOCAL check_stw() {
        if (glob.stw_request.load(std::memory_order_acquire)) {
            glob.stw_barrier_enter->arrive_and_wait();
            glob.stw_barrier_exit->arrive_and_wait();
        }
    }

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

    void FT_API_LOCAL __install_signal_handler_mem();

    bool FT_API_LOCAL _set_name_thread_dbg(const std::string& name, unsigned long thread_id);
    bool FT_API_LOCAL _set_name_thread_dbg(const std::string& name);
    std::string FT_API_LOCAL _get_name_thread_dbg(unsigned long thread_id);
    unsigned long FT_API_LOCAL _thread_id();
    bool FT_API_LOCAL is_debugger_attached();

    FT_DEBUG_ONLY(void FT_API_LOCAL register_object(task_mutex*));
    FT_DEBUG_ONLY(void FT_API_LOCAL register_object(task_recursive_mutex*));
    FT_DEBUG_ONLY(void FT_API_LOCAL register_object(task_rw_mutex*));
    FT_DEBUG_ONLY(void FT_API_LOCAL register_object(task_condition_variable*));
    FT_DEBUG_ONLY(void FT_API_LOCAL register_object(task*));
    FT_DEBUG_ONLY(void FT_API_LOCAL register_object(task_semaphore*));
    FT_DEBUG_ONLY(void FT_API_LOCAL register_object(task_limiter*));
    FT_DEBUG_ONLY(void FT_API_LOCAL register_object(task_query*));
    FT_DEBUG_ONLY(void FT_API_LOCAL register_object(deadline_timer*));

    FT_DEBUG_ONLY(void FT_API_LOCAL unregister_object(task_mutex*));
    FT_DEBUG_ONLY(void FT_API_LOCAL unregister_object(task_recursive_mutex*));
    FT_DEBUG_ONLY(void FT_API_LOCAL unregister_object(task_rw_mutex*));
    FT_DEBUG_ONLY(void FT_API_LOCAL unregister_object(task_condition_variable*));
    FT_DEBUG_ONLY(void FT_API_LOCAL unregister_object(task*));
    FT_DEBUG_ONLY(void FT_API_LOCAL unregister_object(task_semaphore*));
    FT_DEBUG_ONLY(void FT_API_LOCAL unregister_object(task_limiter*));
    FT_DEBUG_ONLY(void FT_API_LOCAL unregister_object(task_query*));
    FT_DEBUG_ONLY(void FT_API_LOCAL unregister_object(deadline_timer*));
}

#endif
