// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#pragma once
#ifndef FAST_TASK_INTERNAL
    #define FAST_TASK_INTERNAL


    #include <atomic>
    #include <barrier>
    #include <boost/context/continuation.hpp>
    #include <concurrentqueue/moodycamel/concurrentqueue.h>
    #include <cstdint>
    #include <exception>
    #include <queue>
    #include <unordered_set>

    #include <exceptions.hpp>
    #include <internal/task_object.hpp>
    #include <shared.hpp>
    #include <task.hpp>
    #include <tasks/classes/synchronization/futex_waiter.hpp>
    #include <tasks/classes/synchronization/internal_sched_cv.hpp>
    #include <tasks/util/_dbg_macro.hpp>
    #include <tasks/util/fixed_task_allocator.hpp>
    #include <tasks/util/hashed_timing_wheel.hpp>
    #include <tasks/util/macro.hpp>
    #include <tasks/util/pcg32.hpp>
    #include <tasks/util/work_stealing_deque.hpp>

namespace fast_task {
    template <uint32_t MaxSlots>
    struct FT_API_LOCAL executor_registry {
        static constexpr uint32_t max_slots = MaxSlots;

        alignas(hardware_destructive_interference_size) std::atomic<work_stealing_deque<task_object*>*> slots[MaxSlots]{};
        alignas(hardware_destructive_interference_size) std::atomic<uint32_t> count{0};
        alignas(hardware_destructive_interference_size) std::atomic<uint32_t> next_free_hint{0};

        uint32_t claim(work_stealing_deque<task_object*>* deque) noexcept {
            uint32_t start = next_free_hint.load(std::memory_order_relaxed);
            for (uint32_t i = 0; i < max_slots; ++i) {
                uint32_t idx = (start + i) % max_slots;
                work_stealing_deque<task_object*>* expected = nullptr;
                if (slots[idx].compare_exchange_strong(expected, deque, std::memory_order_release, std::memory_order_relaxed)) {
                    next_free_hint.store((idx + 1) % max_slots, std::memory_order_relaxed);
                    count.fetch_add(1, std::memory_order_release);
                    return idx;
                }
            }
            return UINT32_MAX;
        }

        void release(uint32_t idx) noexcept {
            if (idx < max_slots) {
                slots[idx].store(nullptr, std::memory_order_release);
                count.fetch_sub(1, std::memory_order_release);
            }
        }
    };

    using global_executor_registry = executor_registry<FT_MAX_EXECUTORS>;
    using binded_executor_registry = executor_registry<FT_BINDED_MAX_SLOTS>;

    struct FT_API_LOCAL task_object::execution_data {
        std::chrono::high_resolution_clock::time_point::rep timeout = std::chrono::high_resolution_clock::time_point::min().time_since_epoch().count();
        boost::context::continuation context;
        size_t context_switch_count = 0;
    #ifdef FT_ENABLE_PREEMPTIVE_SCHEDULER
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
    #if defined(FT_EXCEPTION_POLICY_PRESERVE)
        std::exception_ptr switch_preserve;
    #endif
    };

    struct FT_API_LOCAL task_object::wait_item {
        wait_item* next = nullptr;
        task waiter;
        fast_task::condition_variable_any* native_cv = nullptr;
        bool* native_check = nullptr;
        uint16_t awake_check = 0;
        bool heap_allocated = false;
    };

    struct task_condition_variable::resume_task {
        class task task;
        uint16_t awake_check = 0;
        fast_task::condition_variable_any* native_cv = nullptr;
        bool* native_check = nullptr;
        resume_task* next = nullptr;
        resume_task* prev = nullptr;
        bool heap_allocated = false;
    };

    struct task_limiter::resume_task {
        class task task;
        uint16_t awake_check;
        resume_task* next = nullptr;
        resume_task* prev = nullptr;
    };

    struct task_mutex::resume_task {
        class task task;
        uint16_t awake_check = 0;
        fast_task::condition_variable_any* native_cv = nullptr;
        bool* native_check = nullptr;
        resume_task* next = nullptr;
        resume_task* prev = nullptr;
    };

    struct task_queue_handle {                //96 [sizeof]
        task_condition_variable end_of_queue; //32
        std::list<task> tasks;                //24
        fast_task::spin_lock no_race;         //8
        task_queue* tq = nullptr;             //8
        size_t now_at_execution = 0;          //8
        size_t at_execution_max = 0;          //8
        bool destructed = false;              //1
        bool is_running = false;              //1
                                              //6 [padding]
    };

    struct task_rw_mutex::resume_task {
        class task task;
        fast_task::condition_variable_any* native_cv = nullptr;
        bool* native_check = nullptr;
        resume_task* next = nullptr;
        resume_task* prev = nullptr;
        uint16_t awake_check = 0;
        std::optional<bool> lock_read;
    };

    struct task_semaphore::resume_task {
        class task task;
        uint16_t awake_check;
        resume_task* next = nullptr;
        resume_task* prev = nullptr;
    };

    struct deadline_timer::handle {
        std::atomic_size_t usage_count{1}; // The reference counter
        task_mutex no_race;
        std::chrono::high_resolution_clock::time_point time_point;
        std::unordered_set<size_t> canceled_tasks; //fast_task::task
        std::list<task> scheduled_tasks;           // tasks registered via async_wait(task)
        std::list<task> sleeping_tasks;            // tasks blocked in wait()
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

    inline auto FT_API_LOCAL get_data(class task* task) -> task_object& {
        return *task->obj;
    }

    inline auto FT_API_LOCAL get_data(const class task& task) -> task_object& {
        return *task.obj;
    }

    inline auto FT_API_LOCAL get_execution_data(class task* task) -> task_object::execution_data& {
        auto& slot = get_data(task).exdata;
        auto* p = slot.load(std::memory_order_acquire);
        if (!p) {
            p = new task_object::execution_data{};
            slot.store(p, std::memory_order_release);
        }
        return *p;
    }

    inline auto FT_API_LOCAL get_execution_data(task_object* task) -> task_object::execution_data& {
        auto& slot = task->exdata;
        auto* p = slot.load(std::memory_order_acquire);
        if (!p) {
            p = new task_object::execution_data{};
            slot.store(p, std::memory_order_release);
        }
        return *p;
    }

    inline auto FT_API_LOCAL get_execution_data(class task& task) -> task_object::execution_data& {
        return get_execution_data(&task);
    }

    inline auto FT_API_LOCAL get_execution_data(const class task& task) -> task_object::execution_data& {
        return get_execution_data(const_cast<class task*>(&task));
    }

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
        tl_task_alloc_cache task_alloc_cache;
        tl_timing_alloc_cache timing_alloc_cache;
        std::unique_ptr<work_stealing_deque<task_object*>> local_tasks = std::make_unique<work_stealing_deque<task_object*>>();
        std::exception_ptr ex_ptr;
        task curr_task = nullptr;
        pcg32 rand;
        scheduler::preemption_policy policy = scheduler::preemption_policy::default_policy;
        uint16_t binded_id = (uint16_t)-1;
        uint32_t registry_slot = UINT32_MAX;

        bool is_task_thread : 1 = false;
        bool context_in_swap : 1 = false;
        bool yield_request : 1 = false;

        struct {
            work_stealing_deque<task_object*>* last_success_victim = nullptr;
            uint32_t last_success_epoch = 0; // monotonic counter for staleness
        } steal_cache;

        struct {
            task pending;
    #if FT_TASK_TRANSFERS_LIMIT > 0
            std::atomic_size_t transfers{(size_t)0};
    #endif
        } transfer_state;

        std::chrono::high_resolution_clock::time_point pending_timer = std::chrono::high_resolution_clock::time_point::min();

        void reset();

        ~executors_local();
    };

    struct FT_API_LOCAL binded_context {
        binded_executor_registry executors_registry;
        std::list<uint32_t> completions;
        moodycamel::ConcurrentQueue<task_object*> tasks;
        task_condition_variable on_closed_notifier;
        fast_task::rw_mutex no_race;
        fast_task::condition_variable_any new_task_notifier;
        uint16_t executors = 0;
        uint16_t expected_executors = 0;
        bool in_close : 1 = false;
        bool allow_implicit_start : 1 = false;
        bool fixed_size : 1 = false;
        bool abort_tasks_on_close : 1 = false;
        scheduler::preemption_policy policy = scheduler::preemption_policy::default_policy;
    };

    struct FT_API_LOCAL executor_global {
        global_task_allocator gba;
        internal_sched_cv no_tasks_execute_notifier;
        futex_waiter timer_waiter;
        fast_task::condition_variable_any tasks_notifier;
        fast_task::condition_variable_any executor_shutdown_notifier;

        global_executor_registry executors_registry;
        moodycamel::ConcurrentQueue<task_object*> tasks;
        moodycamel::ConcurrentQueue<task_object*> cold_tasks;
        hashed_timing_wheel timed_wheel;

        fast_task::rw_mutex task_thread_safety;


        std::atomic<bool> time_control_enabled{false};
        std::atomic<bool> shutdown_requested{false};
        std::atomic<bool> executor_shutting_down{false};

        std::atomic_size_t interrupts = 0; //debug counter of the usermode fast_task interrupts
        std::atomic_size_t executors = 0;
    #ifndef NDEBUG
        std::atomic_size_t tasks_in_swap = 0; //this means the tasks is stored outside the scheduler and excepted to be rescheduled later, ex. mutex
    #endif
        std::atomic_size_t in_run_tasks = 0;    //count of tasks in run right now
        std::atomic_size_t executing_tasks = 0; //scheduled and in run tasks, including tasks in swap


        fast_task::rw_mutex binded_workers_safety;
        std::unordered_map<uint16_t, binded_context, std::hash<uint16_t>> binded_workers;


        std::atomic<bool> stw_request{false};
        std::unique_ptr<std::barrier<>> stw_barrier_enter;
        std::unique_ptr<std::barrier<>> stw_barrier_exit;
        std::atomic<size_t> thread_count{0}; //including native worker and timer
        fast_task::mutex stw_mutex;

        executor_global();
        ~executor_global();
    };

    NOINLINE executors_local& get_loc() noexcept;

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
        glob.timer_waiter.notify_one();
        glob.tasks_notifier.notify_all();
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
    void FT_API_LOCAL transfer_task(task&&, enter_state* stat = nullptr);
    void FT_API_LOCAL makeTimeWait(std::chrono::high_resolution_clock::time_point t);
    void FT_API_LOCAL makeTimeWait_extern(task, std::chrono::high_resolution_clock::time_point time_point);
    void FT_API_LOCAL resetTimeWait();

    void FT_API_LOCAL taskExecutor(bool end_in_task_out = false, bool prevent_naming = false);
    void FT_API_LOCAL bindedTaskExecutor(uint16_t id);
    bool FT_API_LOCAL can_be_scheduled_task_to_hot();
    void FT_API_LOCAL forceCancelCancellation(const task_cancellation& restart);

    bool FT_API_LOCAL _set_name_thread_dbg(const std::string& name, unsigned long thread_id);
    bool FT_API_LOCAL _set_name_thread_dbg(const std::string& name);
    std::string FT_API_LOCAL _get_name_thread_dbg(unsigned long thread_id);
    unsigned long FT_API_LOCAL _thread_id();
    bool FT_API_LOCAL is_debugger_attached();

    FT_DEBUG_ONLY(void FT_API_LOCAL register_object(task_mutex*));
    FT_DEBUG_ONLY(void FT_API_LOCAL register_object(task_recursive_mutex*));
    FT_DEBUG_ONLY(void FT_API_LOCAL register_object(task_rw_mutex*));
    FT_DEBUG_ONLY(void FT_API_LOCAL register_object(task_condition_variable*));
    FT_DEBUG_ONLY(void FT_API_LOCAL register_object(task_object*));
    FT_DEBUG_ONLY(void FT_API_LOCAL register_object(task_semaphore*));
    FT_DEBUG_ONLY(void FT_API_LOCAL register_object(task_limiter*));
    FT_DEBUG_ONLY(void FT_API_LOCAL register_object(task_queue*));
    FT_DEBUG_ONLY(void FT_API_LOCAL register_object(deadline_timer*));

    FT_DEBUG_ONLY(void FT_API_LOCAL unregister_object(task_mutex*));
    FT_DEBUG_ONLY(void FT_API_LOCAL unregister_object(task_recursive_mutex*));
    FT_DEBUG_ONLY(void FT_API_LOCAL unregister_object(task_rw_mutex*));
    FT_DEBUG_ONLY(void FT_API_LOCAL unregister_object(task_condition_variable*));
    FT_DEBUG_ONLY(void FT_API_LOCAL unregister_object(task_object*));
    FT_DEBUG_ONLY(void FT_API_LOCAL unregister_object(task_semaphore*));
    FT_DEBUG_ONLY(void FT_API_LOCAL unregister_object(task_limiter*));
    FT_DEBUG_ONLY(void FT_API_LOCAL unregister_object(task_queue*));
    FT_DEBUG_ONLY(void FT_API_LOCAL unregister_object(deadline_timer*));
}

#endif
