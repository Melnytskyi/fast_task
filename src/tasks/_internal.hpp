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

    #if defined(_MSC_VER)
        #define NOINLINE __declspec(noinline)
    #elif defined(__GNUC__) || defined(__clang__)
        #define NOINLINE __attribute__((noinline))
    #else
        #define NOINLINE
    #endif


    #include <atomic>
    #include <barrier>
    #include <boost/context/continuation.hpp>
    #include <concurrentqueue/moodycamel/concurrentqueue.h>
    #include <exception>
    #include <queue>
    #include <random>
    #include <unordered_set>

    #include <exceptions.hpp>
    #include <shared.hpp>
    #include <task.hpp>
    #include <tasks/util/_dbg_macro.hpp>
    #include <tasks/util/hashed_timing_wheel.hpp>
    #include <tasks/util/work_stealing_deque.hpp>

namespace fast_task {
    struct execution_data {
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

    struct alignas(64) FT_API_LOCAL task_object {
        struct FT_API_LOCAL wait_item;
        enum class status_e : uint8_t {
            created,
            running,
            suspending,
            suspended,
            ended
        };

        struct state_f {
            enum f : uint16_t {
                time_end = 0x1,
                awaked = 0x2,
                auto_bind = 0x4,
                is_restartable = 0x8,
                is_on_scheduler = 0x10,
                is_sbo = 0x20,
                spin_lock_locked = 0x40,
                cancellation_requested = 0x80,
                invalid_switch_caught = 0x100,
                completed = 0x200,
            };
        };

        std::atomic<void*> tls_data;         // 8
        std::atomic<wait_item*> on_wait;     // 8
        std::atomic<execution_data*> exdata; // 8
        const task_vtable* vtable;           // 8
        void* relock0;                       // 8
        void* relock1;                       // 8
        uint8_t relock0_type, relock1_type;  // 2
        std::atomic<status_e> status;        // 1
        uint8_t reserved0;                   // 1
        std::atomic<state_f::f> state;       // 2
        uint16_t bind_to_worker_id;          // 2
        uint16_t awake_check;                // 2
        uint16_t tls_capacity;               // 2
        std::atomic<uint32_t> link_counter;  // 4

        alignas(std::max_align_t) std::byte sbo_buffer[48];
        void (*on_start_override)(task_object*);
        void* on_start_override_data;

        bool get_time_end() const noexcept;
        void set_time_end(bool state) noexcept;
        bool get_awaked() const noexcept;
        void set_awaked(bool state) noexcept;
        bool get_auto_bind() const noexcept;
        void set_auto_bind(bool state) noexcept;
        bool get_is_restartable() const noexcept;
        void set_is_restartable(bool state) noexcept;
        bool get_is_on_scheduler() const noexcept;
        void set_is_on_scheduler(bool state) noexcept;
        bool get_is_sbo() const noexcept;
        void set_is_sbo(bool state) noexcept;
        bool get_cancellation_requested() const noexcept;
        void set_cancellation_requested(bool state) noexcept;
        bool get_invalid_switch_caught() const noexcept;
        void set_invalid_switch_caught(bool state) noexcept;
        bool get_completed() const noexcept;
        void set_completed(bool state) noexcept;

        void set_status(status_e) noexcept;

        bool is_started() const noexcept;   // status != created
        bool is_running() const noexcept;   // status == running
        bool is_suspended() const noexcept; // status == suspended
        bool is_ended() const noexcept;     // status == ended

        void* user_data() const noexcept;
        void end_of_life_notify();

        void lock() noexcept;
        void unlock() noexcept;

        void wait();
        void wait_until(std::chrono::high_resolution_clock::time_point);
        void cancel();

        bool enter_wait(const task&, enter_state& state);
        bool enter_wait_until(const task&, enter_state& state, std::chrono::high_resolution_clock::time_point);
        bool enter_cancel(const task&, enter_state& state);

        mutex_unify get_relock_0() const noexcept;
        mutex_unify get_relock_1() const noexcept;
        void set_relock_0(mutex_unify) noexcept;
        void set_relock_1(mutex_unify) noexcept;

        static task_object* alloc();
        static task_object* use(task_object*) noexcept;
        static void free(task_object* obj);

        mutex_unify get_self_unify() noexcept;
    };

    struct FT_API_LOCAL task_object::wait_item {
        wait_item* next = nullptr;
        task waiter;
        fast_task::condition_variable_any* native_cv = nullptr;
        bool* native_check = nullptr;
        uint16_t awake_check = 0;
        bool heap_allocated = false;
    };

    struct mutex_unify_relock_access {
        static void* raw_ptr(const mutex_unify& m) noexcept {
            return reinterpret_cast<void*>(m.nmut);
        }

        static uint8_t raw_type(const mutex_unify& m) noexcept {
            return static_cast<uint8_t>(m.type);
        }

        static mutex_unify from_raw(void* ptr, uint8_t type) noexcept {
            mutex_unify m(nullptr);
            m.type = static_cast<mutex_unify::mutex_unify_type>(type);
            m.nmut = reinterpret_cast<fast_task::mutex*>(ptr);
            return m;
        }

        // Builds a mutex_unify that locks/unlocks a task_object's spin bit, used to
        // protect the task's completion-wait list across a context switch.
        static mutex_unify from_task_object(task_object& obj) noexcept {
            mutex_unify m(nullptr);
            m.type = mutex_unify::mutex_unify_type::task_obj;
            m.nmut = reinterpret_cast<fast_task::mutex*>(&obj);
            return m;
        }

        // Removes a node from a task_object's intrusive completion-wait list
        // (the caller must hold the owning task_object's spin lock).
        static void unlink_wait(std::atomic<task_object::wait_item*>& head, task_object::wait_item* node) noexcept {
            auto* cur = head.load(std::memory_order_relaxed);
            task_object::wait_item* prev = nullptr;
            while (cur) {
                if (cur == node) {
                    if (prev)
                        prev->next = cur->next;
                    else
                        head.store(cur->next, std::memory_order_relaxed);
                    return;
                }
                prev = cur;
                cur = cur->next;
            }
        }

        static_assert(sizeof(task_object::sbo_buffer) == task::sbo_size, "task::sbo_size must match task_object::sbo_buffer");
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

    struct task_query_handle {                //96 [sizeof]
        task_condition_variable end_of_query; //32
        std::list<task> tasks;                //24
        fast_task::spin_lock no_race;         //8
        task_query* tq = nullptr;             //8
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

    inline auto FT_API_LOCAL get_data(task* task) -> task_object& {
        return *task->obj;
    }

    inline auto FT_API_LOCAL get_data(task& task) -> task_object& {
        return *task.obj;
    }

    inline auto FT_API_LOCAL get_data(const task& task) -> task_object& {
        return *task.obj;
    }

    inline auto FT_API_LOCAL get_execution_data(task* task) -> execution_data& {
        auto& slot = get_data(task).exdata;
        auto* p = slot.load(std::memory_order_acquire);
        if (!p) {
            p = new execution_data{};
            slot.store(p, std::memory_order_release);
        }
        return *p;
    }

    inline auto FT_API_LOCAL get_execution_data(task& task) -> execution_data& {
        return get_execution_data(&task);
    }

    inline auto FT_API_LOCAL get_execution_data(const task& task) -> execution_data& {
        return get_execution_data(const_cast<class task*>(&task));
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
        std::shared_ptr<work_stealing_deque<task>> local_tasks = std::make_shared<work_stealing_deque<task>>();
        std::exception_ptr ex_ptr;
        task curr_task = nullptr;
        boost::context::continuation* stack_current_context = nullptr;
        scheduler::executor_policy policy = scheduler::executor_policy::default_policy;
        uint16_t binded_id = (uint16_t)-1;

        bool is_task_thread : 1 = false;
        bool context_in_swap : 1 = false;
        bool yield_request : 1 = false;

        struct {
            task pending;
    #if FT_TASK_TRANSFERS_LIMIT > 0
            std::atomic_size_t transfers{(size_t)0};
    #endif
        } transfer_state;

        void reset();
    };

    struct FT_API_LOCAL binded_context {
        std::atomic<std::shared_ptr<const std::vector<std::shared_ptr<work_stealing_deque<task>>>>> executors_queues;
        std::list<uint32_t> completions;
        moodycamel::ConcurrentQueue<task> tasks;
        task_condition_variable on_closed_notifier;
        fast_task::rw_mutex no_race;
        fast_task::condition_variable_any new_task_notifier;
        uint16_t executors = 0;
        uint16_t expected_executors = 0;
        bool in_close : 1 = false;
        bool allow_implicit_start : 1 = false;
        bool fixed_size : 1 = false;
        bool abort_tasks_on_close : 1 = false;
        scheduler::executor_policy policy = scheduler::executor_policy::default_policy;
    };

    struct FT_API_LOCAL executor_global {
        task_condition_variable no_tasks_execute_notifier;
        fast_task::condition_variable time_notifier;
        fast_task::condition_variable_any tasks_notifier;
        fast_task::condition_variable_any executor_shutdown_notifier;

        std::atomic<std::shared_ptr<const std::vector<std::shared_ptr<work_stealing_deque<task>>>>> executors_queues;
        moodycamel::ConcurrentQueue<task> tasks;
        moodycamel::ConcurrentQueue<task> cold_tasks;
        hashed_timing_wheel timed_wheel;
        hashed_timing_wheel cold_timed_wheel;

        fast_task::rw_mutex task_thread_safety;
        fast_task::mutex task_timer_safety;


        std::atomic<bool> time_control_enabled{false};
        std::atomic<bool> shutdown_requested{false};
        std::atomic<bool> executor_shutting_down{false};

        std::atomic_size_t interrupts = 0; //debug counter of the usermode fast_task interrupts
        std::atomic_size_t executors = 0;
        std::atomic_size_t tasks_in_swap = 0;   //this means the tasks is stored outside the scheduler and excepted to be rescheduled later, ex. mutex
        std::atomic_size_t in_run_tasks = 0;    //count of tasks in run right now
        std::atomic_size_t executing_tasks = 0; //scheduled and in run tasks, including tasks in swap


        fast_task::rw_mutex binded_workers_safety;
        std::unordered_map<uint16_t, binded_context, std::hash<uint16_t>> binded_workers;


        std::atomic<bool> stw_request{false};
        std::unique_ptr<std::barrier<>> stw_barrier_enter;
        std::unique_ptr<std::barrier<>> stw_barrier_exit;
        std::atomic<size_t> thread_count{0}; //including native worker and timer
        fast_task::mutex stw_mutex;
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
        glob.time_notifier.notify_all();
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
    void FT_API_LOCAL swapCtxRelock(const mutex_unify& mut0, const mutex_unify& mut1);
    void FT_API_LOCAL transfer_task(task&&, enter_state* stat = nullptr);
    void FT_API_LOCAL makeTimeWait(std::chrono::high_resolution_clock::time_point t);
    void FT_API_LOCAL makeTimeWait_extern(task, std::chrono::high_resolution_clock::time_point time_point);

    void FT_API_LOCAL makeTimeWait_unsafe(std::chrono::high_resolution_clock::time_point t);
    void FT_API_LOCAL resetTimeWait();

    void FT_API_LOCAL taskExecutor(bool end_in_task_out = false, bool prevent_naming = false);
    void FT_API_LOCAL bindedTaskExecutor(uint16_t id);
    void FT_API_LOCAL unsafe_put_task_to_timed_queue(hashed_timing_wheel& wheel, std::chrono::high_resolution_clock::time_point t, task&);
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
    FT_DEBUG_ONLY(void FT_API_LOCAL register_object(task_query*));
    FT_DEBUG_ONLY(void FT_API_LOCAL register_object(deadline_timer*));

    FT_DEBUG_ONLY(void FT_API_LOCAL unregister_object(task_mutex*));
    FT_DEBUG_ONLY(void FT_API_LOCAL unregister_object(task_recursive_mutex*));
    FT_DEBUG_ONLY(void FT_API_LOCAL unregister_object(task_rw_mutex*));
    FT_DEBUG_ONLY(void FT_API_LOCAL unregister_object(task_condition_variable*));
    FT_DEBUG_ONLY(void FT_API_LOCAL unregister_object(task_object*));
    FT_DEBUG_ONLY(void FT_API_LOCAL unregister_object(task_semaphore*));
    FT_DEBUG_ONLY(void FT_API_LOCAL unregister_object(task_limiter*));
    FT_DEBUG_ONLY(void FT_API_LOCAL unregister_object(task_query*));
    FT_DEBUG_ONLY(void FT_API_LOCAL unregister_object(deadline_timer*));


    NOINLINE std::default_random_engine& FT_API_LOCAL get_thread_local_random_engine();
}

#endif
