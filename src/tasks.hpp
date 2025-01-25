// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#pragma once
#ifndef RUN_TIME_TASKS
    #include <chrono>
    #include <condition_variable>
    #include <forward_list>
    #include <functional>
    #include <list>
    #include <mutex>
    #include <thread>

    #pragma push_macro("min")
    #undef min

namespace fast_task {
    struct task;

    namespace __ {
        struct resume_task {
            std::shared_ptr<task> task;
            uint16_t awake_check;
        };
    }

    class task_cancellation {
        bool in_landing = false;
        friend void forceCancelCancellation(task_cancellation& cancel_token);

    public:
        task_cancellation();
        ~task_cancellation();
        bool _in_landing();
    };

    #pragma pack(push)
    #pragma pack(1)

    class task_mutex {
        friend class task_recursive_mutex;
        std::list<__::resume_task> resume_task;
        std::timed_mutex no_race;
        struct task* current_task = nullptr;

    public:
        task_mutex() = default;

        ~task_mutex();
        void lock();
        bool try_lock();
        bool try_lock_for(size_t milliseconds);
        bool try_lock_until(std::chrono::high_resolution_clock::time_point time_point);
        void unlock();
        bool is_locked();
        void lifecycle_lock(std::shared_ptr<task>& task);
        bool is_own();
    };

    class task_recursive_mutex {
        task_mutex mutex;
        uint32_t recursive_count = 0;

    public:
        task_recursive_mutex() = default;

        ~task_recursive_mutex();
        void lock();
        bool try_lock();
        bool try_lock_for(size_t milliseconds);
        bool try_lock_until(std::chrono::high_resolution_clock::time_point time_point);
        void unlock();
        bool is_locked();
        void lifecycle_lock(std::shared_ptr<task>& task);
        bool is_own();
    };

    class task_rw_mutex {
        friend class task_recursive_mutex;
        std::list<__::resume_task> resume_task;
        std::list<task*> readers;
        std::timed_mutex no_race;
        struct task* current_writer_task = nullptr;


    public:
        task_rw_mutex() = default;

        ~task_rw_mutex();
        void read_lock();
        bool try_read_lock();
        bool try_read_lock_for(size_t milliseconds);
        bool try_read_lock_until(std::chrono::high_resolution_clock::time_point time_point);
        void read_unlock();
        bool is_read_locked();
        void lifecycle_read_lock(std::shared_ptr<task>& task);

        void write_lock();
        bool try_write_lock();
        bool try_write_lock_for(size_t milliseconds);
        bool try_write_lock_until(std::chrono::high_resolution_clock::time_point time_point);
        void write_unlock();
        bool is_write_locked();
        void lifecycle_write_lock(std::shared_ptr<task>& task);

        bool is_own();
    };

    class read_lock {
        task_rw_mutex& mutex;

    public:
        read_lock(task_rw_mutex& mutex)
            : mutex(mutex) {
            mutex.read_lock();
        }

        ~read_lock() {
            mutex.read_unlock();
        }
    };

    class write_lock {
        task_rw_mutex& mutex;

    public:
        write_lock(task_rw_mutex& mutex)
            : mutex(mutex) {
            mutex.write_lock();
        }

        ~write_lock() {
            mutex.write_unlock();
        }
    };

    template <class T>
    class protected_value {
        T value;

    public:
        task_rw_mutex mutex;

        template <class... Args>
        protected_value(Args&&... args)
            : value(std::forward<Args>(args)...) {}

        protected_value(protected_value&& move)
            : value(std::move(move.value)) {}

        template <class _Accessor>
        decltype(auto) get(_Accessor&& accessor) const {
            read_lock lock(const_cast<task_rw_mutex&>(mutex));
            return accessor(const_cast<const T&>(value));
        }

        template <class _Accessor>
        decltype(auto) set(_Accessor&& accessor) {
            write_lock lock(mutex);
            return accessor(value);
        }
    };

    enum class mutex_unify_type : uint8_t {
        noting,
        nmut,
        ntimed,
        nrec,
        umut,
        urmut,
        urwmut_r,
        urwmut_w,
        mmut
    };

    struct mutex_unify {
        union {
            std::mutex* nmut = nullptr;
            std::timed_mutex* ntimed;
            std::recursive_mutex* nrec;
            task_mutex* umut;
            task_rw_mutex* urwmut;
            task_recursive_mutex* urmut;
            struct multiply_mutex* mmut;
        };

        mutex_unify();
        mutex_unify(const mutex_unify& mut);
        mutex_unify(std::mutex& smut);
        mutex_unify(std::timed_mutex& smut);
        mutex_unify(std::recursive_mutex& smut);
        mutex_unify(task_mutex& smut);
        mutex_unify(task_rw_mutex& smut, bool read_write = true);
        mutex_unify(task_recursive_mutex& smut);
        mutex_unify(struct multiply_mutex& mmut);
        mutex_unify(nullptr_t);

        ~mutex_unify();

        mutex_unify& operator=(const mutex_unify& mut);
        mutex_unify& operator=(std::mutex& smut);
        mutex_unify& operator=(std::timed_mutex& smut);
        mutex_unify& operator=(std::recursive_mutex& smut);
        mutex_unify& operator=(task_mutex& smut);
        mutex_unify& operator=(task_recursive_mutex& smut);
        mutex_unify& operator=(struct multiply_mutex& mmut);
        mutex_unify& operator=(nullptr_t);

        mutex_unify_type type;
        void lock();
        bool try_lock();
        bool try_lock_for(size_t milliseconds);
        bool try_lock_until(std::chrono::high_resolution_clock::time_point time_point);
        void unlock();

        void relock_start();
        void relock_end();

        operator bool();
    };

    struct multiply_mutex {
        std::vector<mutex_unify> mu;
        multiply_mutex(const std::initializer_list<mutex_unify>& muts);
        void lock();
        bool try_lock();
        bool try_lock_for(size_t milliseconds);
        bool try_lock_until(std::chrono::high_resolution_clock::time_point time_point);
        void unlock();
    };

    class task_condition_variable {
        std::list<__::resume_task> resume_task;
        std::mutex no_race;

    public:
        task_condition_variable();
        ~task_condition_variable();
        void wait(std::unique_lock<mutex_unify>& lock);
        bool wait_for(std::unique_lock<mutex_unify>& lock, size_t milliseconds);
        bool wait_until(std::unique_lock<mutex_unify>& lock, std::chrono::high_resolution_clock::time_point time_point);
        void notify_one();
        void notify_all();
        bool has_waiters();
        void callback(std::unique_lock<mutex_unify>& mut, const std::shared_ptr<task>& task);
    };

    struct task_result {
        task_condition_variable result_notify;
        void* context = nullptr;
        bool end_of_life = false;
        bool has_result = false;
        void getResult(std::unique_lock<mutex_unify>& l);
        void awaitEnd(std::unique_lock<mutex_unify>& l);
        void yield_result_begin(std::unique_lock<mutex_unify>& l, bool release = true);
        void yield_result_end(std::unique_lock<mutex_unify>& l, bool release = true);

        void final_result_begin(std::unique_lock<mutex_unify>& l, bool release = true);
        void final_result_end(std::unique_lock<mutex_unify>& l, bool release = true);

        task_result();
        task_result(task_result&& move) noexcept;
        ~task_result();
    };

    struct task {
        static size_t max_running_tasks;
        static size_t max_planned_tasks;
        static bool enable_task_naming;

        task_result fres;
        std::function<void(const std::exception_ptr&)> ex_handle;
        std::function<void()> func;
        std::mutex no_race;
        mutex_unify relock_0;
        mutex_unify relock_1;
        mutex_unify relock_2;
        std::chrono::high_resolution_clock::time_point timeout = std::chrono::high_resolution_clock::time_point::min();
        uint16_t awake_check = 0;
        uint16_t bind_to_worker_id = -1;
        bool time_end_flag : 1 = false;
        bool started : 1 = false;
        bool awaked : 1 = false;
        bool end_of_life : 1 = false;
        bool make_cancel : 1 = false;
        bool auto_bind_worker : 1 = false;
        bool invalid_switch_caught : 1 = false;

    public:
        task(std::function<void()> func, std::function<void(const std::exception_ptr&)> ex_handle = nullptr, std::chrono::high_resolution_clock::time_point timeout = std::chrono::high_resolution_clock::time_point::min())
            : func(func), ex_handle(ex_handle), timeout(timeout) {}

        task(task&& mov) noexcept;
        ~task();
        void set_auto_bind_worker(bool enable = true);
        void set_worker_id(uint16_t id);

        static void schedule(std::shared_ptr<task>&& task, size_t milliseconds);
        static void schedule(const std::shared_ptr<task>& task, size_t milliseconds);
        static void schedule_until(std::shared_ptr<task>&& task, std::chrono::high_resolution_clock::time_point time_point);
        static void schedule_until(const std::shared_ptr<task>& task, std::chrono::high_resolution_clock::time_point time_point);
        static void start(std::shared_ptr<task>&& lgr_task);
        static void start(std::list<std::shared_ptr<task>>& lgr_task);
        static void start(const std::shared_ptr<task>& lgr_task);

        static uint16_t create_bind_only_executor(uint16_t fixed_count, bool allow_implicit_start);
        static void assign_bind_only_executor(uint16_t id, uint16_t fixed_count, bool allow_implicit_start);
        static void close_bind_only_executor(uint16_t id);

        static void create_executor(size_t count = 1);
        static size_t total_executors();
        static void reduce_executor(size_t count = 1);
        static void become_task_executor();

        static void await_no_tasks(bool be_executor = false);
        static void await_end_tasks(bool be_executor = false);
        static void sleep(size_t milliseconds);
        static void sleep_until(std::chrono::high_resolution_clock::time_point time_point);
        static void yield();

        static bool has_result(std::shared_ptr<task>& lgr_task);
        static void await_task(const std::shared_ptr<task>& lgr_task, bool make_start = true);
        static void await_multiple(std::list<std::shared_ptr<task>>& tasks, bool pre_started = false, bool release = false);
        static void await_multiple(std::shared_ptr<task>* tasks, size_t len, bool pre_started = false, bool release = false);
        static void notify_cancel(std::shared_ptr<task>& task);
        static void notify_cancel(std::list<std::shared_ptr<task>>& tasks);
        static void await_notify_cancel(std::shared_ptr<task>& task);
        static void await_notify_cancel(std::list<std::shared_ptr<task>>& tasks);
        static size_t task_id();
        static void check_cancellation();
        static void self_cancel();
        static bool is_task();


        static std::shared_ptr<task> dummy_task();
        static std::shared_ptr<task> cxx_native_bridge(bool& checker, std::condition_variable_any& cd);

        static void explicitStartTimer();
        static void shutDown();
        static void callback(std::shared_ptr<task>& target, const std::shared_ptr<task>& task);


        //DEBUG ONLY, not recommended use in production
        static void clean_up();
        //DEBUG ONLY, not recommended use in production
    };

    #pragma pack(pop)

    class task_semaphore {
        std::list<__::resume_task> resume_task;
        std::timed_mutex no_race;
        std::condition_variable_any native_notify;
        size_t allow_threshold = 0;
        size_t max_threshold = 0;

    public:
        task_semaphore() = default;

        void setMaxThreshold(size_t val);
        void lock();
        bool try_lock();
        bool try_lock_for(size_t milliseconds);
        bool try_lock_until(std::chrono::high_resolution_clock::time_point time_point);
        void release();
        void release_all();
        bool is_locked();
    };

    class task_limiter {
        std::list<void*> lock_check;
        std::list<__::resume_task> resume_task;
        std::timed_mutex no_race;
        std::condition_variable_any native_notify;
        size_t allow_threshold = 0;
        size_t max_threshold = 1;
        bool locked = false;
        void unchecked_unlock();

    public:
        task_limiter() = default;

        void set_max_threshold(size_t val);
        void lock();
        bool try_lock();
        bool try_lock_for(size_t milliseconds);
        bool try_lock_until(std::chrono::high_resolution_clock::time_point time_point);
        void unlock();
        bool is_locked();
    };

    class task_query {
        class task_query_handle* handle;
        friend void __TaskQuery_add_task_leave(class task_query_handle* tqh);

    public:
        task_query(size_t at_execution_max = 0);
        ~task_query();
        void add(std::shared_ptr<task>&);
        void add(std::shared_ptr<task>&&);
        void enable();
        void disable();
        bool in_query(const std::shared_ptr<task>& task);
        void set_max_at_execution(size_t val);
        size_t get_max_at_execution();
        void wait();
        bool wait_for(size_t milliseconds);
        bool wait_until(std::chrono::high_resolution_clock::time_point time_point);
    };

    #pragma pop_macro("min")
}
#endif