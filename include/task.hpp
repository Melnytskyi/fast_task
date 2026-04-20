// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#pragma once
#ifndef FAST_TASK_TASKS
    #define FAST_TASK_TASKS
    #include "exceptions.hpp"
    #include "shared.hpp"
    #include "threading.hpp"
    #include <chrono>
    #include <coroutine>
    #include <forward_list>
    #include <functional>
    #include <list>
    #include <mutex>
    #include <variant>

    #pragma push_macro("min")
    #undef min

namespace fast_task {
    namespace debug {
        struct _debug_collect;
    }
    class task;

    struct FT_API_LOCAL task_promise_base {
        std::shared_ptr<task> task_object;
        std::suspend_always initial_suspend() noexcept;
        std::suspend_always final_suspend() noexcept;
    };

    struct base_coro_handle {
        std::coroutine_handle<> handle;
        task_promise_base* promise = nullptr;

        template <class Promise>
        base_coro_handle(std::coroutine_handle<Promise> h) 
            : handle(h), promise(&h.promise()) {}

        base_coro_handle() = default;
        base_coro_handle(const base_coro_handle&) = default;
        base_coro_handle(base_coro_handle&& other) noexcept = default;

        base_coro_handle& operator=(const base_coro_handle&) = default;
        base_coro_handle& operator=(base_coro_handle&& other) noexcept = default;
    };

    class FT_API task_mutex {
        friend class task_recursive_mutex;
        friend struct debug::_debug_collect;
        struct FT_API_LOCAL resume_task;

        struct FT_API_LOCAL private_values {
            std::list<resume_task> resume_task;
            fast_task::spin_lock no_race;
            class task* current_task = nullptr;
        } values;

        struct FT_API [[nodiscard]] task_mutex_lock_awaiter {
            task_mutex& mutex;

            bool await_ready() noexcept;
            bool await_suspend(base_coro_handle h);
            void await_resume() noexcept;
        };

        struct FT_API [[nodiscard]] task_mutex_try_lock_awaiter {
            task_mutex& mutex;
            std::chrono::high_resolution_clock::time_point time_point;
            base_coro_handle handle;
            bool successful = false;

            bool await_ready() noexcept;
            bool await_suspend(base_coro_handle h);
            bool await_resume() noexcept;
        };

    public:
        task_mutex();
        ~task_mutex();

        task_mutex_lock_awaiter async_lock();
        task_mutex_try_lock_awaiter async_try_lock_for(size_t milliseconds);
        task_mutex_try_lock_awaiter async_try_lock_until(std::chrono::high_resolution_clock::time_point time_point);
        void lock();
        bool try_lock();
        bool try_lock_for(size_t milliseconds);
        bool try_lock_until(std::chrono::high_resolution_clock::time_point time_point);
        void unlock();
        bool is_locked();
        void lifecycle_lock(std::shared_ptr<task>&& task);
        bool is_own();
    };

    class FT_API task_recursive_mutex {
        friend struct debug::_debug_collect;
        task_mutex mutex;
        uint32_t recursive_count = 0;

        struct FT_API [[nodiscard]] task_mutex_lock_awaiter {
            task_recursive_mutex& mutex;

            bool await_ready() noexcept;
            bool await_suspend(base_coro_handle h);
            void await_resume() noexcept;
        };

        struct FT_API [[nodiscard]] task_mutex_try_lock_awaiter {
            task_recursive_mutex& mutex;
            std::chrono::high_resolution_clock::time_point time_point;
            base_coro_handle handle;
            bool successful = false;

            bool await_ready() noexcept;
            bool await_suspend(base_coro_handle h);
            bool await_resume() noexcept;
        };

    public:
        task_recursive_mutex();
        ~task_recursive_mutex();

        task_mutex_lock_awaiter async_lock();
        task_mutex_try_lock_awaiter async_try_lock_for(size_t milliseconds);
        task_mutex_try_lock_awaiter async_try_lock_until(std::chrono::high_resolution_clock::time_point time_point);

        void lock();
        bool try_lock();
        bool try_lock_for(size_t milliseconds);
        bool try_lock_until(std::chrono::high_resolution_clock::time_point time_point);
        void unlock();
        bool is_locked();
        void lifecycle_lock(std::shared_ptr<task>&& task);
        bool is_own();
    };

    class FT_API task_rw_mutex {
        friend struct debug::_debug_collect;
        struct FT_API_LOCAL resume_task;

        struct FT_API_LOCAL private_values {
            friend class task_recursive_mutex;
            std::list<resume_task> resume_task;
            std::list<task*> readers;
            fast_task::spin_lock no_race;
            class task* current_writer_task = nullptr;
        } values;

        struct FT_API [[nodiscard]] task_mutex_write_lock_awaiter {
            task_rw_mutex& mutex;

            bool await_ready() noexcept;
            bool await_suspend(base_coro_handle h);
            void await_resume() noexcept;
        };

        struct FT_API [[nodiscard]] task_mutex_try_write_lock_awaiter {
            task_rw_mutex& mutex;
            std::chrono::high_resolution_clock::time_point time_point;
            base_coro_handle handle;
            bool successful = false;

            bool await_ready() noexcept;
            bool await_suspend(base_coro_handle h);
            bool await_resume() noexcept;
        };

        struct FT_API [[nodiscard]] task_mutex_read_lock_awaiter {
            task_rw_mutex& mutex;

            bool await_ready() noexcept;
            bool await_suspend(base_coro_handle h);
            void await_resume() noexcept;
        };

        struct FT_API [[nodiscard]] task_mutex_try_read_lock_awaiter {
            task_rw_mutex& mutex;
            std::chrono::high_resolution_clock::time_point time_point;
            base_coro_handle handle;
            bool successful = false;

            bool await_ready() noexcept;
            bool await_suspend(base_coro_handle h);
            bool await_resume() noexcept;
        };

    public:
        using read_write_mutex = void;
        task_rw_mutex();
        ~task_rw_mutex();

        task_mutex_read_lock_awaiter async_read_lock();
        task_mutex_try_read_lock_awaiter async_try_read_lock_for(size_t milliseconds);
        task_mutex_try_read_lock_awaiter async_try_read_lock_until(std::chrono::high_resolution_clock::time_point time_point);


        task_mutex_write_lock_awaiter async_write_lock();
        task_mutex_try_write_lock_awaiter async_try_write_lock_for(size_t milliseconds);
        task_mutex_try_write_lock_awaiter async_try_write_lock_until(std::chrono::high_resolution_clock::time_point time_point);

        void read_lock();
        bool try_read_lock();
        bool try_read_lock_for(size_t milliseconds);
        bool try_read_lock_until(std::chrono::high_resolution_clock::time_point time_point);
        void read_unlock();
        bool is_read_locked();
        void lifecycle_read_lock(std::shared_ptr<task>&& task);

        void write_lock();
        bool try_write_lock();
        bool try_write_lock_for(size_t milliseconds);
        bool try_write_lock_until(std::chrono::high_resolution_clock::time_point time_point);
        void write_unlock();
        bool is_write_locked();
        void lifecycle_write_lock(std::shared_ptr<task>&& task);

        void lock() {
            write_lock();
        }

        void unlock() {
            write_unlock();
        }

        bool try_lock() {
            return try_write_lock();
        }

        void lock_shared() {
            read_lock();
        }

        void unlock_shared() {
            read_unlock();
        }

        bool try_lock_shared() {
            return try_read_lock();
        }

        bool is_own();
    };

    class FT_API read_lock {
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

    class FT_API write_lock {
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

    template <class T, class mutex_t = task_rw_mutex>
    class protected_value {
        T value;

    public:
        mutable mutex_t mutex;

        template <class... Args>
        protected_value(Args&&... args)
            : value(std::forward<Args>(args)...) {}

        protected_value(protected_value&& move)
            : value(std::move(move.value)) {}

        protected_value& operator=(protected_value&& move) = delete;

        template <class _Accessor>
        decltype(auto) get(_Accessor&& accessor) const {
            shared_lock lock(mutex);
            return accessor(value);
        }

        template <class _Accessor>
        decltype(auto) set(_Accessor&& accessor) {
            unique_lock lock(mutex);
            return accessor(value);
        }
    };

    class FT_API mutex_unify {
        enum class mutex_unify_type : uint8_t {
            noting,
            nmut,
            ntimed,
            nrec,
            rwmut_r,
            rwmut_w,
            std_nmut,
            std_ntimed,
            std_nrec,
            umut,
            urmut,
            urwmut_r,
            urwmut_w,
            mmut,
            uspin,
        };

        union FT_API_LOCAL {
            std::mutex* std_nmut = nullptr;
            std::timed_mutex* std_ntimed;
            std::recursive_mutex* std_nrec;
            fast_task::mutex* nmut;
            fast_task::timed_mutex* ntimed;
            fast_task::rw_mutex* rwmut;
            fast_task::recursive_mutex* nrec;
            fast_task::spin_lock* uspin;
            task_mutex* umut;
            task_rw_mutex* urwmut;
            task_recursive_mutex* urmut;
            class multiply_mutex* mmut;
        };

        mutex_unify_type type;

    public:
        mutex_unify();
        mutex_unify(const mutex_unify& mut);
        mutex_unify(std::mutex& smut);
        mutex_unify(std::timed_mutex& smut);
        mutex_unify(std::recursive_mutex& smut);
        mutex_unify(fast_task::mutex& smut);
        mutex_unify(fast_task::timed_mutex& smut);
        mutex_unify(fast_task::rw_mutex& smut, bool write_read = true);
        mutex_unify(fast_task::recursive_mutex& smut);
        mutex_unify(fast_task::spin_lock& smut);
        mutex_unify(task_mutex& smut);
        mutex_unify(task_rw_mutex& smut, bool write_read = true);
        mutex_unify(task_recursive_mutex& smut);
        mutex_unify(class multiply_mutex& mmut);
        mutex_unify(std::nullptr_t);

        ~mutex_unify();

        mutex_unify& operator=(const mutex_unify&);
        mutex_unify& operator=(std::mutex&);
        mutex_unify& operator=(std::timed_mutex&);
        mutex_unify& operator=(std::recursive_mutex&);
        mutex_unify& operator=(fast_task::mutex&);
        mutex_unify& operator=(fast_task::timed_mutex&);
        mutex_unify& operator=(fast_task::recursive_mutex&);
        mutex_unify& operator=(fast_task::spin_lock&);
        mutex_unify& operator=(task_mutex&);
        mutex_unify& operator=(task_recursive_mutex&);
        mutex_unify& operator=(class multiply_mutex&);
        mutex_unify& operator=(std::nullptr_t);

        bool operator==(const mutex_unify&);
        bool operator==(std::mutex&);
        bool operator==(std::timed_mutex&);
        bool operator==(std::recursive_mutex&);
        bool operator==(fast_task::mutex&);
        bool operator==(fast_task::timed_mutex&);
        bool operator==(fast_task::rw_mutex&);
        bool operator==(fast_task::recursive_mutex&);
        bool operator==(fast_task::spin_lock&);
        bool operator==(task_mutex&);
        bool operator==(task_rw_mutex&);
        bool operator==(task_recursive_mutex&);
        bool operator==(class multiply_mutex&);
        bool operator==(std::nullptr_t);

        void lock();
        bool try_lock();
        bool try_lock_for(size_t milliseconds);
        bool try_lock_until(std::chrono::high_resolution_clock::time_point time_point);
        void unlock();

        void relock_start();
        void relock_end();

        operator bool();
    };

    class FT_API multiply_mutex {
        struct FT_API_LOCAL private_value {
            std::vector<mutex_unify> mu;
        } value;

    public:
        multiply_mutex(const std::initializer_list<mutex_unify>& muts);
        void lock();
        bool try_lock();
        bool try_lock_for(size_t milliseconds);
        bool try_lock_until(std::chrono::high_resolution_clock::time_point time_point);
        void unlock();
    };

    class FT_API task_condition_variable {
        friend struct debug::_debug_collect;
        struct FT_API_LOCAL resume_task;

        struct FT_API_LOCAL private_values {
            std::list<resume_task> resume_task;
            fast_task::mutex no_race;
        } values;

        struct FT_API [[nodiscard]] task_wait_awaiter {
            task_condition_variable& cv;
            bool await_ready() noexcept;
            bool await_suspend(base_coro_handle h);
            void await_resume() noexcept;
        };

        struct FT_API [[nodiscard]] task_wait_util_awaiter {
            task_condition_variable& cv;
            std::chrono::high_resolution_clock::time_point time_point;
            base_coro_handle handle;
            bool successful = false;

            bool await_ready() noexcept;
            bool await_suspend(base_coro_handle h);
            bool await_resume() noexcept;
        };

    public:
        task_condition_variable();
        ~task_condition_variable();
        task_wait_awaiter async_wait(fast_task::unique_lock<mutex_unify>& lock);
        task_wait_util_awaiter async_wait_for(fast_task::unique_lock<mutex_unify>& lock, size_t milliseconds);
        task_wait_util_awaiter async_wait_until(fast_task::unique_lock<mutex_unify>& lock, std::chrono::high_resolution_clock::time_point time_point);

        void wait(fast_task::unique_lock<mutex_unify>& lock);
        bool wait_for(fast_task::unique_lock<mutex_unify>& lock, size_t milliseconds);
        bool wait_until(fast_task::unique_lock<mutex_unify>& lock, std::chrono::high_resolution_clock::time_point time_point);
        void wait(std::unique_lock<mutex_unify>& lock);
        bool wait_for(std::unique_lock<mutex_unify>& lock, size_t milliseconds);
        bool wait_until(std::unique_lock<mutex_unify>& lock, std::chrono::high_resolution_clock::time_point time_point);
        void notify_one();
        void notify_all();
        bool has_waiters();
        void callback(fast_task::unique_lock<mutex_unify>& mut, const std::shared_ptr<task>& task);
        void callback(std::unique_lock<mutex_unify>& mut, const std::shared_ptr<task>& task);
    };

    enum class task_priority {
        background,
        low,
        lower,
        normal,
        higher,
        high,
        semi_realtime,
    };

    //The task class has two modes,
    // the normal one allows setting `func` function which would start on ist own stack
    //  on exception it allows to catch using `ex_handle` callback
    // the extended one allows handling on_start, on_await and on_cancel events.
    //  the on_await and on_cancel executed on calling thread and could be used for example, to wrap the sockets in the task interface
    //  the on_start executed on its own stack like normal one and allows using all synchronization primitives
    //    when is_restartable is set the task could be restarted, to disable use this_task::the_coroutine_ended
    //    but when the is_on_scheduler variable is set, the task would be executed on scheduler stack which would reduce the deallocations
    //      and the task should be aware, the scheduler could not interrupt itself, so the task effectively becomes cooperative only,
    //      the task should never consume too much time on scheduler to prevent the task overloading the whole scheduler system
    //      and the task should use async_* methods for synchronization, the regular operations would throw exception
    //      this flag allows to create stackless coroutines like in c++ or other language
    class FT_API task {
        void awaitEnd(fast_task::unique_lock<mutex_unify>& l);
        struct FT_API_LOCAL execution_data;

        struct FT_API_LOCAL data {
            union FT_API_LOCAL callbacks_data {
                bool is_extended_mode : 1 = false;

                struct FT_API_LOCAL normal_mode_t {
                    bool is_extended_mode : 1;
                    std::move_only_function<void(const std::exception_ptr&)> ex_handle;
                    std::move_only_function<void()> func;

                    ~normal_mode_t() = default;
                } normal_mode;

                struct FT_API_LOCAL extended_mode_t {
                    bool is_extended_mode : 1;
                    bool is_restartable : 1;
                    void* data;
                    void (*on_start)(void*);
                    void (*on_await)(void*);
                    void (*on_cancel)(void*);
                    void (*on_destruct)(void*);

                    ~extended_mode_t() = default;
                } extended_mode;

                callbacks_data();

                callbacks_data(callbacks_data&& move) noexcept;
                ~callbacks_data();

                callbacks_data& operator=(callbacks_data&&) = delete;
            } callbacks;

            task_condition_variable result_notify;
            fast_task::spin_lock no_race;
            mutex_unify relock_0;
            mutex_unify relock_1;
            mutex_unify relock_2;
            std::chrono::high_resolution_clock::time_point::rep timeout = std::chrono::high_resolution_clock::time_point::min().time_since_epoch().count();
            uint16_t awake_check = 0;
            uint16_t bind_to_worker_id = (uint16_t)-1;
            bool time_end_flag : 1 = false;
            bool started : 1 = false;
            bool awaked : 1 = false;
            bool end_of_life : 1 = false;
            bool make_cancel : 1 = false;
            bool auto_bind_worker : 1 = false;
            bool invalid_switch_caught : 1 = false;
            bool completed : 1 = false;
            bool is_on_scheduler : 1 = false;
            execution_data* exdata = nullptr;
        } data_;

        friend task::data& get_data(task* task);
        friend task::data& get_data(std::shared_ptr<task>& task);
        friend task::data& get_data(const std::shared_ptr<task>& task);
        friend task::execution_data& get_execution_data(task* task);
        friend task::execution_data& get_execution_data(std::shared_ptr<task>& task);
        friend task::execution_data& get_execution_data(const std::shared_ptr<task>& task);

        void _extended_end();

    public:
        static size_t max_running_tasks;
        static bool enable_task_naming;

        task(void* data, void (*on_start)(void*), void (*on_await)(void*), void (*on_cancel)(void*), void (*on_destruct)(void*), bool is_restartable = false, bool is_on_scheduler = false);
        task(std::move_only_function<void()>&& func, std::move_only_function<void(const std::exception_ptr&)>&& ex_handle = nullptr, std::chrono::high_resolution_clock::time_point timeout = std::chrono::high_resolution_clock::time_point::min(), task_priority priority = task_priority::high, bool is_on_scheduler = false);

        task(task&& mov) noexcept;
        ~task();
        task& operator=(task&&) = delete;

        void set_auto_bind_worker(bool enable = true) noexcept;
        void set_worker_id(uint16_t id) noexcept;
        void set_priority(task_priority) noexcept;
        void set_timeout(std::chrono::high_resolution_clock::time_point timeout) noexcept;
        task_priority get_priority() const noexcept;
        size_t get_counter_interrupt() const noexcept;
        size_t get_counter_context_switch() const noexcept;
        std::chrono::high_resolution_clock::time_point get_timeout() const noexcept;
        bool is_cancellation_requested() const noexcept;
        bool is_ended() const noexcept;
        void await_task();
        void callback(const std::shared_ptr<task>& task);
        void notify_cancel();
        void await_notify_cancel();

        template <class FN>
        void access_dummy(FN&& fn) {
            if (data_.callbacks.is_extended_mode)
                fn(data_.callbacks.extended_mode.data);
            else
                throw std::runtime_error("This task is not in extended mode");
        };

        template <class FN>
        void end_dummy(FN&& fn) {
            if (data_.callbacks.is_extended_mode) {
                fn(data_.callbacks.extended_mode.data);
                fast_task::lock_guard l(data_.no_race);
                data_.end_of_life = true;
                data_.result_notify.notify_all();
            } else
                throw std::runtime_error("This task is not in extended mode");
        };

        static std::shared_ptr<task> run(std::function<void()>&& func);
        static std::shared_ptr<task> create(std::function<void()>&& func);


        static void await_task(const std::shared_ptr<task>& lgr_task, bool make_start = true);
        static void await_multiple(std::list<std::shared_ptr<task>>& tasks, bool pre_started = false, bool release = false);
        static void await_multiple(std::vector<std::shared_ptr<task>>& tasks, bool pre_started = false, bool release = false);
        static void await_multiple(std::shared_ptr<task>* tasks, size_t len, bool pre_started = false, bool release = false);

        static std::shared_ptr<task> callback_dummy(void* dummy_data, void (*on_start)(void*), void (*on_await)(void*), void (*on_cancel)(void*), void (*on_destruct)(void*), bool is_restartable = false, bool is_on_scheduler = false);
        static std::shared_ptr<task> callback_dummy(void* dummy_data, void (*on_await)(void*), void (*on_cancel)(void*), void (*on_destruct)(void*), bool is_restartable = false, bool is_on_scheduler = false);
    };

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


        /**
         * @brief requests stop the world to scheduler and the scheduler would stop its execution 
         *         and including internal threads and then runs the function. 
         *         This means the function is allowed only and only in native threads.
         *         
         *  @note Could be used for GC or debugging purposes
         *  @param func The function to execute when all workers stopped
         *  @throws `invalid_native_context` in task context
         *  @returns noting
         */
        void FT_API request_stw(const std::function<void()>& func);

        //DEBUG ONLY, not recommended use in production
        void FT_API clean_up();
        //DEBUG ONLY, not recommended use in production
    }

    namespace this_task {
        size_t FT_API get_id() noexcept;
        void FT_API yield();
        void FT_API sleep_until(std::chrono::high_resolution_clock::time_point time_point);

        template <class Dur_resolution, class Dur_type>
        void sleep_for(std::chrono::duration<Dur_resolution, Dur_type> duration) {
            sleep_until(std::chrono::high_resolution_clock::now() + duration);
        }

        void FT_API check_cancellation();
        bool FT_API is_cancellation_requested() noexcept;
        void FT_API self_cancel();
        bool FT_API is_task() noexcept;
        void FT_API the_coroutine_ended() noexcept;
    }

    class FT_API task_semaphore {
        friend struct debug::_debug_collect;
        struct FT_API_LOCAL resume_task;

        struct private_values {
            std::list<resume_task> resume_task;
            fast_task::spin_lock no_race;
            fast_task::condition_variable_any native_notify;
            size_t allow_threshold = 0;
            size_t max_threshold = 0;
        } values;

        struct FT_API [[nodiscard]] task_lock_awaiter {
            task_semaphore& sem;

            bool await_ready() noexcept;
            bool await_suspend(base_coro_handle h);
            void await_resume() noexcept;
        };

        struct FT_API [[nodiscard]] task_try_lock_awaiter {
            task_semaphore& sem;
            std::chrono::high_resolution_clock::time_point time_point;
            base_coro_handle handle;
            bool successful = false;

            bool await_ready() noexcept;
            bool await_suspend(base_coro_handle h);
            bool await_resume() noexcept;
        };

    public:
        task_semaphore();
        ~task_semaphore();
        task_lock_awaiter async_lock();
        task_try_lock_awaiter async_try_lock_for(size_t milliseconds);
        task_try_lock_awaiter async_try_lock_until(std::chrono::high_resolution_clock::time_point time_point);

        void set_max_threshold(size_t val);
        void lock();
        bool try_lock();
        bool try_lock_for(size_t milliseconds);
        bool try_lock_until(std::chrono::high_resolution_clock::time_point time_point);
        void release();
        void release_all();
        bool is_locked();
    };

    //same as task_semaphore but with checks
    class FT_API task_limiter {
        friend struct debug::_debug_collect;
        struct FT_API_LOCAL resume_task;

        struct private_values {
            std::list<void*> lock_check;
            std::list<resume_task> resume_task;
            fast_task::spin_lock no_race;
            fast_task::condition_variable_any native_notify;
            size_t allow_threshold = 0;
            size_t max_threshold = 1;
            bool locked = false;
        } values;

        void unchecked_unlock();

        struct FT_API [[nodiscard]] task_lock_awaiter {
            task_limiter& lim;

            bool await_ready() noexcept;
            bool await_suspend(base_coro_handle h);
            void await_resume();
        };

        struct FT_API [[nodiscard]] task_try_lock_awaiter {
            task_limiter& lim;
            std::chrono::high_resolution_clock::time_point time_point;
            base_coro_handle handle;
            bool successful = false;

            bool await_ready() noexcept;
            bool await_suspend(base_coro_handle h);
            bool await_resume();
        };

    public:
        task_limiter();
        ~task_limiter();
        task_lock_awaiter async_lock();
        task_try_lock_awaiter async_try_lock_for(size_t milliseconds);
        task_try_lock_awaiter async_try_lock_until(std::chrono::high_resolution_clock::time_point time_point);

        void set_max_threshold(size_t val);
        void lock();
        bool try_lock();
        bool try_lock_for(size_t milliseconds);
        bool try_lock_until(std::chrono::high_resolution_clock::time_point time_point);
        void unlock();
        bool is_locked();
    };

    class FT_API task_query {
        friend struct debug::_debug_collect;
        struct task_query_handle* handle;
        friend void __TaskQuery_add_task_leave(struct task_query_handle* tqh);

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

    class FT_API deadline_timer {
        friend struct debug::_debug_collect;
        struct handle;
        handle* hh;

    public:
        enum class status {
            timeouted, //normal timeout
            canceled,  //set when used cancel,cancel_one, expires_from_now or expires_at
            shutdown,  //set when deadline_timer is destructed
        };
        deadline_timer();
        deadline_timer(std::chrono::high_resolution_clock::duration);
        deadline_timer(std::chrono::high_resolution_clock::time_point);
        deadline_timer(deadline_timer&&);
        ~deadline_timer();

        deadline_timer& operator=(deadline_timer&&) = delete;

        size_t cancel();
        bool cancel_one();

        //awoken when timeouted
        void async_wait(const std::shared_ptr<task>&);

        //true if got timeout
        void async_wait(std::function<void(status)>&&);
        void async_wait(const std::function<void(status)>&);

        //returns count of canceled tasks
        size_t expires_from_now(std::chrono::high_resolution_clock::duration dur);
        size_t expires_at(std::chrono::high_resolution_clock::time_point dur);

        status wait();
        status wait(fast_task::unique_lock<mutex_unify>& lock);
        status wait(std::unique_lock<mutex_unify>& lock);

        bool timed_out();
    };
}


    #pragma pop_macro("min")
#endif
