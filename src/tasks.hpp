// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#pragma once
#ifndef FAST_TASK_TASKS
    #define FAST_TASK_TASKS
    #ifndef tasks_enable_preemptive_scheduler_preview
        #define tasks_enable_preemptive_scheduler_preview true
    #endif
    #include "threading.hpp"
    #include <chrono>
    #include <condition_variable>
    #include <forward_list>
    #include <functional>
    #include <list>
    #include <mutex>

    #pragma push_macro("min")
    #undef min

namespace fast_task {
    class task;

    class task_cancellation {
        bool in_landing = false;
        friend void forceCancelCancellation(const task_cancellation& cancel_token);

    public:
        task_cancellation();
        ~task_cancellation();
        bool _in_landing();
    };

    class task_mutex {
        struct resume_task;
        friend class task_recursive_mutex;
        std::list<resume_task> resume_task;
        fast_task::timed_mutex no_race;
        class task* current_task = nullptr;

    public:
        task_mutex();
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
        task_recursive_mutex();
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
        struct resume_task;
        friend class task_recursive_mutex;
        std::list<resume_task> resume_task;
        std::list<task*> readers;
        fast_task::timed_mutex no_race;
        class task* current_writer_task = nullptr;


    public:
        task_rw_mutex();
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

        protected_value& operator=(protected_value&& move) = delete;

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

    class mutex_unify {
        enum class mutex_unify_type : uint8_t {
            noting,
            nmut,
            ntimed,
            nrec,
            std_nmut,
            std_ntimed,
            std_nrec,
            umut,
            urmut,
            urwmut_r,
            urwmut_w,
            mmut
        };

        union {
            std::mutex* std_nmut = nullptr;
            std::timed_mutex* std_ntimed;
            std::recursive_mutex* std_nrec;
            fast_task::mutex* nmut;
            fast_task::timed_mutex* ntimed;
            fast_task::recursive_mutex* nrec;
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
        mutex_unify(fast_task::recursive_mutex& smut);
        mutex_unify(task_mutex& smut);
        mutex_unify(task_rw_mutex& smut, bool read_write = true);
        mutex_unify(task_recursive_mutex& smut);
        mutex_unify(class multiply_mutex& mmut);
        mutex_unify(nullptr_t);

        ~mutex_unify();

        mutex_unify& operator=(const mutex_unify&);
        mutex_unify& operator=(std::mutex&);
        mutex_unify& operator=(std::timed_mutex&);
        mutex_unify& operator=(std::recursive_mutex&);
        mutex_unify& operator=(fast_task::mutex&);
        mutex_unify& operator=(fast_task::timed_mutex&);
        mutex_unify& operator=(fast_task::recursive_mutex&);
        mutex_unify& operator=(task_mutex&);
        mutex_unify& operator=(task_recursive_mutex&);
        mutex_unify& operator=(class multiply_mutex&);
        mutex_unify& operator=(nullptr_t);

        bool operator==(const mutex_unify&);
        bool operator==(std::mutex&);
        bool operator==(std::timed_mutex&);
        bool operator==(std::recursive_mutex&);
        bool operator==(fast_task::mutex&);
        bool operator==(fast_task::timed_mutex&);
        bool operator==(fast_task::recursive_mutex&);
        bool operator==(task_mutex&);
        bool operator==(task_rw_mutex&);
        bool operator==(task_recursive_mutex&);
        bool operator==(class multiply_mutex&);
        bool operator==(nullptr_t);

        void lock();
        bool try_lock();
        bool try_lock_for(size_t milliseconds);
        bool try_lock_until(std::chrono::high_resolution_clock::time_point time_point);
        void unlock();

        void relock_start();
        void relock_end();

        operator bool();
    };

    class multiply_mutex {
        std::vector<mutex_unify> mu;

    public:
        multiply_mutex(const std::initializer_list<mutex_unify>& muts);
        void lock();
        bool try_lock();
        bool try_lock_for(size_t milliseconds);
        bool try_lock_until(std::chrono::high_resolution_clock::time_point time_point);
        void unlock();
    };

    class task_condition_variable {
        struct resume_task;
        std::list<resume_task> resume_task;
        fast_task::mutex no_race;

    public:
        task_condition_variable();
        ~task_condition_variable();
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
    //  on exception it allows to catch using `ex_handle`
    // the extended one allows handling on_start, on_await and on_cancel events.
    //  the on_await and on_cancel executed on calling thread and could be used for example, to wrap the sockets in the task interface
    //  the on_start executed on its own stack like normal one and allows using all synchronization primitives
    //    but when is_coroutine is set the task could be restarted, to complete coroutine use this_task::the_coroutine_ended
    //    this could be used to reduce allocated memory for stacks, because they would be reused for other coroutines
    class task {
        void awaitEnd(fast_task::unique_lock<mutex_unify>& l);

        struct data {
            union callbacks_data {
                bool is_extended_mode : 1 = false;

                struct normal_mode_t {
                    bool is_extended_mode : 1;
                    std::function<void(const std::exception_ptr&)> ex_handle;
                    std::function<void()> func;

                    ~normal_mode_t() = default;
                } normal_mode;

                struct extended_mode_t {
                    bool is_extended_mode : 1;
                    bool is_coroutine : 1;
                    void* data;
                    void (*on_start)(void*);
                    void (*on_await)(void*);
                    void (*on_cancel)(void*);
                    void (*on_destruct)(void*);

                    ~extended_mode_t() = default;
                } extended_mode;

                callbacks_data() : normal_mode() {}

                callbacks_data(callbacks_data&& move) noexcept {
                    if (move.is_extended_mode) {
                        is_extended_mode = true;
                        extended_mode.is_coroutine = move.extended_mode.is_coroutine;
                        extended_mode.data = move.extended_mode.data;
                        extended_mode.on_start = move.extended_mode.on_start;
                        extended_mode.on_await = move.extended_mode.on_await;
                        extended_mode.on_cancel = move.extended_mode.on_cancel;
                        extended_mode.on_destruct = move.extended_mode.on_destruct;
                        move.extended_mode.on_destruct = nullptr;
                    } else {
                        is_extended_mode = false;
                        normal_mode.ex_handle = std::move(move.normal_mode.ex_handle);
                        normal_mode.func = std::move(move.normal_mode.func);
                    }
                }

                ~callbacks_data() {
                    if (is_extended_mode) {
                        if (extended_mode.on_destruct)
                            extended_mode.on_destruct(extended_mode.data);
                        extended_mode.data = nullptr;
                        extended_mode.on_start = nullptr;
                        extended_mode.on_await = nullptr;
                        extended_mode.on_cancel = nullptr;
                        extended_mode.on_destruct = nullptr;
                    } else {
                        normal_mode.ex_handle = nullptr;
                        normal_mode.func = nullptr;
                    }
                }

                callbacks_data& operator=(callbacks_data&&) = delete;
            } callbacks;

            task_condition_variable result_notify;
            fast_task::mutex no_race;
            mutex_unify relock_0;
            mutex_unify relock_1;
            mutex_unify relock_2;
            std::chrono::high_resolution_clock::time_point timeout = std::chrono::high_resolution_clock::time_point::min();
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
            void* context = nullptr;
            size_t context_switch_count = 0;
    #if tasks_enable_preemptive_scheduler_preview
            std::chrono::nanoseconds current_available_quantum = std::chrono::nanoseconds(0);
            task_priority priority = task_priority::high;
            size_t interrupt_count = 0;
            size_t interrupt_data = 0; //used only when task requested switch but it has interrupt lock
    #endif
        } data_;

        friend task::data& get_data(std::shared_ptr<task>& task);
        friend task::data& get_data(const std::shared_ptr<task>& task);

        void _extended_end();

    public:
        static size_t max_running_tasks;
        static bool enable_task_naming;

        task(void* data, void (*on_start)(void*), void (*on_await)(void*), void (*on_cancel)(void*), void (*on_destruct)(void*), bool is_coroutine = false);
        task(std::function<void()> func, std::function<void(const std::exception_ptr&)> ex_handle = nullptr, std::chrono::high_resolution_clock::time_point timeout = std::chrono::high_resolution_clock::time_point::min(), task_priority priority = task_priority::high);

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


        static void await_task(const std::shared_ptr<task>& lgr_task, bool make_start = true);
        static void await_multiple(std::list<std::shared_ptr<task>>& tasks, bool pre_started = false, bool release = false);
        static void await_multiple(std::vector<std::shared_ptr<task>>& tasks, bool pre_started = false, bool release = false);
        static void await_multiple(std::shared_ptr<task>* tasks, size_t len, bool pre_started = false, bool release = false);

        static std::shared_ptr<task> callback_dummy(void* dummy_data, void (*on_start)(void*), void (*on_await)(void*), void (*on_cancel)(void*), void (*on_destruct)(void*), bool is_coroutine = false);
        static std::shared_ptr<task> callback_dummy(void* dummy_data, void (*on_await)(void*), void (*on_cancel)(void*), void (*on_destruct)(void*), bool is_coroutine = false);
    };

    namespace scheduler {
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

        template <class Dur_resolution, class Dur_type>
        void schedule(std::shared_ptr<task>&& task, std::chrono::duration<Dur_resolution, Dur_type> duration) {
            schedule_until(std::move(task), std::chrono::high_resolution_clock::now() + duration);
        }

        template <class Dur_resolution, class Dur_type>
        void schedule(const std::shared_ptr<task>& task, std::chrono::duration<Dur_resolution, Dur_type> duration) {
            schedule_until(task, std::chrono::high_resolution_clock::now() + duration);
        }

        void schedule_until(std::shared_ptr<task>&& task, std::chrono::high_resolution_clock::time_point time_point);
        void schedule_until(const std::shared_ptr<task>& task, std::chrono::high_resolution_clock::time_point time_point);
        void start(std::shared_ptr<task>&& lgr_task);
        void start(std::list<std::shared_ptr<task>>& lgr_task);
        void start(std::vector<std::shared_ptr<task>>& lgr_task);
        void start(const std::shared_ptr<task>& lgr_task);

        uint16_t create_bind_only_executor(uint16_t fixed_count, bool allow_implicit_start);
        void assign_bind_only_executor(uint16_t id, uint16_t fixed_count, bool allow_implicit_start);
        void close_bind_only_executor(uint16_t id);

        void create_executor(size_t count = 1);
        size_t total_executors();
        void reduce_executor(size_t count = 1);

        void become_task_executor();
        void await_no_tasks(bool be_executor = false);
        void await_end_tasks(bool be_executor = false);

        void explicit_start_timer();
        void shut_down();

        //DEBUG ONLY, not recommended use in production
        static void clean_up();
        //DEBUG ONLY, not recommended use in production
    }

    namespace this_task {
        size_t get_id() noexcept;
        void yield();
        void sleep_until(std::chrono::high_resolution_clock::time_point time_point);

        template <class Dur_resolution, class Dur_type>
        void sleep_for(std::chrono::duration<Dur_resolution, Dur_type> duration) {
            sleep_until(std::chrono::high_resolution_clock::now() + duration);
        }

        void check_cancellation();
        bool is_cancellation_requested() noexcept;
        void self_cancel();
        bool is_task() noexcept;
        void the_coroutine_ended() noexcept;
    }

    class task_semaphore {
        struct resume_task;
        std::list<resume_task> resume_task;
        fast_task::timed_mutex no_race;
        fast_task::condition_variable_any native_notify;
        size_t allow_threshold = 0;
        size_t max_threshold = 0;

    public:
        task_semaphore();
        ~task_semaphore();

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
        struct resume_task;
        std::list<void*> lock_check;
        std::list<resume_task> resume_task;
        fast_task::timed_mutex no_race;
        fast_task::condition_variable_any native_notify;
        size_t allow_threshold = 0;
        size_t max_threshold = 1;
        bool locked = false;
        void unchecked_unlock();

    public:
        task_limiter();
        ~task_limiter();

        void set_max_threshold(size_t val);
        void lock();
        bool try_lock();
        bool try_lock_for(size_t milliseconds);
        bool try_lock_until(std::chrono::high_resolution_clock::time_point time_point);
        void unlock();
        bool is_locked();
    };

    class task_query {
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

    class deadline_timer {
        struct handle;
        std::shared_ptr<handle> hh;

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
