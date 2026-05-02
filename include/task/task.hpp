// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef INCLUDE_TASK_TASK
#define INCLUDE_TASK_TASK

#include "../exceptions.hpp"
#include "condition_variable.hpp"
#include "mutex_unify.hpp"
#include <functional>
#include <list>
#include <vector>

namespace fast_task {
    enum class task_priority {
        background,
        low,
        lower,
        normal,
        higher,
        high,
        semi_realtime,
    };

    //The task class internally uses callbacks like on_start, on_exception, on_await and on_cancel
    //  the on_await and on_cancel executed on calling thread and could be used for example, to wrap the sockets in the task interface
    //  the on_start executed on its own stack like normal one and allows using all synchronization primitives
    //    when is_restartable is set the task could be restarted, to disable use this_task::the_coroutine_ended
    //    but when the is_on_scheduler variable is set, the task would be executed on scheduler stack which would reduce the memory usage
    //      and the task should be aware, the scheduler could not interrupt itself, so the task effectively becomes cooperative only,
    //      the task on scheduler should never consume too much time to prevent the task overloading the whole scheduler system
    //      and the task should use enter_* methods for synchronization, the regular operations would throw exception
    //      for c++20 coroutines use the functions from coroutines/*.hpp headers, if you want to implement own coroutines use these as an example of how to use the enter_* methods
    //      this flag allows to create stackless coroutines like in c++ or other language
    //  the task has is_sbo optimization to reduce the memory consumption on the simple tasks whose have only on_start and on_exception callbacks
    class FT_API task {
        void awaitEnd(fast_task::unique_lock<mutex_unify>& l);
        struct FT_API_LOCAL execution_data;

        struct FT_API_LOCAL data {
            struct FT_API_LOCAL callbacks_data {
                bool is_restartable : 1 = false;
                bool is_on_scheduler : 1 = false;
                bool is_sbo : 1 = false;

                union {
                    struct {
                        void* data;
                        void (*on_await)(void*);
                        void (*on_cancel)(void*);
                    } dat;

                    alignas(std::max_align_t) std::byte sbo_buffer[sizeof(void*) * 3];
                } buf;

                void (*on_start)(void*) = nullptr;
                void (*on_exception)(void*, const std::exception_ptr&) = nullptr;
                void (*on_destruct)(void*) = nullptr;
                void (*on_move)(void*, void*) noexcept = nullptr;

                void (*on_start_override)(callbacks_data&) = nullptr; //used internally, never deallocated
                void* on_start_override_data = nullptr;               //used internally, never deallocated


                callbacks_data();

                callbacks_data(callbacks_data&& move) noexcept;
                ~callbacks_data();

                callbacks_data& operator=(callbacks_data&&) = delete;

                void make_await() {
                    if (!is_sbo)
                        if (buf.dat.on_await)
                            buf.dat.on_await(buf.dat.data);
                }

                void make_cancel() {
                    if (!is_sbo)
                        if (buf.dat.on_cancel)
                            buf.dat.on_cancel(buf.dat.data);
                }

                void* get_data() {
                    return is_sbo ? (void**)&buf.sbo_buffer : buf.dat.data;
                }
            } callbacks;

            task_condition_variable result_notify;
            mutable fast_task::spin_lock no_race;
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

        template <typename Func, typename ExHandle = std::nullptr_t>
        struct task_state {
            Func func;
            ExHandle ex_handle;
        };

        template <typename State>
        static void start_thunk(void* ptr) {
            if constexpr (!std::is_same_v<decltype(State::func), std::nullptr_t>) {
                static_cast<State*>(ptr)->func();
            }
        }

        template <typename State>
        static void exception_thunk(void* ptr, const std::exception_ptr& ex) {
            if constexpr (!std::is_same_v<decltype(State::ex_handle), std::nullptr_t>) {
                static_cast<State*>(ptr)->ex_handle(ex);
            }
        }

        template <typename State>
        static void sbo_destruct_thunk(void* ptr) {
            static_cast<State*>(ptr)->~State();
        }

        template <typename State>
        static void heap_destruct_thunk(void* ptr) {
            delete static_cast<State*>(ptr);
        }

    public:
        static size_t max_running_tasks;
        static bool enable_task_naming;

        task(void* data, void (*on_start)(void*), void (*on_await)(void*), void (*on_cancel)(void*), void (*on_destruct)(void*), bool is_restartable = false, bool is_on_scheduler = false);

        template <typename Func, typename ExHandle = std::nullptr_t>
        task(Func&& func, ExHandle&& ex_handle = nullptr, std::chrono::high_resolution_clock::time_point timeout = std::chrono::high_resolution_clock::time_point::min(), task_priority priority = task_priority::high, bool is_on_scheduler = false) {
            if constexpr (std::is_same_v<Func, std::nullptr_t>) {
                data_.callbacks.on_start = nullptr;
                data_.callbacks.on_move = nullptr;
                data_.callbacks.on_destruct = nullptr;
                data_.callbacks.on_exception = nullptr;
            } else {
                using State = task_state<std::decay_t<Func>, std::decay_t<ExHandle>>;
                constexpr bool use_sbo = sizeof(State) <= sizeof(data_.callbacks.buf.sbo_buffer) &&
                                         alignof(State) <= alignof(std::max_align_t);

                data_.callbacks.is_sbo = use_sbo;
                data_.callbacks.is_restartable = false;
                data_.callbacks.is_on_scheduler = is_on_scheduler;
                data_.callbacks.on_move = [](void* dst, void* src) noexcept {
                    State* state_src = static_cast<State*>(src);
                    new (dst) State{std::move(state_src->func), std::move(state_src->ex_handle)};
                    state_src->~State();
                };

                if constexpr (use_sbo) {
                    new (data_.callbacks.buf.sbo_buffer) State{std::forward<Func>(func), std::forward<ExHandle>(ex_handle)};
                    data_.callbacks.on_destruct = sbo_destruct_thunk<State>;
                } else {
                    State* ptr = new State{std::forward<Func>(func), std::forward<ExHandle>(ex_handle)};
                    data_.callbacks.buf.dat.data = ptr;
                    data_.callbacks.on_destruct = heap_destruct_thunk<State>;
                }


                data_.callbacks.on_start = start_thunk<State>;
                if constexpr (!std::is_same_v<std::decay_t<ExHandle>, std::nullptr_t>) {
                    data_.callbacks.on_exception = exception_thunk<State>;
                }

                this->data_.timeout = timeout.time_since_epoch().count();
                set_priority(priority);
            }
        }

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
        bool has_wait_timed_out() const noexcept; // for timed enter_wait_until, allows to check if the operation timed out. Also resets the flag(locks)
        bool is_cancellation_requested() const noexcept;
        bool is_ended() const noexcept;
        void await_task();
        void callback(const std::shared_ptr<task>& task);
        void notify_cancel();
        void await_notify_cancel();
        void reset_awake(); //resets the time_end_flag and awaked flags

        template <class FN>
        void access_dummy(FN&& fn) {
            fn(data_.callbacks.get_data());
        };

        template <class FN>
        void end_dummy(FN&& fn) {
            fn(data_.callbacks.get_data());
            fast_task::lock_guard l(data_.no_race);
            data_.end_of_life = true;
            data_.result_notify.notify_all();
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
}
#endif /* INCLUDE_TASK_TASK */
