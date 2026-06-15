// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef INCLUDE_TASK_TASK
#define INCLUDE_TASK_TASK

#include "../shared.hpp"
#include "enter_state.hpp"
#include <atomic>

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

    //TODO UPDATE this doc
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

    struct alignas(64) FT_API_LOCAL task_object;

    struct FT_API task_vtable {
        void (*on_await)(void*) = nullptr;
        void (*on_cancel)(void*) = nullptr;
        void (*on_start)(void*);
        void (*on_exception)(void*, const std::exception_ptr&) = nullptr;
        void (*on_destruct)(void*) = nullptr;
        bool heap_allocated = false;
    };

    class FT_API task {
        task_object* obj;

        friend task_object& get_data(task* task);
        friend task_object& get_data(const task& task);
        friend struct mutex_unify_relock_access;

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

        void* init_inplace(task_vtable* vtable, bool is_restartable, bool is_on_scheduler);
        void init_pointer(void* heap_state, task_vtable* vtable, bool is_restartable, bool is_on_scheduler);
        void* user_data() const noexcept;
        void end_of_life_notify() const;


    public:
        static size_t max_running_tasks;
        static bool enable_task_naming;
        static constexpr size_t sbo_size = 48; // must match task_object::sbo_buffer size

        task(void* data, task_vtable* vtable, bool is_restartable = false, bool is_on_scheduler = false);

        task() noexcept;
        task(std::nullptr_t) noexcept;
        task(task&& mov) noexcept;
        task(const task& copy) noexcept;
        ~task();
        task& operator=(task&&) noexcept;
        task& operator=(const task&) noexcept;

        inline operator bool() const noexcept {
            return obj;
        }

        inline bool operator==(const task& tsk) const noexcept {
            return obj == tsk.obj;
        }

        inline bool operator==(std::nullptr_t) const noexcept {
            return obj == nullptr;
        }

        void reset() noexcept;
        task_object* release() noexcept;
        static task adopt(task_object* raw) noexcept;


        void set_auto_bind_worker(bool enable = true) const noexcept;
        void set_worker_id(uint16_t id) const noexcept;
        void set_priority(task_priority) const noexcept;
        void set_timeout(std::chrono::high_resolution_clock::time_point timeout) const noexcept;
        task_priority get_priority() const noexcept;
        size_t get_counter_interrupt() const noexcept;
        size_t get_counter_context_switch() const noexcept;
        std::chrono::high_resolution_clock::time_point get_timeout() const noexcept;
        bool has_wait_timed_out() const noexcept; // for timed enter_wait_until, allows to check if the operation timed out. Also resets the flag(locks)
        bool is_cancellation_requested() const noexcept;
        bool is_ended() const noexcept;
        void await_task() const;
        bool await_task_until(std::chrono::high_resolution_clock::time_point) const;
        void callback(const task&) const;
        void notify_cancel() const;
        void await_notify_cancel() const;
        void reset_awake() const; //resets the time_end_flag and awaked flags
        void start() const;
        size_t get_id() const noexcept;

        template <class FN>
        void access_dummy(FN&& fn) const {
            fn(user_data());
        };

        template <class FN>
        void end_dummy(FN&& fn) const {
            fn(user_data());
            end_of_life_notify();
        };

        bool enter_wait(const task&, enter_state&) const;
        bool enter_wait_until(const task&, enter_state&, std::chrono::high_resolution_clock::time_point) const;
        bool enter_cancel(const task&, enter_state&) const;

        template <typename Func, typename ExHandle = std::nullptr_t>
        static task run(Func&& func, ExHandle&& ex_handle = nullptr, std::chrono::high_resolution_clock::time_point timeout = std::chrono::high_resolution_clock::time_point::min(), task_priority priority = task_priority::high, bool is_on_scheduler = false) {
            auto r = create(std::forward<Func>(func), std::forward<ExHandle>(ex_handle), timeout, priority, is_on_scheduler);
            r.start();
            return r;
        }

        template <typename Func, typename ExHandle = std::nullptr_t>
        static task create(Func&& func, ExHandle&& ex_handle = nullptr, std::chrono::high_resolution_clock::time_point timeout = std::chrono::high_resolution_clock::time_point::min(), task_priority priority = task_priority::high, bool is_on_scheduler = false) {
            task res;
            if constexpr (std::is_same_v<std::decay_t<Func>, std::nullptr_t>) {
                static task_vtable empty_vtable{
                    nullptr,
                    nullptr,
                    nullptr,
                    nullptr,
                    nullptr,
                    false
                };
                res.init_pointer(nullptr, &empty_vtable, false, is_on_scheduler);
            } else {
                using State = task_state<std::decay_t<Func>, std::decay_t<ExHandle>>;
                constexpr bool use_sbo = sizeof(State) <= sbo_size &&
                                         alignof(State) <= alignof(std::max_align_t);

                static task_vtable vtable{
                    nullptr,
                    nullptr,
                    start_thunk<State>,
                    std::is_same_v<std::decay_t<ExHandle>, std::nullptr_t> ? nullptr : exception_thunk<State>,
                    use_sbo ? sbo_destruct_thunk<State> : heap_destruct_thunk<State>,
                    false
                };

                if constexpr (use_sbo) {
                    void* storage = res.init_inplace(&vtable, false, is_on_scheduler);
                    new (storage) State{std::forward<Func>(func), std::forward<ExHandle>(ex_handle)};
                } else {
                    State* ptr = new State{std::forward<Func>(func), std::forward<ExHandle>(ex_handle)};
                    res.init_pointer(ptr, &vtable, false, is_on_scheduler);
                }

                res.set_timeout(timeout);
                res.set_priority(priority);
            }
            return res;
        }

        static void await_task(const task& t, bool make_start = true);

        template <class Container>
        static void await_multiple(const Container& cont, bool make_start = true) {
            if (make_start)
                for (auto& it : cont)
                    it.start();
            for (auto& it : cont)
                it.await_task();
        }

        static task callback_dummy(void* dummy_data, void (*on_start)(void*), void (*on_await)(void*), void (*on_cancel)(void*), void (*on_destruct)(void*), bool is_restartable = false, bool is_on_scheduler = false);
        static task callback_dummy(void* dummy_data, void (*on_await)(void*), void (*on_cancel)(void*), void (*on_destruct)(void*), bool is_restartable = false, bool is_on_scheduler = false);

        template <class Dur_resolution, class Dur_type>
        bool await_task_for(std::chrono::duration<Dur_resolution, Dur_type> duration) const {
            return await_task_until(std::chrono::high_resolution_clock::now() + duration);
        }
    };
}
#endif /* INCLUDE_TASK_TASK */
