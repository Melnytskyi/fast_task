// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_INCLUDE_TASK_TASK
#define FAST_TASK_INCLUDE_TASK_TASK

#include "../clock.hpp"
#include "../shared.hpp"
#include "enter_state.hpp"
#include <atomic>
#include <chrono>
#include <exception>
#include <memory>
#include <new>

namespace fast_task {
    enum class task_priority : uint8_t {
        background,
        low,
        lower,
        normal,
        higher,
        high,
        semi_realtime,
    };
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
        struct sbo_guarded_state {
            union {
                State state;
            };
            bool constructed = false;

            sbo_guarded_state() noexcept {}
            ~sbo_guarded_state() {
                if (constructed)
                    state.~State();
            }

            template <typename Func, typename ExHandle>
            void emplace(Func&& func, ExHandle&& ex_handle) {
                new (&state) State{std::forward<Func>(func), std::forward<ExHandle>(ex_handle)};
                constructed = true;
            }
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
        static void guarded_start_thunk(void* ptr) {
            auto& st = static_cast<sbo_guarded_state<State>*>(ptr)->state;
            if constexpr (!std::is_same_v<decltype(State::func), std::nullptr_t>) {
                st.func();
            }
        }

        template <typename State>
        static void guarded_exception_thunk(void* ptr, const std::exception_ptr& ex) {
            auto& st = static_cast<sbo_guarded_state<State>*>(ptr)->state;
            if constexpr (!std::is_same_v<decltype(State::ex_handle), std::nullptr_t>) {
                st.ex_handle(ex);
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
        static std::atomic<size_t> max_running_tasks;
        static bool enable_task_naming;
        static constexpr size_t sbo_size = 64; // must match task_object::sbo_buffer size

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


        void set_priority(task_priority) const noexcept;
        void set_timeout(fast_task::time_point timeout) const noexcept;
        task_priority get_priority() const noexcept;
        size_t get_counter_interrupt() const noexcept;
        size_t get_counter_context_switch() const noexcept;
        fast_task::time_point get_timeout() const noexcept;
        bool has_wait_timed_out() const noexcept; // for timed enter_wait_until, allows to check if the operation timed out. Also resets the flag(locks)
        bool is_cancellation_requested() const noexcept;
        bool is_ended() const noexcept;
        void await_task() const;
        bool await_task_until(fast_task::time_point) const;
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
        bool enter_wait_until(const task&, enter_state&, fast_task::time_point) const;
        bool enter_cancel(const task&, enter_state&) const;

        template <typename Func, typename ExHandle = std::nullptr_t>
        static task run(Func&& func, ExHandle&& ex_handle = nullptr, fast_task::time_point timeout = fast_task::time_point::min(), task_priority priority = task_priority::high, bool is_on_scheduler = false) {
            auto r = create(std::forward<Func>(func), std::forward<ExHandle>(ex_handle), timeout, priority, is_on_scheduler);
            r.start();
            return r;
        }

        template <typename Func, typename ExHandle = std::nullptr_t>
        static task create(Func&& func, ExHandle&& ex_handle = nullptr, fast_task::time_point timeout = fast_task::time_point::min(), task_priority priority = task_priority::high, bool is_on_scheduler = false) {
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
                constexpr bool nothrow_init =
                    std::is_nothrow_constructible_v<std::decay_t<Func>, Func&&> &&
                    std::is_nothrow_constructible_v<std::decay_t<ExHandle>, ExHandle&&>;
                using SboState = std::conditional_t<nothrow_init, State, sbo_guarded_state<State>>;
                constexpr bool use_sbo = sizeof(SboState) <= sbo_size &&
                                         alignof(SboState) <= alignof(std::max_align_t);

                if constexpr (use_sbo) {
                    if constexpr (nothrow_init) {
                        static task_vtable vtable{
                            nullptr,
                            nullptr,
                            start_thunk<State>,
                            std::is_same_v<std::decay_t<ExHandle>, std::nullptr_t> ? nullptr : exception_thunk<State>,
                            sbo_destruct_thunk<State>,
                            false
                        };
                        void* storage = res.init_inplace(&vtable, false, is_on_scheduler);
                        new (storage) State{std::forward<Func>(func), std::forward<ExHandle>(ex_handle)};
                    } else {
                        static task_vtable vtable{
                            nullptr,
                            nullptr,
                            guarded_start_thunk<State>,
                            std::is_same_v<std::decay_t<ExHandle>, std::nullptr_t> ? nullptr : guarded_exception_thunk<State>,
                            sbo_destruct_thunk<SboState>,
                            false
                        };
                        void* storage = res.init_inplace(&vtable, false, is_on_scheduler);
                        auto* guard = new (storage) SboState();
                        guard->emplace(std::forward<Func>(func), std::forward<ExHandle>(ex_handle));
                    }
                } else {
                    static task_vtable vtable{
                        nullptr,
                        nullptr,
                        start_thunk<State>,
                        std::is_same_v<std::decay_t<ExHandle>, std::nullptr_t> ? nullptr : exception_thunk<State>,
                        heap_destruct_thunk<State>,
                        false
                    };
                    std::unique_ptr<State> ptr(new State{std::forward<Func>(func), std::forward<ExHandle>(ex_handle)});
                    res.init_pointer(ptr.get(), &vtable, false, is_on_scheduler);
                    ptr.release();
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
            return await_task_until(fast_task::clock::now() + duration);
        }
    };
}
#endif /* FAST_TASK_INCLUDE_TASK_TASK */
