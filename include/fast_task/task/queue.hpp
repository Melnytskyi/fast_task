// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_INCLUDE_TASK_QUEUE
#define FAST_TASK_INCLUDE_TASK_QUEUE
#include "enter_state.hpp"
#include "task.hpp"


#if __cplusplus >= 202002
    #include "../coroutine/core.hpp"
#endif

namespace fast_task {
    class FT_API queue {
        friend struct debug::_debug_collect;
        struct queue_handle* handle;
        friend void __TaskQueue_add_leave(struct queue_handle* tqh);

    public:
        queue(size_t at_execution_max = 1);
        ~queue();
        void add(task&);
        void add(task&&);
        void enable();
        void disable();
        bool in_queue(const task& task);
        void set_max_at_execution(size_t val);
        size_t get_max_at_execution();
        void wait();
        bool wait_until(std::chrono::high_resolution_clock::time_point time_point);

        template <class Rep, class Period>
        bool wait_for(const std::chrono::duration<Rep, Period>& duration) {
            return wait_until(std::chrono::high_resolution_clock::now() + duration);
        }

        bool enter_wait(const task&, enter_state& task);
        bool enter_wait_until(const task&, enter_state& task, std::chrono::high_resolution_clock::time_point);

#if __cplusplus >= 202002
        [[nodiscard]] auto async_wait() {
            struct awaiter {
                enter_state state;
                queue& q;

                bool await_ready() noexcept {
                    return false;
                }

                bool await_suspend(const base_coro_handle& h) {
                    return !q.enter_wait(h.promise->task_object, state);
                }

                void await_resume() noexcept {}
            };

            return awaiter{{}, *this};
        }

        [[nodiscard]] auto async_wait_until(std::chrono::high_resolution_clock::time_point time_point) {
            struct awaiter {
                enter_state state;
                queue& q;
                std::chrono::high_resolution_clock::time_point time_point;
                fast_task::task task_obj;
                bool successful = false;

                bool await_ready() noexcept {
                    successful = std::chrono::high_resolution_clock::now() >= time_point;
                    return successful;
                }

                bool await_suspend(const base_coro_handle& h) {
                    task_obj = h.promise->task_object;
                    return !q.enter_wait_until(h.promise->task_object, state, time_point);
                }

                bool await_resume() noexcept {
                    if (successful)
                        return true;
                    successful = !task_obj.has_wait_timed_out();
                    return successful;
                }
            };

            return awaiter{{}, *this, time_point, {}};
        }

        template <class Rep, class Period>
        [[nodiscard]] auto async_wait_for(const std::chrono::duration<Rep, Period>& duration) {
            return async_wait_until(std::chrono::high_resolution_clock::now() + duration);
        }
#endif
    };
}


#endif /* FAST_TASK_INCLUDE_TASK_QUEUE */
