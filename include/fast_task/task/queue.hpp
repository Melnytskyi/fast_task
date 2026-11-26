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
        queue(const queue&) = delete;
        queue& operator=(const queue&) = delete;
        queue(queue&&) = delete;
        queue& operator=(queue&&) = delete;
        void add(task&);
        void add(task&&);
        void enable();
        void disable();
        bool in_queue(const task& task);
        void set_max_at_execution(size_t val);
        size_t get_max_at_execution();
        void wait();
        bool wait_until(fast_task::time_point time_point);

        template <class Rep, class Period>
        bool wait_for(const std::chrono::duration<Rep, Period>& duration) {
            return wait_until(fast_task::deadline_after(duration));
        }

        bool enter_wait(const task&, enter_state& task);
        bool enter_wait_until(const task&, enter_state& task, fast_task::time_point);

#if __cplusplus >= 202002
    private:
        struct wait_awaiter {
            enter_state state;
            queue& q;

            bool await_ready() noexcept {
                return false;
            }

            template <std::derived_from<task_promise_base> Promise>
            bool await_suspend(std::coroutine_handle<Promise> h) {
                return !q.enter_wait(h.promise().task_object, state);
            }

            void await_resume() noexcept {}
        };

        struct wait_until_awaiter {
            enter_state state;
            queue& q;
            fast_task::time_point time_point;
            fast_task::task task_obj;
            bool successful = false;
            bool timed_out_early = false;

            bool await_ready() noexcept {
                if (fast_task::is_no_deadline(time_point) || fast_task::clock::now() >= time_point) {
                    timed_out_early = true;
                    return true;
                }
                return false;
            }

            template <std::derived_from<task_promise_base> Promise>
            bool await_suspend(std::coroutine_handle<Promise> h) {
                task_obj = h.promise().task_object;
                if (q.enter_wait_until(task_obj, state, time_point)) {
                    successful = !task_obj.has_wait_timed_out();
                    return false;
                }
                return true;
            }

            bool await_resume() noexcept {
                if (timed_out_early)
                    return false;
                if (successful)
                    return true;
                successful = !task_obj.has_wait_timed_out();
                return successful;
            }
        };

    public:
        [[nodiscard]] auto async_wait() {
            return wait_awaiter{{}, *this};
        }

        [[nodiscard]] auto async_wait_until(fast_task::time_point time_point) {
            return wait_until_awaiter{{}, *this, time_point, {}};
        }

        template <class Rep, class Period>
        [[nodiscard]] auto async_wait_for(const std::chrono::duration<Rep, Period>& duration) {
            return async_wait_until(fast_task::clock::now() + duration);
        }
#endif
    };
}


#endif /* FAST_TASK_INCLUDE_TASK_QUEUE */
