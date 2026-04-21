#ifndef INCLUDE_TASK_CONDITION_VARIABLE
#define INCLUDE_TASK_CONDITION_VARIABLE
#include "mutex_unify.hpp"
#include "fwd.hpp"
#include <list>
#include <mutex>
#include "promise.hpp"

namespace fast_task {
    class FT_API task_condition_variable {
        friend struct debug::_debug_collect;
        struct FT_API_LOCAL resume_task;

        struct FT_API_LOCAL private_values {
            std::list<resume_task> resume_task;
            fast_task::mutex no_race;
        } values;

        struct FT_API [[nodiscard]] task_wait_awaiter {
            task_condition_variable& cv;
            base_coro_handle handle;

            bool await_ready() noexcept;
            bool await_suspend(base_coro_handle h);
            void await_resume() noexcept;
        };

        struct FT_API [[nodiscard]] task_wait_until_awaiter {
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
        task_wait_until_awaiter async_wait_until(fast_task::unique_lock<mutex_unify>& lock, std::chrono::high_resolution_clock::time_point time_point);

        void wait(fast_task::unique_lock<mutex_unify>& lock);
        bool wait_until(fast_task::unique_lock<mutex_unify>& lock, std::chrono::high_resolution_clock::time_point time_point);
        void wait(std::unique_lock<mutex_unify>& lock);
        bool wait_until(std::unique_lock<mutex_unify>& lock, std::chrono::high_resolution_clock::time_point time_point);
        void notify_one();
        void notify_all();
        bool has_waiters();
        void callback(fast_task::unique_lock<mutex_unify>& mut, const std::shared_ptr<task>& task);
        void callback(std::unique_lock<mutex_unify>& mut, const std::shared_ptr<task>& task);

        bool enter_wait(const std::shared_ptr<task>& task);                                                       //always returns false
        bool enter_wait_until(const std::shared_ptr<task>& task, std::chrono::high_resolution_clock::time_point); //always returns false

        template <class Rep, class Period>
        task_wait_until_awaiter async_wait_for(fast_task::unique_lock<mutex_unify>& lock, const std::chrono::duration<Rep, Period>& duration) {
            return async_wait_until(lock, std::chrono::high_resolution_clock::now() + duration);
        }

        template <class Rep, class Period>
        bool wait_for(fast_task::unique_lock<mutex_unify>& lock, const std::chrono::duration<Rep, Period>& duration) {
            return wait_until(lock, std::chrono::high_resolution_clock::now() + duration);
        }

        template <class Rep, class Period>
        bool wait_for(std::unique_lock<mutex_unify>& lock, const std::chrono::duration<Rep, Period>& duration) {
            return wait_until(lock, std::chrono::high_resolution_clock::now() + duration);
        }
    };
}

#endif /* INCLUDE_TASK_CONDITION_VARIABLE */
