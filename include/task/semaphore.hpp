#ifndef INCLUDE_TASK_SEMAPHORE
#define INCLUDE_TASK_SEMAPHORE

#include "fwd.hpp"
#include "../threading.hpp"
#include <list>

namespace fast_task {
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
        task_try_lock_awaiter async_try_lock_until(std::chrono::high_resolution_clock::time_point time_point);

        void set_max_threshold(size_t val);
        void lock();
        bool try_lock();
        bool try_lock_until(std::chrono::high_resolution_clock::time_point time_point);
        void release();
        void release_all();
        bool is_locked();

        bool enter_wait(const std::shared_ptr<task>& task);
        bool enter_wait_until(const std::shared_ptr<task>& task, std::chrono::high_resolution_clock::time_point);

        template <class Rep, class Period>
        bool try_lock_for(const std::chrono::duration<Rep, Period>& duration) {
            return try_lock_until(std::chrono::high_resolution_clock::now() + duration);
        }

        template <class Rep, class Period>
        task_try_lock_awaiter async_try_lock_for(const std::chrono::duration<Rep, Period>& duration) {
            return async_try_lock_until(std::chrono::high_resolution_clock::now() + duration);
        }
    };

    //same as task_semaphore but with checks
    class FT_API task_limiter {
        friend struct debug::_debug_collect;
        struct FT_API_LOCAL resume_task;
        friend class mutex_unify;

        struct private_values {
            std::list<void*> lock_check;
            std::list<resume_task> resume_task;
            fast_task::spin_lock no_race;
            fast_task::condition_variable_any native_notify;
            size_t allow_threshold = 1;
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
        task_try_lock_awaiter async_try_lock_until(std::chrono::high_resolution_clock::time_point time_point);

        void set_max_threshold(size_t val);
        void lock();
        bool try_lock();
        bool try_lock_until(std::chrono::high_resolution_clock::time_point time_point);
        void unlock();
        bool is_locked();

        bool enter_wait(const std::shared_ptr<task>& task);
        bool enter_wait_until(const std::shared_ptr<task>& task, std::chrono::high_resolution_clock::time_point);

        template <class Rep, class Period>
        bool try_lock_for(const std::chrono::duration<Rep, Period>& duration) {
            return try_lock_until(std::chrono::high_resolution_clock::now() + duration);
        }

        template <class Rep, class Period>
        task_try_lock_awaiter async_try_lock_for(const std::chrono::duration<Rep, Period>& duration) {
            return async_try_lock_until(std::chrono::high_resolution_clock::now() + duration);
        }
    };
}

#endif /* INCLUDE_TASK_SEMAPHORE */
