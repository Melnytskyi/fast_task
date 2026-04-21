#ifndef INCLUDE_TASK_MUTEX
#define INCLUDE_TASK_MUTEX
#include "../threading.hpp"
#include "fwd.hpp"
#include "promise.hpp"
#include <list>

namespace fast_task {
    class FT_API task_mutex {
        friend class task_recursive_mutex;
        friend struct debug::_debug_collect;
        struct FT_API_LOCAL resume_task;
        friend class mutex_unify;

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
        task_mutex_try_lock_awaiter async_try_lock_until(std::chrono::high_resolution_clock::time_point time_point);
        void lock();
        bool try_lock();
        bool try_lock_until(std::chrono::high_resolution_clock::time_point time_point);
        void unlock();
        bool is_locked();
        void lifecycle_lock(std::shared_ptr<task>&& task);
        bool is_own();


        //for coroutines
        bool enter_wait(const std::shared_ptr<task>& task); //returns true if the lock locked, false if the task submitted to wait list
        bool enter_wait_until(const std::shared_ptr<task>& task, std::chrono::high_resolution_clock::time_point);

        template <class Rep, class Period>
        bool try_lock_for(const std::chrono::duration<Rep, Period>& duration) {
            return try_lock_until(std::chrono::high_resolution_clock::now() + duration);
        }

        template <class Rep, class Period>
        task_mutex_try_lock_awaiter async_try_lock_for(const std::chrono::duration<Rep, Period>& duration) {
            return async_try_lock_until(std::chrono::high_resolution_clock::now() + duration);
        }
    };

    class FT_API task_recursive_mutex {
        friend struct debug::_debug_collect;
        friend class mutex_unify;
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
        task_mutex_try_lock_awaiter async_try_lock_until(std::chrono::high_resolution_clock::time_point time_point);

        void lock();
        bool try_lock();
        bool try_lock_until(std::chrono::high_resolution_clock::time_point time_point);
        void unlock();
        bool is_locked();
        void lifecycle_lock(std::shared_ptr<task>&& task);
        bool is_own();


        bool enter_wait(const std::shared_ptr<task>& task);
        bool enter_wait_until(const std::shared_ptr<task>& task, std::chrono::high_resolution_clock::time_point);

        template <class Rep, class Period>
        bool try_lock_for(const std::chrono::duration<Rep, Period>& duration) {
            return try_lock_until(std::chrono::high_resolution_clock::now() + duration);
        }

        template <class Rep, class Period>
        task_mutex_try_lock_awaiter async_try_lock_for(const std::chrono::duration<Rep, Period>& duration) {
            return async_try_lock_until(std::chrono::high_resolution_clock::now() + duration);
        }
    };

    class FT_API task_rw_mutex {
        friend struct debug::_debug_collect;
        struct FT_API_LOCAL resume_task;
        friend class mutex_unify;

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
        task_mutex_try_read_lock_awaiter async_try_read_lock_until(std::chrono::high_resolution_clock::time_point time_point);
        task_mutex_write_lock_awaiter async_write_lock();
        task_mutex_try_write_lock_awaiter async_try_write_lock_until(std::chrono::high_resolution_clock::time_point time_point);

        void read_lock();
        bool try_read_lock();
        bool try_read_lock_until(std::chrono::high_resolution_clock::time_point time_point);
        void read_unlock();
        bool is_read_locked();
        void lifecycle_read_lock(std::shared_ptr<task>&& task);

        void write_lock();
        bool try_write_lock();
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


        bool enter_read_wait(const std::shared_ptr<task>& task);
        bool enter_read_wait_until(const std::shared_ptr<task>& task, std::chrono::high_resolution_clock::time_point);

        bool enter_write_wait(const std::shared_ptr<task>& task);
        bool enter_write_wait_until(const std::shared_ptr<task>& task, std::chrono::high_resolution_clock::time_point);

        template <class Rep, class Period>
        bool try_read_lock_for(const std::chrono::duration<Rep, Period>& duration) {
            return try_read_lock_until(std::chrono::high_resolution_clock::now() + duration);
        }

        template <class Rep, class Period>
        bool try_write_lock_for(const std::chrono::duration<Rep, Period>& duration) {
            return try_write_lock_until(std::chrono::high_resolution_clock::now() + duration);
        }

        template <class Rep, class Period>
        task_mutex_try_read_lock_awaiter async_try_read_lock_for(const std::chrono::duration<Rep, Period>& duration) {
            return async_try_read_lock_until(std::chrono::high_resolution_clock::now() + duration);
        }

        template <class Rep, class Period>
        task_mutex_try_write_lock_awaiter async_try_write_lock_for(const std::chrono::duration<Rep, Period>& duration) {
            return async_try_write_lock_until(std::chrono::high_resolution_clock::now() + duration);
        }
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
}


#endif /* INCLUDE_TASK_MUTEX */
