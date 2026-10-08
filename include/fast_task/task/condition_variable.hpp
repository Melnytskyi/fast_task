// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_INCLUDE_TASK_CONDITION_VARIABLE
#define FAST_TASK_INCLUDE_TASK_CONDITION_VARIABLE
#include "enter_state.hpp"
#include "fwd.hpp"
#include "mutex.hpp"
#include <mutex>

#if __cplusplus >= 202002
    #include "../coroutine/core.hpp"
#endif

namespace fast_task {
    class FT_API condition_variable {
        friend struct debug::_debug_collect;
        std::atomic_uint8_t address;

    public:
        condition_variable();
        ~condition_variable();
        void wait(fast_task::unique_lock<mutex>& lock);
        bool wait_until(fast_task::unique_lock<mutex>& lock, std::chrono::high_resolution_clock::time_point time_point);
        void wait(std::unique_lock<mutex>& lock);
        bool wait_until(std::unique_lock<mutex>& lock, std::chrono::high_resolution_clock::time_point time_point);
        void notify_one();
        void notify_all();
        bool has_waiters();

        void callback(fast_task::unique_lock<mutex>& mut, const task& task);
        void callback(std::unique_lock<mutex>& mut, const task& task);

        bool enter_wait(mutex& mut, const task& task, enter_state&);                                                       //always returns false, requires mut to be locked
        bool enter_wait_until(mutex& mut, const task& task, enter_state&, std::chrono::high_resolution_clock::time_point); //could return true on early timeout, requires mut to be locked

        template <class Rep, class Period>
        bool wait_for(fast_task::unique_lock<mutex>& lock, const std::chrono::duration<Rep, Period>& duration) {
            return wait_until(lock, std::chrono::high_resolution_clock::now() + duration);
        }

        template <class Rep, class Period>
        bool wait_for(std::unique_lock<mutex>& lock, const std::chrono::duration<Rep, Period>& duration) {
            return wait_until(lock, std::chrono::high_resolution_clock::now() + duration);
        }

#if __cplusplus >= 202002
        [[nodiscard]] auto async_wait(fast_task::unique_lock<mutex>& lock) {
            struct awaiter {
                enter_state state;
                fast_task::unique_lock<mutex>& lock;
                mutex* mut;
                condition_variable& cv;

                bool await_ready() noexcept {
                    return false;
                }

                bool await_suspend(const base_coro_handle& h) {
                    return !cv.enter_wait(*mut, h.promise->task_object, state);
                }

                void await_resume() noexcept {
                    lock = {*mut, fast_task::adopt_lock};
                }
            };

            return awaiter{{}, lock, lock.release(), *this};
        }

        [[nodiscard]] auto async_wait_until(fast_task::unique_lock<mutex>& lock, std::chrono::high_resolution_clock::time_point time_point) {
            struct awaiter {
                enter_state state;
                fast_task::unique_lock<mutex>& lock;
                mutex* mut;
                condition_variable& cv;
                std::chrono::high_resolution_clock::time_point time_point;
                fast_task::task task_obj;
                bool successful = false;

                bool await_ready() noexcept {
                    successful = std::chrono::high_resolution_clock::now() >= time_point;
                    return successful;
                }

                bool await_suspend(const base_coro_handle& h) {
                    task_obj = h.promise->task_object;
                    return !cv.enter_wait_until(*mut, h.promise->task_object, state, time_point);
                }

                bool await_resume() noexcept {
                    if (successful)
                        return true;
                    successful = !task_obj.has_wait_timed_out();
                    lock = {*mut, fast_task::adopt_lock};
                    return successful;
                }
            };

            return awaiter{{}, lock, lock.release(), *this, time_point, {}};
        }

        template <class Rep, class Period>
        [[nodiscard]] auto async_wait_for(fast_task::unique_lock<mutex>& lock, const std::chrono::duration<Rep, Period>& duration) {
            return async_wait_until(lock, std::chrono::high_resolution_clock::now() + duration);
        }

        [[nodiscard]] auto async_wait(std::unique_lock<mutex>& lock) {
            struct awaiter {
                enter_state state;
                std::unique_lock<mutex>& lock;
                mutex* mut;
                condition_variable& cv;

                bool await_ready() noexcept {
                    return false;
                }

                bool await_suspend(const base_coro_handle& h) {
                    return !cv.enter_wait(*mut, h.promise->task_object, state);
                }

                void await_resume() noexcept {
                    lock = std::unique_lock<mutex>(*mut, std::adopt_lock);
                }
            };

            return awaiter{{}, lock, lock.release(), *this};
        }

        [[nodiscard]] auto async_wait_until(std::unique_lock<mutex>& lock, std::chrono::high_resolution_clock::time_point time_point) {
            struct awaiter {
                enter_state state;
                std::unique_lock<mutex>& lock;
                mutex* mut;
                condition_variable& cv;
                std::chrono::high_resolution_clock::time_point time_point;
                fast_task::task task_obj;
                bool successful = false;

                bool await_ready() noexcept {
                    successful = std::chrono::high_resolution_clock::now() >= time_point;
                    return successful;
                }

                bool await_suspend(const base_coro_handle& h) {
                    task_obj = h.promise->task_object;
                    return !cv.enter_wait_until(*mut, h.promise->task_object, state, time_point);
                }

                bool await_resume() noexcept {
                    if (successful)
                        return true;
                    successful = !task_obj.has_wait_timed_out();
                    lock = std::unique_lock<mutex>(*mut, std::adopt_lock);
                    return successful;
                }
            };

            return awaiter{{}, lock, lock.release(), *this, time_point, {}};
        }

        template <class Rep, class Period>
        [[nodiscard]] inline auto async_wait_for(condition_variable& cv, std::unique_lock<mutex>& lock, const std::chrono::duration<Rep, Period>& duration) {
            return async_wait_until(cv, lock, std::chrono::high_resolution_clock::now() + duration);
        }
#endif
    };

    class FT_API condition_variable_any {
        mutex _mutex;
        condition_variable _cond;

    public:
        condition_variable_any() = default;

        void notify_one() {
            lock_guard<mutex> lock(_mutex);
            _cond.notify_one();
        }

        void notify_all() {
            lock_guard<mutex> lock(_mutex);
            _cond.notify_all();
        }

        bool has_waiters() {
            return _cond.has_waiters();
        }

        template <class mut>
        void wait(mut& mtx) {
            fast_task::unique_lock<mutex> lock(_mutex);
            relock_guard<mut> relock(mtx);
            _cond.wait(lock);
            lock.unlock();
        }

        template <class mut>
        bool wait_for(mut& mtx, std::chrono::milliseconds ms) {
            return wait_until(mtx, std::chrono::high_resolution_clock::now() + ms);
        }

        template <class mut>
        bool wait_until(mut& mtx, std::chrono::high_resolution_clock::time_point time) {
            fast_task::unique_lock<mutex> lock(_mutex);
            relock_guard<mut> relock(mtx);
            bool ret = _cond.wait_until(lock, time);
            lock.unlock();
            return ret;
        }
    };
}

#endif /* FAST_TASK_INCLUDE_TASK_CONDITION_VARIABLE */
