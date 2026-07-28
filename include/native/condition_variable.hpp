// Copyright Danyil Melnytskyi 2022-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_INCLUDE_NATIVE_CONDITION_VARIABLE
#define FAST_TASK_INCLUDE_NATIVE_CONDITION_VARIABLE
#include "../shared.hpp"
#include "../shared/primitives.hpp"
#include "mutex.hpp"
#include <chrono>

namespace fast_task::native {
    namespace detail{
        template <class M>
        struct full_state_relock_guard {
            M& ref;

            full_state_relock_guard(M& ref)
                : ref(ref) {
                ref.unlock();
            }

            ~full_state_relock_guard() {
                ref.lock();
            }
        };

        template <>
        struct full_state_relock_guard<recursive_mutex> {
            recursive_mutex& ref;
            recursive_mutex::relock_state state;

            full_state_relock_guard(recursive_mutex& ref)
                : ref(ref) {
                state = ref.relock_begin();
                ref.unlock();
            }

            ~full_state_relock_guard() {
                ref.lock();
                ref.relock_end(state);
            }
        };

        template <>
        struct full_state_relock_guard<::fast_task::unique_lock<recursive_mutex>> {
            ::fast_task::unique_lock<recursive_mutex>& ref;
            recursive_mutex::relock_state state;

            full_state_relock_guard(::fast_task::unique_lock<recursive_mutex>& ref)
                : ref(ref) {
                state = ref.mutex()->relock_begin();
                ref.unlock();
            }

            ~full_state_relock_guard() {
                ref.lock();
                ref.mutex()->relock_end(state);
            }
        };
    }

    class FT_API condition_variable {
#ifdef _WIN32
        void* _cond;
#else
        pthread_cond_t* _cond;
#endif
    public:
        condition_variable();
        condition_variable(const condition_variable& other) = delete;
        condition_variable(condition_variable&& other) = delete;
        condition_variable& operator=(const condition_variable& other) = delete;
        condition_variable& operator=(condition_variable&& other) = delete;
        ~condition_variable() noexcept;
        void notify_one();
        void notify_all();
        void wait(mutex& mtx);
        cv_status wait_for(mutex& mtx, std::chrono::milliseconds ms);
        cv_status wait_until(mutex& mtx, std::chrono::high_resolution_clock::time_point time);

        void wait(recursive_mutex& mtx);
        cv_status wait_for(recursive_mutex& mtx, std::chrono::milliseconds ms);
        cv_status wait_until(recursive_mutex& mtx, std::chrono::high_resolution_clock::time_point time);

        inline void wait(::fast_task::unique_lock<mutex>& mtx) {
            wait(*mtx.mutex());
        }

        inline cv_status wait_for(::fast_task::unique_lock<mutex>& mtx, std::chrono::milliseconds ms) {
            return wait_until(*mtx.mutex(), std::chrono::high_resolution_clock::now() + ms);
        }

        inline cv_status wait_until(::fast_task::unique_lock<mutex>& mtx, std::chrono::high_resolution_clock::time_point time) {
            return wait_until(*mtx.mutex(), time);
        }

        inline void wait(::fast_task::unique_lock<recursive_mutex>& mtx) {
            wait(*mtx.mutex());
        }

        inline cv_status wait_for(::fast_task::unique_lock<recursive_mutex>& mtx, std::chrono::milliseconds ms) {
            return wait_until(*mtx.mutex(), std::chrono::high_resolution_clock::now() + ms);
        }

        inline cv_status wait_until(::fast_task::unique_lock<recursive_mutex>& mtx, std::chrono::high_resolution_clock::time_point time) {
            return wait_until(*mtx.mutex(), time);
        }
    };

    class FT_API condition_variable_any {
        condition_variable _cond;
        mutex _mutex;

    public:
        condition_variable_any() = default;
        void notify_one();
        void notify_all();

        template <class mut>
        void wait(mut& mtx) {
            fast_task::unique_lock<mutex> lock(_mutex);
            detail::full_state_relock_guard<mut> relock(mtx);
            _cond.wait(_mutex);
            lock.unlock();
        }

        template <class mut>
        cv_status wait_for(mut& mtx, std::chrono::milliseconds ms) {
            return wait_until(mtx, std::chrono::high_resolution_clock::now() + ms);
        }

        template <class mut>
        cv_status wait_until(mut& mtx, std::chrono::high_resolution_clock::time_point time) {
            fast_task::unique_lock<mutex> lock(_mutex);
            detail::full_state_relock_guard<mut> relock(mtx);
            cv_status ret = _cond.wait_until(_mutex, time);
            lock.unlock();
            return ret;
        }

        void unsafe_notify_one(); //used in scheduler
        void unsafe_notify_all();
    };
}

#endif /* FAST_TASK_INCLUDE_NATIVE_CONDITION_VARIABLE */
