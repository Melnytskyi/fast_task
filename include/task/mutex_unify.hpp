// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_INCLUDE_TASK_MUTEX_UNIFY
#define FAST_TASK_INCLUDE_TASK_MUTEX_UNIFY

#include "../native/mutex.hpp"
#include "../native/spin_lock.hpp"
#include "enter_state.hpp"
#include "fwd.hpp"
#include <cstdint>
#include <initializer_list>
#include <mutex>
#include <vector>

namespace fast_task {

    class FT_API mutex_unify {
        friend class multiply_mutex;
        friend struct mutex_unify_relock_access;
        enum class mutex_unify_type : uint8_t {
            nothing,
            nmut,
            ntimed,
            nrec,
            rwmut_r,
            rwmut_w,
            std_nmut,
            std_ntimed,
            std_nrec,
            umut,
            urmut,
            urwmut_r,
            urwmut_w,
            mmut,
            uspin,
            sem,
            lim,
            task_obj // internal: routes to task_object::lock()/unlock(); pointer kept in the union's raw slot
        };

        union FT_API_LOCAL {
            std::mutex* std_nmut = nullptr;
            std::timed_mutex* std_ntimed;
            std::recursive_mutex* std_nrec;
            fast_task::native::mutex* nmut;
            fast_task::native::timed_mutex* ntimed;
            fast_task::native::rw_mutex* rwmut;
            fast_task::native::recursive_mutex* nrec;
            fast_task::native::spin_lock* uspin;
            mutex* umut;
            rw_mutex* urwmut;
            recursive_mutex* urmut;
            class multiply_mutex* mmut;
            semaphore* sem;
            limiter* lim;
        };

        mutex_unify_type type;

        void donate_ownership(fast_task::task* target_owner); //internal function for multiply_mutex::enter_wait*

    public:
        mutex_unify();
        mutex_unify(const mutex_unify& mut);
        mutex_unify(std::mutex& smut);
        mutex_unify(std::timed_mutex& smut);
        mutex_unify(std::recursive_mutex& smut);
        mutex_unify(fast_task::native::mutex& smut);
        mutex_unify(fast_task::native::timed_mutex& smut);
        mutex_unify(fast_task::native::rw_mutex& smut, bool write_read = true);
        mutex_unify(fast_task::native::recursive_mutex& smut);
        mutex_unify(fast_task::native::spin_lock& smut);
        mutex_unify(mutex& smut);
        mutex_unify(rw_mutex& smut, bool write_read = true);
        mutex_unify(recursive_mutex& smut);
        mutex_unify(multiply_mutex& mmut);
        mutex_unify(semaphore& sem);
        mutex_unify(limiter& lim);
        mutex_unify(std::nullptr_t);

        ~mutex_unify();

        mutex_unify& operator=(const mutex_unify&);
        mutex_unify& operator=(std::mutex&);
        mutex_unify& operator=(std::timed_mutex&);
        mutex_unify& operator=(std::recursive_mutex&);
        mutex_unify& operator=(fast_task::native::mutex&);
        mutex_unify& operator=(fast_task::native::timed_mutex&);
        mutex_unify& operator=(fast_task::native::recursive_mutex&);
        mutex_unify& operator=(fast_task::native::spin_lock&);
        mutex_unify& operator=(mutex&);
        mutex_unify& operator=(recursive_mutex&);
        mutex_unify& operator=(class multiply_mutex&);
        mutex_unify& operator=(semaphore&);
        mutex_unify& operator=(limiter&);
        mutex_unify& operator=(std::nullptr_t);

        bool operator==(const mutex_unify&);
        bool operator==(std::mutex&);
        bool operator==(std::timed_mutex&);
        bool operator==(std::recursive_mutex&);
        bool operator==(fast_task::native::mutex&);
        bool operator==(fast_task::native::timed_mutex&);
        bool operator==(fast_task::native::rw_mutex&);
        bool operator==(fast_task::native::recursive_mutex&);
        bool operator==(fast_task::native::spin_lock&);
        bool operator==(mutex&);
        bool operator==(rw_mutex&);
        bool operator==(recursive_mutex&);
        bool operator==(class multiply_mutex&);
        bool operator==(semaphore&);
        bool operator==(limiter&);
        bool operator==(std::nullptr_t);

        void lock();
        bool try_lock();
        bool try_lock_until(std::chrono::high_resolution_clock::time_point time_point);
        void unlock();

        void relock_start();
        void relock_end();

        operator bool();

        bool enter_wait(const task&, enter_state& task); //for unsupported locks like std::mutex the function locks as is and returns true
        bool enter_wait_until(const task&, enter_state& task, std::chrono::high_resolution_clock::time_point);

        template <class Rep, class Period>
        bool try_lock_for(const std::chrono::duration<Rep, Period>& duration) {
            return try_lock_until(std::chrono::high_resolution_clock::now() + duration);
        }
    };

    class FT_API multiply_mutex {
        friend class mutex_unify;

        struct FT_API_LOCAL private_value {
            std::vector<mutex_unify> mu;
        } value;

        void donate_ownership(fast_task::task* target_owner); //internal function for multiply_mutex::enter_wait*
    public:
        multiply_mutex(const std::initializer_list<mutex_unify>& muts);
        void lock();
        bool try_lock();
        bool try_lock_until(std::chrono::high_resolution_clock::time_point time_point);
        void unlock();


        bool enter_wait(const task&, enter_state& task);
        bool enter_wait_until(const task&, enter_state& task, std::chrono::high_resolution_clock::time_point);

        template <class Rep, class Period>
        bool try_lock_for(const std::chrono::duration<Rep, Period>& duration) {
            return try_lock_until(std::chrono::high_resolution_clock::now() + duration);
        }
    };
}

#endif /* FAST_TASK_INCLUDE_TASK_MUTEX_UNIFY */
