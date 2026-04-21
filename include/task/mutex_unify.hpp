#ifndef INCLUDE_TASK_MUTEX_UNIFY
#define INCLUDE_TASK_MUTEX_UNIFY

#include "fwd.hpp"
#include "../threading.hpp"
#include <cstdint>
#include <initializer_list>
#include <vector>
#include <mutex>

namespace fast_task {

    class FT_API mutex_unify {
        friend class multiply_mutex;
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
            lim
        };

        union FT_API_LOCAL {
            std::mutex* std_nmut = nullptr;
            std::timed_mutex* std_ntimed;
            std::recursive_mutex* std_nrec;
            fast_task::mutex* nmut;
            fast_task::timed_mutex* ntimed;
            fast_task::rw_mutex* rwmut;
            fast_task::recursive_mutex* nrec;
            fast_task::spin_lock* uspin;
            task_mutex* umut;
            task_rw_mutex* urwmut;
            task_recursive_mutex* urmut;
            class multiply_mutex* mmut;
            task_semaphore* sem;
            task_limiter* lim;
        };

        mutex_unify_type type;

        void donate_ownership(fast_task::task* target_owner); //internal function for multiply_mutex::enter_wait*

    public:
        mutex_unify();
        mutex_unify(const mutex_unify& mut);
        mutex_unify(std::mutex& smut);
        mutex_unify(std::timed_mutex& smut);
        mutex_unify(std::recursive_mutex& smut);
        mutex_unify(fast_task::mutex& smut);
        mutex_unify(fast_task::timed_mutex& smut);
        mutex_unify(fast_task::rw_mutex& smut, bool write_read = true);
        mutex_unify(fast_task::recursive_mutex& smut);
        mutex_unify(fast_task::spin_lock& smut);
        mutex_unify(task_mutex& smut);
        mutex_unify(task_rw_mutex& smut, bool write_read = true);
        mutex_unify(task_recursive_mutex& smut);
        mutex_unify(multiply_mutex& mmut);
        mutex_unify(task_semaphore& sem);
        mutex_unify(task_limiter& lim);
        mutex_unify(std::nullptr_t);

        ~mutex_unify();

        mutex_unify& operator=(const mutex_unify&);
        mutex_unify& operator=(std::mutex&);
        mutex_unify& operator=(std::timed_mutex&);
        mutex_unify& operator=(std::recursive_mutex&);
        mutex_unify& operator=(fast_task::mutex&);
        mutex_unify& operator=(fast_task::timed_mutex&);
        mutex_unify& operator=(fast_task::recursive_mutex&);
        mutex_unify& operator=(fast_task::spin_lock&);
        mutex_unify& operator=(task_mutex&);
        mutex_unify& operator=(task_recursive_mutex&);
        mutex_unify& operator=(class multiply_mutex&);
        mutex_unify& operator=(task_semaphore&);
        mutex_unify& operator=(task_limiter&);
        mutex_unify& operator=(std::nullptr_t);

        bool operator==(const mutex_unify&);
        bool operator==(std::mutex&);
        bool operator==(std::timed_mutex&);
        bool operator==(std::recursive_mutex&);
        bool operator==(fast_task::mutex&);
        bool operator==(fast_task::timed_mutex&);
        bool operator==(fast_task::rw_mutex&);
        bool operator==(fast_task::recursive_mutex&);
        bool operator==(fast_task::spin_lock&);
        bool operator==(task_mutex&);
        bool operator==(task_rw_mutex&);
        bool operator==(task_recursive_mutex&);
        bool operator==(class multiply_mutex&);
        bool operator==(task_semaphore&);
        bool operator==(task_limiter&);
        bool operator==(std::nullptr_t);

        void lock();
        bool try_lock();
        bool try_lock_until(std::chrono::high_resolution_clock::time_point time_point);
        void unlock();

        void relock_start();
        void relock_end();

        operator bool();

        bool enter_wait(const std::shared_ptr<task>& task); //for unsupported locks like std::mutex the function locks as is and returns true
        bool enter_wait_until(const std::shared_ptr<task>& task, std::chrono::high_resolution_clock::time_point);

        template <class Rep, class Period>
        bool enter_wait_for(const std::shared_ptr<task>& task, const std::chrono::duration<Rep, Period>& duration) {
            return enter_wait_until(task, std::chrono::high_resolution_clock::now() + duration);
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


        bool enter_wait(const std::shared_ptr<task>& task);
        bool enter_wait_until(const std::shared_ptr<task>& task, std::chrono::high_resolution_clock::time_point);

        template <class Rep, class Period>
        bool try_lock_for(const std::chrono::duration<Rep, Period>& duration) {
            return try_lock_until(std::chrono::high_resolution_clock::now() + duration);
        }
    };
}

#endif /* INCLUDE_TASK_MUTEX_UNIFY */
