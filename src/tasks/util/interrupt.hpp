// Copyright Danyil Melnytskyi 2022-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_INTERRUPT
#define FAST_TASK_INTERRUPT

//Virtualized signals for windows and proxy for posix signals
//  implements only timer signals
namespace fast_task::interrupt {
    struct interrupt_unsafe_region {
        interrupt_unsafe_region();
        ~interrupt_unsafe_region();
        static void lock();
        static void unlock();
        static size_t lock_swap(size_t);
    };

    struct timeval {
        long tv_sec;
        long tv_usec;
    };

    struct itimerval {
        struct timeval it_interval;
        struct timeval it_value;
    };

    bool timer_callback(void (*interrupter)());
    bool setitimer(const struct itimerval* new_value, struct itimerval* old_value);
    void stop_timer();

    
}

#endif
