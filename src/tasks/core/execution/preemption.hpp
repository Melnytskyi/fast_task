// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_CORE_PREEMPTION
#define FAST_TASK_CORE_PREEMPTION

namespace fast_task {
#ifdef FT_ENABLE_PREEMPTIVE_SCHEDULER
    void FT_API_LOCAL timer_reinit();
    void FT_API_LOCAL interruptTask();
    void FT_API_LOCAL set_interruptTask();
    void FT_API_LOCAL stop_timer();
    void FT_API_LOCAL preserve_interrupt_data();
    void FT_API_LOCAL restore_interrupt_data();
    void FT_API_LOCAL flush_interrupt_data();
#else
    inline void timer_reinit() {}

    inline void interruptTask() {}

    inline void set_interruptTask() {}

    inline void stop_timer() {}

    inline void preserve_interrupt_data() {}

    inline void restore_interrupt_data() {}

    inline void flush_interrupt_data() {}
#endif
}

#endif /* FAST_TASK_CORE_PREEMPTION */
