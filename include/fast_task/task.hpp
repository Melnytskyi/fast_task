// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#pragma once
#ifndef FAST_TASK_TASKS
    #define FAST_TASK_TASKS
    #include "shared/seqlock.hpp"
    #include "task/cancellation.hpp"
    #include "task/channel.hpp"
    #include "task/condition_variable.hpp"
    #include "task/deadline_timer.hpp"
    #include "task/event.hpp"
    #include "task/future.hpp"
    #include "task/latch.hpp"
    #include "task/mutex.hpp"
    #include "task/mutex_unify.hpp"
    #include "task/once.hpp"
    #include "task/oneshot.hpp"
    #include "task/parallel.hpp"
    #include "task/queue.hpp"
    #include "task/rate_limiter.hpp"
    #include "task/scheduler.hpp"
    #include "task/semaphore.hpp"
    #include "task/spsc_channel.hpp"
    #include "task/task.hpp"
    #include "task/task_group.hpp"
    #include "task/this_task.hpp"
    #include "task/ticker.hpp"
    #include "task/watch_channel.hpp"
#endif
