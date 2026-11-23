// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <fast_task/native/thread.hpp>
#include <tasks/_internal.hpp>
#include <tasks/util/interrupt.hpp>
#include <tasks/util/light_stack.hpp>

namespace fast_task {

    // The dedicated timer thread is gone: driver_context::poll() performs the
    // exact same wheel collection from whichever worker is idle. Enabling the
    // controller is now just a flag flip plus a driver wake-up.
    void startTimeController() {
        if (glob.timing.enabled.load(std::memory_order_acquire))
            return;
        bool expected = false;
        if (glob.timing.enabled.compare_exchange_strong(expected, true, std::memory_order_acquire))
            glob.driver.wake();
    }

    namespace {
        // Returns the tick the node was armed at. The wheel may push a tick that
        // is already in the past one tick ahead, so this value is only ever used
        // as a "not later than" comparison against the driver's park deadline.
        inline uint64_t put_task_to_wheel(
            hashed_timing_wheel& wheel,
            fast_task::time_point t,
            task& awake
        ) {
            const uint64_t tick = wheel.to_ticks(t);
            wheel.insert(tick, awake, get_data(awake).awake_check, !can_be_scheduled_task_to_hot());
            return tick;
        }

    }

    void makeTimeWait_extern(task _task, fast_task::time_point time_point) {
        startTimeController();
        get_data(_task).reset_wait_flags();

        const uint64_t tick = put_task_to_wheel(glob.timing.wheel, time_point, _task);
        notify_driver_of_timer(tick);
    }

    void makeTimeWait(fast_task::time_point t) {
        startTimeController();
        auto loc = get_loc();
        get_data(loc->curr_task).reset_wait_flags();

        const uint64_t tick = put_task_to_wheel(glob.timing.wheel, t, loc->curr_task);
        notify_driver_of_timer(tick);
    }

    void resetTimeWait() {
        auto loc = get_loc();
        get_data(loc->curr_task).reset_wait_flags();
    }
} // namespace fast_task
