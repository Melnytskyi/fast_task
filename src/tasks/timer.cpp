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
        if (glob.time_control_enabled.load(std::memory_order_acquire))
            return;
        bool expected = false;
        if (glob.time_control_enabled.compare_exchange_strong(expected, true, std::memory_order_acquire))
            glob.driver.wake();
    }

    inline void put_task_to_wheel(
        hashed_timing_wheel& wheel,
        fast_task::time_point t,
        task& task
    ) {
        wheel.insert(wheel.to_ticks(t), task, get_data(task).awake_check, !can_be_scheduled_task_to_hot());
    }

    void makeTimeWait_extern(task _task, fast_task::time_point time_point) {
        startTimeController();
        get_data(_task).set_awaked(false);
        get_data(_task).set_time_end(false);

        put_task_to_wheel(glob.timed_wheel, time_point, _task);
        // Always wake the driver. The "became earliest" optimisation is not
        // safe here: the driver reads next_deadline() and then parks, and those
        // two steps are not atomic with this insert. Skipping the wake in that
        // window leaves the driver asleep past the new deadline. If nobody is
        // driving at all, this also wakes an idle worker to take the driver so
        // the freshly armed deadline is not missed.
        glob.driver.ensure_driver();
    }

    void makeTimeWait(fast_task::time_point t) {
        startTimeController();
        auto loc = get_loc();
        get_data(loc->curr_task).set_awaked(false);
        get_data(loc->curr_task).set_time_end(false);

        put_task_to_wheel(glob.timed_wheel, t, loc->curr_task);
        glob.driver.ensure_driver();
    }

    void resetTimeWait() {
        auto loc = get_loc();
        get_data(loc->curr_task).set_awaked(false);
        get_data(loc->curr_task).set_time_end(false);
    }
} // namespace fast_task