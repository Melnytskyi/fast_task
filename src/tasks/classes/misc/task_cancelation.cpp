// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <task.hpp>
#include <tasks/_internal.hpp>
#include <tasks/util/interrupt.hpp>

namespace fast_task {
    task_cancellation::task_cancellation() {
        interrupt::interrupt_unsafe_region::lock();
    }

    task_cancellation::~task_cancellation() {
        interrupt::interrupt_unsafe_region::unlock();
        assert(in_landing);
    }

    bool task_cancellation::_in_landing() {
        return in_landing;
    }

    void forceCancelCancellation(const task_cancellation& cancel_token) {
        const_cast<task_cancellation&>(cancel_token).in_landing = true;
    }

    bool checkCancellation() noexcept {
        if (!loc.curr_task)
            return false;
        if (get_data(loc.curr_task).make_cancel)
            return true;
        if (get_data(loc.curr_task).timeout != std::chrono::high_resolution_clock::time_point::min().time_since_epoch().count())
            if (get_data(loc.curr_task).timeout <= std::chrono::high_resolution_clock::now().time_since_epoch().count())
                return true;
        return false;
    }
}
