// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <tasks.hpp>
#include <tasks/_internal.hpp>

namespace fast_task {
    task_cancellation::task_cancellation() {}

    task_cancellation::~task_cancellation() noexcept(false) {
        if (!in_landing) {
            abort();
        }
    }

    bool task_cancellation::_in_landing() {
        return in_landing;
    }

    void forceCancelCancellation(task_cancellation& cancel_token) {
        cancel_token.in_landing = true;
    }

    void checkCancellation() {
        if (loc.curr_task->make_cancel)
            throw task_cancellation();
        if (loc.curr_task->timeout != std::chrono::high_resolution_clock::time_point::min())
            if (loc.curr_task->timeout <= std::chrono::high_resolution_clock::now())
                throw task_cancellation();
    }
}
