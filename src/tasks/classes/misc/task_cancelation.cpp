// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <fast_task/interrupt.hpp>
#include <fast_task/task.hpp>
#include <tasks/_internal.hpp>
#include <tasks/util/interrupt.hpp>

namespace fast_task {
    task_cancellation::task_cancellation() {
        interrupt_unsafe_region::lock();
    }

    task_cancellation::task_cancellation(const task_cancellation& other)
        : in_landing(other.in_landing) {
        interrupt_unsafe_region::lock();
    }

    task_cancellation& task_cancellation::operator=(const task_cancellation& other) noexcept {
        in_landing = other.in_landing;
        return *this;
    }

    task_cancellation::~task_cancellation() {
        interrupt_unsafe_region::unlock();
    }

    bool task_cancellation::_in_landing() {
        return in_landing;
    }

    void forceCancelCancellation(const task_cancellation& cancel_token) {
        const_cast<task_cancellation&>(cancel_token).in_landing = true;
    }

    bool checkCancellation() noexcept {
        constexpr auto timeout_disabled = fast_task::time_point::min().time_since_epoch().count();
        interrupt_unsafe_region reg;
        if (!get_loc())
            return false;
        auto& task = get_loc()->curr_task;
        if (!task)
            return false;
        auto& curr_task = get_data(task);
        if (curr_task.get_cancellation_requested())
            return true;
        if (auto* ex = curr_task.exdata.load(std::memory_order_acquire))
            if (ex->timeout != timeout_disabled)
                if (ex->timeout <= fast_task::clock::now().time_since_epoch().count())
                    return true;
        return false;
    }
}
