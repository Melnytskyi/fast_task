// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)
#include <fast_task/task/future.hpp>
#include <functional>

namespace fast_task {
    std::shared_ptr<future<void>> future<void>::make_ready() {
        std::shared_ptr<future> future_ = std::make_shared<future>();
        future_->task_ = task::callback_dummy(nullptr, nullptr, nullptr, nullptr, nullptr);
        future_->task_.end_dummy([](auto) {});
        future_->has_result = true;
        return future_;
    }

    void future<void>::get() {
        wait();
    }

    void future<void>::take() {
        wait();
    }

    void future<void>::callback(const task& task) {
        task_.callback(task);
    }

    bool future<void>::is_ready() {
        return task_.is_ended();
    }

    void future<void>::wait() {
        wait_impl();
        if (ex_ptr)
            std::rethrow_exception(ex_ptr);
        if (task_.is_cancellation_requested())
            throw std::runtime_error("Task has been canceled. Can not receive result.");
    }

    bool future<void>::wait_until(fast_task::time_point time) {
        if (!wait_until_impl(time))
            return false;
        if (ex_ptr)
            std::rethrow_exception(ex_ptr);
        if (task_.is_cancellation_requested())
            throw std::runtime_error("Task has been canceled. Can not receive result.");
        return true;
    }

    void future<void>::wait_no_except() {
        wait_impl();
    }

    bool future<void>::wait_until_no_except(fast_task::time_point time) {
        return wait_until_impl(time);
    }

    bool future<void>::has_exception() const {
        return task_.is_ended() && static_cast<bool>(ex_ptr);
    }

    void future<void>::cancel() {
        task_.await_notify_cancel();
    }

    bool future<void>::is_canceled() const {
        return task_.is_cancellation_requested();
    }

    bool future<void>::enter_wait(const task& t, enter_state& state) {
        return task_.enter_wait(t, state);
    }

    bool future<void>::enter_wait_until(const task& t, enter_state& state, fast_task::time_point time) {
        return task_.enter_wait_until(t, state, time);
    }
}