// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)
#include <functional>
#include <future.hpp>

namespace fast_task {
    template struct FT_API future<void>;

    future<void>::~future() = default;

    std::shared_ptr<future<void>> future<void>::make_ready() {
        std::shared_ptr<future> future_ = std::make_shared<future>();
        future_->_is_ready = true;
        return future_;
    }

    void future<void>::get() {
        wait();
    }

    void future<void>::take() {
        get();
    }

    bool future<void>::is_ready() const {
        return _is_ready;
    }

    void future<void>::wait() {
        mutex_unify um(task_mt);
        fast_task::unique_lock lock(um);
        while (!_is_ready)
            task_cv.wait(lock);
        if (ex_ptr)
            std::rethrow_exception(ex_ptr);
    }

    bool future<void>::wait_for(std::chrono::milliseconds ms) {
        return wait_until(std::chrono::high_resolution_clock::now() + ms);
    }

    bool future<void>::wait_until(std::chrono::time_point<std::chrono::high_resolution_clock> time) {
        mutex_unify um(task_mt);
        fast_task::unique_lock lock(um);
        while (!_is_ready)
            if (!task_cv.wait_until(lock, time))
                return false;
        if (ex_ptr)
            std::rethrow_exception(ex_ptr);
        return true;
    }

    void future<void>::wait_no_except() {
        mutex_unify um(task_mt);
        fast_task::unique_lock lock(um);
        while (!_is_ready)
            task_cv.wait(lock);
    }

    bool future<void>::wait_for_no_except(std::chrono::milliseconds ms) {
        return wait_until_no_except(std::chrono::high_resolution_clock::now() + ms);
    }

    bool future<void>::wait_until_no_except(std::chrono::time_point<std::chrono::high_resolution_clock> time) {
        mutex_unify um(task_mt);
        fast_task::unique_lock lock(um);
        while (!_is_ready)
            if (!task_cv.wait_until(lock, time))
                return false;
        return true;
    }

    bool future<void>::has_exception() const {
        return (bool)ex_ptr;
    }

}