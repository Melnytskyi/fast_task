// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)
#include <functional>
#include <future.hpp>

namespace fast_task {
    template struct FT_API future<void>;

    future<void>::~future() {
        if (ex_ptr)
            delete ex_ptr;
    }

    std::shared_ptr<future<void>> future<void>::start(const std::function<void()>& fn, uint16_t bind_id) {
        std::shared_ptr<future> future_ = std::make_shared<future>();
        auto task_ = std::make_shared<task>([fn, future_]() {
            try {
                fn();
            } catch (const task_cancellation&) {
                fast_task::lock_guard guard(future_->task_mt);
                future_->_is_ready = true;
                future_->task_cv.notify_all();
                throw;
            } catch (...) {
                future_->ex_ptr = new auto(std::current_exception());
            }
            fast_task::lock_guard guard(future_->task_mt);
            future_->_is_ready = true;
            future_->task_cv.notify_all();
        });
        if (bind_id != (uint16_t)-1)
            task_->set_worker_id(bind_id);
        scheduler::start(task_);
        return future_;
    }

    std::shared_ptr<future<void>> future<void>::start(fast_task::task_query& query, const std::function<void()>& fn, uint16_t bind_id) {
        std::shared_ptr<future> future_ = std::make_shared<future>();
        auto task_ = std::make_shared<task>([fn, future_]() {
            try {
                fn();
            } catch (const task_cancellation&) {
                fast_task::lock_guard guard(future_->task_mt);
                future_->_is_ready = true;
                future_->task_cv.notify_all();
                throw;
            } catch (...) {
                future_->ex_ptr = new auto(std::current_exception());
            }
            fast_task::lock_guard guard(future_->task_mt);
            future_->_is_ready = true;
            future_->task_cv.notify_all();
        });
        if (bind_id != (uint16_t)-1)
            task_->set_worker_id(bind_id);
        query.add(task_);
        return future_;
    }

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

    void future<void>::when_ready(const std::function<void()>& fn) {
        mutex_unify um(task_mt);
        fast_task::unique_lock lock(um);
        if (_is_ready) {
            lock.unlock();
            fn();
        } else {
            task_cv.callback(
                lock,
                std::make_shared<task>(fn)
            );
        }
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
            std::rethrow_exception(*ex_ptr);
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
            std::rethrow_exception(*ex_ptr);
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