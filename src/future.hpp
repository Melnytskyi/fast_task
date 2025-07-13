
// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#pragma once
#ifndef FAST_TASK_FUTURE
    #define FAST_TASK_FUTURE

    #include "tasks.hpp"
    #include <functional>

namespace fast_task {
    template <class T>
    struct future {
        task_mutex task_mt;
        task_condition_variable task_cv;
        T result;
        bool _is_ready = false;
        std::exception_ptr ex_ptr;

        static std::shared_ptr<future> start(const std::function<T()>& fn, uint16_t bind_id = (uint16_t)-1) {
            std::shared_ptr<future> future_ = std::make_shared<future>();
            auto task_ = std::make_shared<task>([fn, future_]() {
                try {
                    future_->result = fn();
                } catch (const task_cancellation&) {
                    fast_task::lock_guard guard(future_->task_mt);
                    future_->_is_ready = true;
                    future_->task_cv.notify_all();
                    throw;
                } catch (...) {
                    future_->ex_ptr = std::current_exception();
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

        static std::shared_ptr<future> make_ready(const T& value) {
            std::shared_ptr<future> future_ = std::make_shared<future>();
            future_->result = value;
            future_->_is_ready = true;
            return future_;
        }

        static std::shared_ptr<future> make_ready(T&& value) {
            std::shared_ptr<future> future_ = std::make_shared<future>();
            future_->result = std::move(value);
            future_->_is_ready = true;
            return future_;
        }

        T get() {
            mutex_unify um(task_mt);
            fast_task::unique_lock lock(um);
            while (!_is_ready)
                task_cv.wait(lock);
            if (ex_ptr)
                std::rethrow_exception(ex_ptr);
            return result;
        }

        T take() {
            mutex_unify um(task_mt);
            fast_task::unique_lock lock(um);
            while (!_is_ready)
                task_cv.wait(lock);
            if (ex_ptr)
                std::rethrow_exception(ex_ptr);
            return std::move(result);
        }

        void when_ready(const std::function<void(T)>& fn) {
            mutex_unify um(task_mt);
            fast_task::unique_lock lock(um);
            if (_is_ready) {
                fn(result);
            } else {
                task_cv.callback(
                    lock,
                    std::make_shared<task>(
                        [this, fn]() {
                            fn(get());
                        }
                    )
                );
            }
        }

        bool is_ready() {
            fast_task::unique_lock lock(task_mt);
            return _is_ready;
        }

        void wait() {
            mutex_unify um(task_mt);
            fast_task::unique_lock lock(um);
            while (!_is_ready)
                task_cv.wait(lock);
            if (ex_ptr)
                std::rethrow_exception(ex_ptr);
        }

        template <class T>
        void wait_with(fast_task::unique_lock<T>& lock) {
            mutex_unify um(task_mt);
            fast_task::unique_lock l(um);
            lock.unlock();
            while (!_is_ready)
                task_cv.wait(l);
            lock.lock();
            if (ex_ptr)
                std::rethrow_exception(ex_ptr);
        }

        template <class T>
        void wait_with(std::unique_lock<T>& lock) {
            mutex_unify um(task_mt);
            fast_task::unique_lock l(um);
            lock.unlock();
            while (!_is_ready)
                task_cv.wait(l);
            lock.lock();
            if (ex_ptr)
                std::rethrow_exception(ex_ptr);
        }


        bool wait_for(std::chrono::milliseconds ms) {
            return wait_until(std::chrono::high_resolution_clock::now() + ms);
        }

        bool wait_until(std::chrono::time_point<std::chrono::high_resolution_clock> time) {
            mutex_unify um(task_mt);
            fast_task::unique_lock lock(um);
            while (!_is_ready)
                if (!task_cv.wait_until(lock, time))
                    return false;
            if (ex_ptr)
                std::rethrow_exception(ex_ptr);
            return true;
        }

        void wait_no_except() {
            mutex_unify um(task_mt);
            fast_task::unique_lock lock(um);
            while (!_is_ready)
                task_cv.wait(lock);
        }

        bool wait_for_no_except(std::chrono::milliseconds ms) {
            return wait_until_no_except(std::chrono::high_resolution_clock::now() + ms);
        }

        bool wait_until_no_except(std::chrono::time_point<std::chrono::high_resolution_clock> time) {
            mutex_unify um(task_mt);
            fast_task::unique_lock lock(um);
            while (!_is_ready)
                if (!task_cv.wait_until(lock, time))
                    return false;
            return true;
        }

        bool has_exception() const {
            return (bool)ex_ptr;
        }
    };

    template <>
    struct future<void> {
        task_mutex task_mt;
        task_condition_variable task_cv;
        bool _is_ready = false;
        std::exception_ptr ex_ptr;

        static std::shared_ptr<future> start(const std::function<void()>& fn, uint16_t bind_id = (uint16_t)-1) {
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
                    future_->ex_ptr = std::current_exception();
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

        static std::shared_ptr<future> make_ready() {
            std::shared_ptr<future> future_ = std::make_shared<future>();
            future_->_is_ready = true;
            return future_;
        }

        void get() {
            mutex_unify um(task_mt);
            fast_task::unique_lock lock(um);
            while (!_is_ready)
                task_cv.wait(lock);
            if (ex_ptr)
                std::rethrow_exception(ex_ptr);
        }

        void take() {
            get();
        }

        void when_ready(const std::function<void()>& fn) {
            mutex_unify um(task_mt);
            fast_task::unique_lock lock(um);
            if (_is_ready) {
                fn();
            } else {
                task_cv.callback(
                    lock,
                    std::make_shared<task>(fn)
                );
            }
        }

        bool is_ready() const {
            return _is_ready;
        }

        void wait() {
            mutex_unify um(task_mt);
            fast_task::unique_lock lock(um);
            while (!_is_ready)
                task_cv.wait(lock);
            if (ex_ptr)
                std::rethrow_exception(ex_ptr);
        }

        template <class T>
        void wait_with(fast_task::unique_lock<T>& lock) {
            mutex_unify um(task_mt);
            fast_task::unique_lock l(um);
            while (!_is_ready)
                task_cv.wait(l);
            if (ex_ptr)
                std::rethrow_exception(ex_ptr);
        }

        template <class T>
        void wait_with(std::unique_lock<T>& lock) {
            mutex_unify um(task_mt);
            fast_task::unique_lock l(um);
            while (!_is_ready)
                task_cv.wait(l);
            if (ex_ptr)
                std::rethrow_exception(ex_ptr);
        }

        bool wait_for(std::chrono::milliseconds ms) {
            return wait_until(std::chrono::high_resolution_clock::now() + ms);
        }

        bool wait_until(std::chrono::time_point<std::chrono::high_resolution_clock> time) {
            mutex_unify um(task_mt);
            fast_task::unique_lock lock(um);
            while (!_is_ready)
                if (!task_cv.wait_until(lock, time))
                    return false;
            if (ex_ptr)
                std::rethrow_exception(ex_ptr);
            return true;
        }

        void wait_no_except() {
            mutex_unify um(task_mt);
            fast_task::unique_lock lock(um);
            while (!_is_ready)
                task_cv.wait(lock);
        }

        bool wait_for_no_except(std::chrono::milliseconds ms) {
            return wait_until_no_except(std::chrono::high_resolution_clock::now() + ms);
        }

        bool wait_until_no_except(std::chrono::time_point<std::chrono::high_resolution_clock> time) {
            mutex_unify um(task_mt);
            fast_task::unique_lock lock(um);
            while (!_is_ready)
                if (!task_cv.wait_until(lock, time))
                    return false;
            return true;
        }

        bool has_exception() const {
            return (bool)ex_ptr;
        }
    };

    template <class T>
    struct cancelable_future : public future<T> {
        std::shared_ptr<task> task_;

        static std::shared_ptr<cancelable_future> start(const std::function<T()>& fn, uint16_t bind_id = (uint16_t)-1) {
            std::shared_ptr<cancelable_future> future_ = std::make_shared<cancelable_future>();
            future_->task_ = std::make_shared<task>([fn, future_]() {
                try {
                    future_->result = fn();
                } catch (const task_cancellation&) {
                    fast_task::lock_guard guard(future_->task_mt);
                    future_->_is_ready = true;
                    future_->task_cv.notify_all();
                    throw;
                } catch (...) {
                    future_->ex_ptr = std::current_exception();
                }
                fast_task::lock_guard guard(future_->task_mt);
                future_->_is_ready = true;
                future_->task_cv.notify_all();
            });
            if (bind_id != (uint16_t)-1)
                future_->task_->set_worker_id(bind_id);
            scheduler::start(future_->task_);
            return future_;
        }

        static std::shared_ptr<cancelable_future> make_ready(const T& value) {
            std::shared_ptr<cancelable_future> future_ = std::make_shared<cancelable_future>();
            future_->result = value;
            future_->_is_ready = true;
            return future_;
        }

        static std::shared_ptr<cancelable_future> make_ready(T&& value) {
            std::shared_ptr<cancelable_future> future_ = std::make_shared<cancelable_future>();
            future_->result = std::move(value);
            future_->_is_ready = true;
            return future_;
        }

        T get() {
            mutex_unify um(future<T>::task_mt);
            fast_task::unique_lock lock(um);
            while (!future<T>::_is_ready)
                future<T>::task_cv.wait(lock);
            if (future<T>::ex_ptr)
                std::rethrow_exception(future<T>::ex_ptr);
            if (task_)
                if (task_->is_cancellation_requested())
                    throw std::runtime_error("Task has been canceled. Can not receive result.");
            return future<T>::result;
        }

        T take() {
            mutex_unify um(future<T>::task_mt);
            fast_task::unique_lock lock(um);
            while (!future<T>::_is_ready)
                future<T>::task_cv.wait(lock);
            if (future<T>::ex_ptr)
                std::rethrow_exception(future<T>::ex_ptr);
            if (task_)
                if (task_->is_cancellation_requested())
                    throw std::runtime_error("Task has been canceled. Can not receive result.");
            return std::move(future<T>::result);
        }

        void cancel() {
            task_->await_notify_cancel();
        }
    };

    template <>
    struct cancelable_future<void> : public future<void> {
        std::shared_ptr<task> task_;

        static std::shared_ptr<cancelable_future> start(const std::function<void()>& fn, uint16_t bind_id = (uint16_t)-1) {
            std::shared_ptr<cancelable_future> future_ = std::make_shared<cancelable_future>();
            future_->task_ = std::make_shared<task>([fn, future_]() {
                try {
                    fn();
                } catch (const task_cancellation&) {
                    fast_task::lock_guard guard(future_->task_mt);
                    future_->_is_ready = true;
                    future_->task_cv.notify_all();
                    throw;
                } catch (...) {
                    future_->ex_ptr = std::current_exception();
                }
                fast_task::lock_guard guard(future_->task_mt);
                future_->_is_ready = true;
                future_->task_cv.notify_all();
            });
            if (bind_id != (uint16_t)-1)
                future_->task_->set_worker_id(bind_id);
            scheduler::start(future_->task_);
            return future_;
        }

        static std::shared_ptr<cancelable_future> make_ready() {
            std::shared_ptr<cancelable_future> future_ = std::make_shared<cancelable_future>();
            future_->_is_ready = true;
            return future_;
        }

        void get() {
            mutex_unify um(future<void>::task_mt);
            fast_task::unique_lock lock(um);
            while (!future<void>::_is_ready)
                future<void>::task_cv.wait(lock);
            if (future<void>::ex_ptr)
                std::rethrow_exception(future<void>::ex_ptr);
            if (task_)
                if (task_->is_cancellation_requested())
                    throw std::runtime_error("Task has been canceled. Can not receive result.");
        }

        void take() {
            get();
        }

        void cancel() {
            task_->await_notify_cancel();
        }
    };

    template <class T>
    using future_ptr = std::shared_ptr<future<T>>;

    template <class T>
    using cancelable_future_ptr = std::shared_ptr<cancelable_future<T>>;

    namespace future_tool {
        template <class T, class FN>
        future_ptr<void> forEach(T& container, FN&& fn) {
            if (container.empty())
                return future<void>::make_ready();
            std::vector<cancelable_future_ptr<void>> futures;
            futures.reserve(container.size());
            for (auto& item : container)
                futures.push_back(cancelable_future<void>::start([item, fn]() { fn(item); }));

            return future<void>::start([fut = std::move(futures)] {
                try {
                    for (auto& future_ : fut)
                        future_->wait();
                } catch (...) {
                    for (auto& future_ : fut)
                        future_->cancel();
                    throw;
                }
            });
        }

        template <class T, class FN>
        future_ptr<void> forEachMove(T&& container, FN&& fn) {
            if (container.empty())
                return future<void>::make_ready();
            std::vector<cancelable_future_ptr<void>> futures;
            futures.reserve(container.size());
            for (auto&& item : container)
                futures.push_back(cancelable_future<void>::start([it = std::move(item), fn]() mutable {
                    fn(std::move(it));
                }));

            return future<void>::start([fut = std::move(futures)] {
                try {
                    for (auto& future_ : fut)
                        future_->wait();
                } catch (...) {
                    for (auto& future_ : fut)
                        future_->cancel();
                    throw;
                }
            });
        }

        template <class Result, class T, class FN>
        std::vector<Result> process(const std::vector<T>& container, FN&& fn) {
            if (container.empty())
                return {};

            std::vector<cancelable_future_ptr<Result>> futures;
            futures.reserve(container.size());
            for (auto& item : container)
                futures.push_back(cancelable_future<Result>::start([item, fn = fn]() mutable { return fn(item); }));

            std::vector<Result> res;
            res.reserve(container.size());
            try {
                for (auto& future_ : futures)
                    res.push_back(future_->take());
            } catch (...) {
                for (auto& future_ : futures)
                    future_->cancel();
                throw;
            }
            return res;
        }

        template <class Ret, class Accept>
        future_ptr<Ret> chain(const future_ptr<Accept>& future_, const std::function<Ret(Accept)>& fn) {
            future_ptr<Ret> new_future = std::make_shared<future<Ret>>();
            future_->when_ready([fn, new_future](Accept a) mutable {
                try {
                    if constexpr (std::is_same_v<Ret, void>)
                        fn(std::move(a));
                    else
                        new_future->result = fn(std::move(a));
                } catch (...) {
                };
                fast_task::lock_guard guard(new_future->task_mt);
                new_future->_is_ready = true;
                new_future->task_cv.notify_all();
            });
            return new_future;
        }

        template <class Ret>
        future_ptr<Ret> chain(const future_ptr<void>& future_, const std::function<Ret()>& fn) {
            future_ptr<Ret> new_future = std::make_shared<future<Ret>>();
            future_->when_ready([fn, new_future]() mutable {
                try {
                    if constexpr (std::is_same_v<Ret, void>)
                        fn();
                    else
                        new_future->result = fn();
                } catch (...) {
                };
                fast_task::lock_guard guard(new_future->task_mt);
                new_future->_is_ready = true;
                new_future->task_cv.notify_all();
            });
            return new_future;
        }

        template <class Ret>
        future_ptr<std::vector<Ret>> accumulate(const std::vector<future_ptr<Ret>>& futures) {
            if (futures.empty())
                return future<std::vector<Ret>>::make_ready({});
            return future<std::vector<Ret>>::start([fut = futures] {
                std::vector<Ret> res;
                res.resize(fut.size());
                fut.for_each([&](size_t pos, auto& it) {
                    res[pos] = it.take();
                });
                return res;
            });
        }

        template <class Ret>
        future_ptr<std::vector<Ret>> accumulate(std::vector<future_ptr<Ret>>&& futures) {
            if (futures.empty())
                return future<std::vector<Ret>>::make_ready({});
            return future<std::vector<Ret>>::start([fut = std::move(futures)] {
                std::vector<Ret> res;
                res.resize(fut.size());
                fut.for_each([&](size_t pos, auto& it) {
                    res[pos] = it.take();
                });
                return res;
            });
        }

        static future_ptr<void> combineAll(const std::vector<future_ptr<void>>& futures) {
            if (futures.empty())
                return future<void>::make_ready();
            std::vector<future_ptr<void>> fut = {futures.begin(), futures.end()};
            return future<void>::start([fut = std::move(fut)] {
                for (auto& future_ : fut)
                    future_->wait();
            });
        }

        static future_ptr<void> combineAll(std::vector<future_ptr<void>>&& futures) {
            if (futures.empty())
                return future<void>::make_ready();
            return future<void>::start([fut = std::move(futures)] {
                for (auto& future_ : fut)
                    future_->wait();
            });
        }

        template <class... Futures>
        void each(Futures&&... futures) {
            std::vector<future_ptr<void>> fut = {futures...};
            for (auto& future_ : fut)
                future_->wait();
        }

        template <class... Futures>
        void eachIn(Futures&&... futures) {
            std::vector<future_ptr<void>> fut = {futures...};
            for (auto& future_ : fut)
                future_->wait();
        }
    }

    template <class T>
    auto make_ready_future(T&& value) {
        return future<std::remove_reference_t<std::remove_cv_t<T>>>::make_ready(std::forward<T>(value));
    }
}
#endif
