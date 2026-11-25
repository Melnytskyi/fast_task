// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#pragma once
#ifndef FAST_TASK_INCLUDE_TASK_FUTURE
    #define FAST_TASK_INCLUDE_TASK_FUTURE
    #include "../shared.hpp"
    #include "condition_variable.hpp"
    #include "fwd.hpp"
    #include "queue.hpp"
    #include "scheduler.hpp"
    #include "task.hpp"
    #include <optional>

    #if __cplusplus >= 202002
        #include "../coroutine/core.hpp"
    #endif
namespace fast_task {
    namespace detail {
        struct queued_future_sync {
            fast_task::mutex mtx;
            fast_task::condition_variable cv;
            bool done = false;

            void signal() {
                {
                    fast_task::lock_guard<fast_task::mutex> lk(mtx);
                    done = true;
                }
                cv.notify_all();
            }

            void wait() {
                fast_task::unique_lock<fast_task::mutex> lk(mtx);
                while (!done)
                    cv.wait(lk);
            }

            bool wait_until(fast_task::time_point tp) {
                fast_task::unique_lock<fast_task::mutex> lk(mtx);
                while (!done) {
                    if (!cv.wait_until(lk, tp))
                        return done;
                }
                return true;
            }
        };
    }

    template <class T>
    class future : public std::enable_shared_from_this<future<T>> {
        template <class U>
        friend class future;

        task task_;
        std::optional<T> result;
        std::exception_ptr ex_ptr;
        std::shared_ptr<detail::queued_future_sync> queued_sync;

        void wait_impl() {
            if (task_.is_ended())
                return;
            if (queued_sync) {
                queued_sync->wait();
                return;
            }
            task_.await_task();
        }

        bool wait_until_impl(fast_task::time_point time) {
            if (task_.is_ended())
                return true;
            if (queued_sync)
                return queued_sync->wait_until(time);
            return task_.await_task_until(time);
        }

    public:
        future() = default;
        ~future() = default;

        template <class FN>
        static std::shared_ptr<future> start(FN&& fn, scheduler::worker_pool* pool = nullptr)
            requires std::is_same_v<std::invoke_result_t<FN>, T>
        {
            std::shared_ptr<future> future_ = std::make_shared<future>();
            future_->task_ = task::create(
                [fn = std::forward<FN>(fn), weak_future = std::weak_ptr<future>(future_)]() mutable {
                    auto result = std::make_optional<T>(fn());
                    if (auto self = weak_future.lock())
                        self->result.emplace(std::move(*result));
                },
                [weak_future = std::weak_ptr<future>(future_)](const std::exception_ptr& ex) {
                    if (auto self = weak_future.lock())
                        self->ex_ptr = ex;
                }
            );
            if (pool)
                pool->bind(future_->task_);
            scheduler::start(future_->task_);
            return future_;
        }

        template <class FN>
        static std::shared_ptr<future> start(fast_task::queue& queue, FN&& fn, scheduler::worker_pool* pool = nullptr)
            requires std::is_same_v<std::invoke_result_t<FN>, T>
        {
            std::shared_ptr<future> future_ = std::make_shared<future>();
            auto sync = std::make_shared<detail::queued_future_sync>();
            future_->queued_sync = sync;
            future_->task_ = task::create(
                [fn = std::forward<FN>(fn), weak_future = std::weak_ptr<future>(future_)]() mutable {
                    auto result = std::make_optional<T>(fn());
                    if (auto self = weak_future.lock())
                        self->result.emplace(std::move(*result));
                },
                [weak_future = std::weak_ptr<future>(future_)](const std::exception_ptr& ex) {
                    if (auto self = weak_future.lock())
                        self->ex_ptr = ex;
                }
            );
            if (pool)
                pool->bind(future_->task_);
            queue.add(future_->task_);
            future_->task_.callback(task::create([sync = std::move(sync)]() {
                sync->signal();
            }));
            return future_;
        }

        template <class FN>
        std::shared_ptr<future<std::invoke_result_t<FN, T>>> chain(FN&& fn, scheduler::worker_pool* pool = nullptr) &;

        template <class FN>
        std::shared_ptr<future<std::invoke_result_t<FN, T>>> chain(FN&& fn, scheduler::worker_pool* pool = nullptr) &&;

        static std::shared_ptr<future> make_ready(const T& value) {
            std::shared_ptr<future> future_ = std::make_shared<future>();
            future_->task_ = task::callback_dummy(nullptr, nullptr, nullptr, nullptr, nullptr);
            future_->task_.end_dummy([](auto) {});
            future_->result = std::make_optional<T>(value);
            return future_;
        }

        static std::shared_ptr<future> make_ready(T&& value) {
            std::shared_ptr<future> future_ = std::make_shared<future>();
            future_->task_ = task::callback_dummy(nullptr, nullptr, nullptr, nullptr, nullptr);
            future_->task_.end_dummy([](auto) {});
            future_->result = std::make_optional<T>(std::move(value));
            return future_;
        }

        T get() {
            wait_impl();
            if (ex_ptr)
                std::rethrow_exception(ex_ptr);
            if (task_.is_cancellation_requested())
                throw std::runtime_error("Task has been canceled. Can not receive result.");
            if (!result.has_value())
                throw std::runtime_error("Future has no result.");
            return *result;
        }

        T take() {
            wait_impl();
            if (ex_ptr)
                std::rethrow_exception(ex_ptr);
            if (task_.is_cancellation_requested())
                throw std::runtime_error("Task has been canceled. Can not receive result.");
            if (!result.has_value())
                throw std::runtime_error("Future has no result.");
            return std::move(*result);
        }

        template <class FN>
        void when_ready(FN&& fn)
            requires std::is_same_v<std::invoke_result_t<FN, future&>, void>
        {
            if (task_.is_ended())
                fn(*this);
            else
                task_.callback(task::create([fut = this->shared_from_this(), fn = std::forward<FN>(fn)]() mutable {
                    fn(*fut);
                }));
        }

        template <class FN>
        void when_ready(FN&& fn)
            requires std::is_invocable_v<FN>
        {
            if (task_.is_ended())
                fn();
            else
                task_.callback(task::create([fn = std::forward<FN>(fn)]() mutable {
                    fn();
                }));
        }

        void callback(const task& task) {
            task_.callback(task);
        }

        bool is_ready() {
            return task_.is_ended();
        }

        void wait() {
            wait_impl();
            if (ex_ptr)
                std::rethrow_exception(ex_ptr);
            if (task_.is_cancellation_requested())
                throw std::runtime_error("Task has been canceled. Can not receive result.");
        }

        template <class Dur_resolution, class Dur_type>
        bool wait_for(std::chrono::duration<Dur_resolution, Dur_type> duration) {
            return wait_until(fast_task::clock::now() + duration);
        }

        bool wait_until(fast_task::time_point time) {
            if (!wait_until_impl(time))
                return false;
            if (ex_ptr)
                std::rethrow_exception(ex_ptr);
            if (task_.is_cancellation_requested())
                throw std::runtime_error("Task has been canceled. Can not receive result.");
            return true;
        }

        void wait_no_except() {
            wait_impl();
        }

        template <class Dur_resolution, class Dur_type>
        bool wait_for_no_except(std::chrono::duration<Dur_resolution, Dur_type> duration) {
            return wait_until_no_except(fast_task::clock::now() + duration);
        }

        bool wait_until_no_except(fast_task::time_point time) {
            return wait_until_impl(time);
        }

        bool has_exception() const {
            return task_.is_ended() && static_cast<bool>(ex_ptr);
        }

        bool is_canceled() const {
            return task_.is_cancellation_requested();
        }

        void cancel() {
            task_.await_notify_cancel();
        }

        bool enter_wait(const task& t, enter_state& state) {
            return task_.enter_wait(t, state);
        }

        bool enter_wait_until(const task& t, enter_state& state, fast_task::time_point time) {
            return task_.enter_wait_until(t, state, time);
        }
    };

    template <>
    class FT_API future<void> : public std::enable_shared_from_this<future<void>> {
        template <class U>
        friend class future;

        task task_;
        std::exception_ptr ex_ptr;
        bool has_result = false;
        std::shared_ptr<detail::queued_future_sync> queued_sync;

        void wait_impl() {
            if (task_.is_ended())
                return;
            if (queued_sync) {
                queued_sync->wait();
                return;
            }
            task_.await_task();
        }

        bool wait_until_impl(fast_task::time_point time) {
            if (task_.is_ended())
                return true;
            if (queued_sync)
                return queued_sync->wait_until(time);
            return task_.await_task_until(time);
        }

    public:
        future() = default;
        ~future() = default;

        template <class FN>
        static std::shared_ptr<future> start(FN&& fn, scheduler::worker_pool* pool = nullptr)
            requires std::is_same_v<std::invoke_result_t<FN>, void>
        {
            std::shared_ptr<future> future_ = std::make_shared<future>();
            future_->task_ = task::create(
                [fn = std::forward<FN>(fn), weak_future = std::weak_ptr<future>(future_)]() mutable {
                    fn();
                    if (auto self = weak_future.lock())
                        self->has_result = true;
                },
                [weak_future = std::weak_ptr<future>(future_)](const std::exception_ptr& ex) {
                    if (auto self = weak_future.lock())
                        self->ex_ptr = ex;
                }
            );
            if (pool)
                pool->bind(future_->task_);
            scheduler::start(future_->task_);
            return future_;
        }

        template <class FN>
        static std::shared_ptr<future> start(fast_task::queue& queue, FN&& fn, scheduler::worker_pool* pool = nullptr)
            requires std::is_same_v<std::invoke_result_t<FN>, void>
        {
            std::shared_ptr<future> future_ = std::make_shared<future>();
            auto sync = std::make_shared<detail::queued_future_sync>();
            future_->queued_sync = sync;
            future_->task_ = task::create(
                [fn = std::forward<FN>(fn), weak_future = std::weak_ptr<future>(future_)]() mutable {
                    fn();
                    if (auto self = weak_future.lock())
                        self->has_result = true;
                },
                [weak_future = std::weak_ptr<future>(future_)](const std::exception_ptr& ex) {
                    if (auto self = weak_future.lock())
                        self->ex_ptr = ex;
                }
            );
            if (pool)
                pool->bind(future_->task_);
            queue.add(future_->task_);
            future_->task_.callback(task::create([sync = std::move(sync)]() {
                sync->signal();
            }));
            return future_;
        }

        template <class FN>
        std::shared_ptr<future<std::invoke_result_t<FN>>> chain(FN&& fn, scheduler::worker_pool* pool = nullptr) &;

        template <class FN>
        std::shared_ptr<future<std::invoke_result_t<FN>>> chain(FN&& fn, scheduler::worker_pool* pool = nullptr) &&;

        static std::shared_ptr<future> make_ready();
        void get();
        void take();

        template <class FN>
        void when_ready(FN&& fn)
            requires std::is_same_v<std::invoke_result_t<FN, future&>, void>
        {
            if (task_.is_ended())
                fn(*this);
            else
                task_.callback(task::create([fut = this->shared_from_this(), fn = std::forward<FN>(fn)]() mutable {
                    fn(*fut);
                }));
        }

        template <class FN>
        void when_ready(FN&& fn)
            requires std::is_invocable_v<FN>
        {
            if (task_.is_ended())
                fn();
            else
                task_.callback(task::create([fn = std::forward<FN>(fn)]() mutable {
                    fn();
                }));
        }

        void callback(const task& task);
        bool is_ready();
        void wait();

        template <class Dur_resolution, class Dur_type>
        bool wait_for(std::chrono::duration<Dur_resolution, Dur_type> duration) {
            return wait_until(fast_task::clock::now() + duration);
        }

        bool wait_until(fast_task::time_point time);
        void wait_no_except();

        template <class Dur_resolution, class Dur_type>
        bool wait_for_no_except(std::chrono::duration<Dur_resolution, Dur_type> duration) {
            return wait_until_no_except(fast_task::clock::now() + duration);
        }

        bool wait_until_no_except(fast_task::time_point time);
        bool has_exception() const;
        bool is_canceled() const;
        void cancel();
        bool enter_wait(const task&, enter_state& t);
        bool enter_wait_until(const task&, enter_state& t, fast_task::time_point time);
    };

    template <class T>
    using future_ptr = std::shared_ptr<future<T>>;

    template <class T>
    template <class FN>
    future_ptr<std::invoke_result_t<FN, T>> future<T>::chain(FN&& fn, scheduler::worker_pool* pool) & {
        using ResT = std::invoke_result_t<FN, T>;
        std::shared_ptr<future<ResT>> future_ = std::make_shared<future<ResT>>();
        future_->task_ = task::create(
            [fn = std::forward<FN>(fn), weak_future = std::weak_ptr<future<ResT>>(future_), prev_future = this->shared_from_this()]() mutable {
                if constexpr (std::is_same_v<ResT, void>) {
                    fn(prev_future->get());
                    if (auto self = weak_future.lock())
                        self->has_result = true;
                } else {
                    auto result = std::make_optional<ResT>(fn(prev_future->get()));
                    if (auto self = weak_future.lock())
                        self->result.emplace(std::move(*result));
                }
            },
            [weak_future = std::weak_ptr<future<ResT>>(future_)](const std::exception_ptr& ex) {
                if (auto self = weak_future.lock())
                    self->ex_ptr = ex;
            }
        );
        if (pool)
            pool->bind(future_->task_);
        callback(future_->task_);
        return future_;
    }

    template <class T>
    template <class FN>
    future_ptr<std::invoke_result_t<FN, T>> future<T>::chain(FN&& fn, scheduler::worker_pool* pool) && {
        using ResT = std::invoke_result_t<FN, T>;
        std::shared_ptr<future<ResT>> future_ = std::make_shared<future<ResT>>();
        future_->task_ = task::create(
            [fn = std::forward<FN>(fn), weak_future = std::weak_ptr<future<ResT>>(future_), prev_future = this->shared_from_this()]() mutable {
                if constexpr (std::is_same_v<ResT, void>) {
                    fn(prev_future->take());
                    if (auto self = weak_future.lock())
                        self->has_result = true;
                } else {
                    auto result = std::make_optional<ResT>(fn(prev_future->take()));
                    if (auto self = weak_future.lock())
                        self->result.emplace(std::move(*result));
                }
            },
            [weak_future = std::weak_ptr<future<ResT>>(future_)](const std::exception_ptr& ex) {
                if (auto self = weak_future.lock())
                    self->ex_ptr = ex;
            }
        );
        if (pool)
            pool->bind(future_->task_);
        callback(future_->task_);
        return future_;
    }

    template <class FN>
    future_ptr<std::invoke_result_t<FN>> future<void>::chain(FN&& fn, scheduler::worker_pool* pool) & {
        using ResT = std::invoke_result_t<FN>;
        std::shared_ptr<future<ResT>> future_ = std::make_shared<future<ResT>>();
        future_->task_ = task::create(
            [fn = std::forward<FN>(fn), weak_future = std::weak_ptr<future<ResT>>(future_), prev_future = this->shared_from_this()]() mutable {
                prev_future->get();
                if constexpr (std::is_same_v<ResT, void>) {
                    fn();
                    if (auto self = weak_future.lock())
                        self->has_result = true;
                } else {
                    auto result = std::make_optional<ResT>(fn());
                    if (auto self = weak_future.lock())
                        self->result.emplace(std::move(*result));
                }
            },
            [weak_future = std::weak_ptr<future<ResT>>(future_)](const std::exception_ptr& ex) {
                if (auto self = weak_future.lock())
                    self->ex_ptr = ex;
            }
        );
        if (pool)
            pool->bind(future_->task_);
        callback(future_->task_);
        return future_;
    }

    template <class FN>
    future_ptr<std::invoke_result_t<FN>> future<void>::chain(FN&& fn, scheduler::worker_pool* pool) && {
        using ResT = std::invoke_result_t<FN>;
        std::shared_ptr<future<ResT>> future_ = std::make_shared<future<ResT>>();
        future_->task_ = task::create(
            [fn = std::forward<FN>(fn), weak_future = std::weak_ptr<future<ResT>>(future_), prev_future = this->shared_from_this()]() mutable {
                prev_future->get();
                if constexpr (std::is_same_v<ResT, void>) {
                    fn();
                    if (auto self = weak_future.lock())
                        self->has_result = true;
                } else {
                    auto result = std::make_optional<ResT>(fn());
                    if (auto self = weak_future.lock())
                        self->result.emplace(std::move(*result));
                }
            },
            [weak_future = std::weak_ptr<future<ResT>>(future_)](const std::exception_ptr& ex) {
                if (auto self = weak_future.lock())
                    self->ex_ptr = ex;
            }
        );
        if (pool)
            pool->bind(future_->task_);
        callback(future_->task_);
        return future_;
    }

    namespace future_tool {
        template <class T, class FN>
        future_ptr<void> for_each(T& container, fast_task::queue& queue, FN&& fn) {
            if (container.empty())
                return future<void>::make_ready();
            std::vector<future_ptr<void>> futures;
            futures.reserve(container.size());
            for (auto& item : container)
                futures.push_back(future<void>::start(queue, [item, fn]() { fn(item); }));

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
        future_ptr<void> for_each(T& container, FN&& fn) {
            if (container.empty())
                return future<void>::make_ready();
            std::vector<future_ptr<void>> futures;
            futures.reserve(container.size());
            for (auto& item : container)
                futures.push_back(future<void>::start([item, fn]() { fn(item); }));

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
        future_ptr<void> for_each_move(T&& container, FN&& fn) {
            if (container.empty())
                return future<void>::make_ready();
            std::vector<future_ptr<void>> futures;
            futures.reserve(container.size());
            for (auto&& item : container)
                futures.push_back(future<void>::start([it = std::move(item), fn]() mutable {
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

        template <class T, class FN>
        future_ptr<void> for_each_move(T&& container, fast_task::queue& queue, FN&& fn) {
            if (container.empty())
                return future<void>::make_ready();
            std::vector<future_ptr<void>> futures;
            futures.reserve(container.size());
            for (auto&& item : container)
                futures.push_back(future<void>::start(queue, [it = std::move(item), fn]() mutable {
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

        template <class T, class FN>
        void for_each_wait(T& container, fast_task::queue& queue, FN&& fn) {
            if (container.empty())
                return;
            std::vector<future_ptr<void>> futures;
            futures.reserve(container.size());
            try {
                for (auto& item : container)
                    futures.push_back(future<void>::start(queue, [&item, &fn]() { fn(item); }));

                for (auto& future_ : futures)
                    future_->wait();
            } catch (...) {
                for (auto& future_ : futures)
                    future_->cancel();
                for (auto& future_ : futures)
                    future_->wait_no_except();
                throw;
            }
        }

        template <class T, class FN>
        void for_each_wait(T& container, FN&& fn) {
            if (container.empty())
                return;
            std::vector<future_ptr<void>> futures;
            futures.reserve(container.size());
            try {
                for (auto& item : container)
                    futures.push_back(future<void>::start([&item, &fn]() { fn(item); }));

                for (auto& future_ : futures)
                    future_->wait();
            } catch (...) {
                for (auto& future_ : futures)
                    future_->cancel();
                for (auto& future_ : futures)
                    future_->wait_no_except();
                throw;
            }
        }

        template <class Result, class T, class FN>
        std::vector<Result> process(const T& container, FN&& fn) {
            if (container.empty())
                return {};

            std::vector<future_ptr<Result>> futures;
            futures.reserve(container.size());
            for (auto& item : container)
                futures.push_back(future<Result>::start([item, fn = fn]() mutable { return fn(item); }));

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

        template <class Result, class T, class FN>
        std::vector<Result> process(const T& container, fast_task::queue& queue, FN&& fn) {
            if (container.empty())
                return {};

            std::vector<future_ptr<Result>> futures;
            futures.reserve(container.size());
            for (auto& item : container)
                futures.push_back(future<Result>::start(queue, [item, fn = fn]() mutable { return fn(item); }));

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

        template <class Ret>
        future_ptr<std::vector<Ret>> accumulate(const std::vector<future_ptr<Ret>>& futures) {
            if (futures.empty())
                return future<std::vector<Ret>>::make_ready({});
            return future<std::vector<Ret>>::start([fut = futures] {
                std::vector<Ret> res;
                res.resize(fut.size());
                for (size_t pos = 0; pos < fut.size(); ++pos) {
                    if (fut[pos])
                        res[pos] = fut[pos]->take();
                }
                return res;
            });
        }

        template <class Ret>
        future_ptr<std::vector<Ret>> accumulate(fast_task::queue& queue, const std::vector<future_ptr<Ret>>& futures) {
            if (futures.empty())
                return future<std::vector<Ret>>::make_ready({});
            return future<std::vector<Ret>>::start(queue, [fut = futures] {
                std::vector<Ret> res;
                res.resize(fut.size());
                for (size_t pos = 0; pos < fut.size(); ++pos) {
                    if (fut[pos])
                        res[pos] = fut[pos]->take();
                }
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
                for (size_t pos = 0; pos < fut.size(); ++pos) {
                    if (fut[pos])
                        res[pos] = fut[pos]->take();
                }
                return res;
            });
        }

        template <class Ret>
        future_ptr<std::vector<Ret>> accumulate(fast_task::queue& queue, std::vector<future_ptr<Ret>>&& futures) {
            if (futures.empty())
                return future<std::vector<Ret>>::make_ready({});
            return future<std::vector<Ret>>::start(queue, [fut = std::move(futures)] {
                std::vector<Ret> res;
                res.resize(fut.size());
                for (size_t pos = 0; pos < fut.size(); ++pos) {
                    if (fut[pos])
                        res[pos] = fut[pos]->take();
                }
                return res;
            });
        }

        inline FT_API future_ptr<void> combine_all(const std::vector<future_ptr<void>>& futures) {
            if (futures.empty())
                return future<void>::make_ready();
            std::vector<future_ptr<void>> fut = {futures.begin(), futures.end()};
            return future<void>::start([fut = std::move(fut)] {
                for (auto& future_ : fut)
                    if (future_)
                        future_->wait();
            });
        }

        inline FT_API future_ptr<void> combine_all(fast_task::queue& queue, const std::vector<future_ptr<void>>& futures) {
            if (futures.empty())
                return future<void>::make_ready();
            std::vector<future_ptr<void>> fut = {futures.begin(), futures.end()};
            return future<void>::start(queue, [fut = std::move(fut)] {
                for (auto& future_ : fut)
                    if (future_)
                        future_->wait();
            });
        }

        inline FT_API future_ptr<void> combine_all(std::vector<future_ptr<void>>&& futures) {
            if (futures.empty())
                return future<void>::make_ready();
            return future<void>::start([fut = std::move(futures)] {
                for (auto& future_ : fut)
                    if (future_)
                        future_->wait();
            });
        }

        inline FT_API future_ptr<void> combine_all(fast_task::queue& queue, std::vector<future_ptr<void>>&& futures) {
            if (futures.empty())
                return future<void>::make_ready();
            return future<void>::start(queue, [fut = std::move(futures)] {
                for (auto& future_ : fut)
                    if (future_)
                        future_->wait();
            });
        }

        template <class T>
        void wait_all(T&& futures) {
            for (auto& future_ : futures)
                if (future_)
                    future_->wait();
        }
    }

    template <class T>
    auto make_ready_future(T&& value) {
        return future<std::remove_reference_t<std::remove_cv_t<T>>>::make_ready(std::forward<T>(value));
    }

    #if __cplusplus >= 202002
    namespace detail {
        template <class T>
        struct future_mov_result_awaiter {
            enter_state state;
            future_ptr<T> t;

            bool await_ready() noexcept {
                return !t || t->is_ready();
            }

            template <class Promise>
            bool await_suspend(std::coroutine_handle<Promise> h) {
                if constexpr (std::derived_from<Promise, task_promise_base>) {
                    return !t->enter_wait(h.promise().task_object, state);
                } else {
                    static task_vtable vt = {
                        nullptr, //no special treatment for the on_await
                        nullptr, //no special treatment for the on_cancel, the flag set automatically
                        [](void* handle_addr) {
                            std::coroutine_handle<>::from_address(handle_addr).resume();
                        },
                        nullptr,
                        nullptr,
                        false
                    };
                    auto bridge_task = fast_task::task(
                        h.address(),
                        &vt,
                        false,
                        true
                    );
                    if (!t || t->is_ready())
                        return false;
                    t->callback(bridge_task);
                    return true;
                }
            }

            auto await_resume() {
                return t->take();
            }
        };

        template <class T>
        struct future_cop_result_awaiter {
            enter_state state;
            future_ptr<T> t;

            bool await_ready() noexcept {
                return !t || t->is_ready();
            }

            template <class Promise>
            bool await_suspend(std::coroutine_handle<Promise> h) {
                if constexpr (std::derived_from<Promise, task_promise_base>) {
                    return !t->enter_wait(h.promise().task_object, state);
                } else {
                    static task_vtable vt = {
                        nullptr, //no special treatment for the on_await
                        nullptr, //no special treatment for the on_cancel, the flag set automatically
                        [](void* handle_addr) {
                            std::coroutine_handle<>::from_address(handle_addr).resume();
                        },
                        nullptr,
                        nullptr,
                        false
                    };
                    auto bridge_task = fast_task::task(
                        h.address(),
                        &vt,
                        false,
                        true
                    );
                    if (!t || t->is_ready())
                        return false;
                    t->callback(bridge_task);
                    return true;
                }
            }

            auto await_resume() {
                return t->get();
            }
        };
    }

    template <class T>
    inline auto operator co_await(future_ptr<T>&& t) noexcept {
        return detail::future_mov_result_awaiter{{}, std::move(t)};
    }

    template <class T>
    inline auto operator co_await(const future_ptr<T>& t) noexcept {
        return detail::future_cop_result_awaiter{{}, t};
    }
    #endif
}
#endif
