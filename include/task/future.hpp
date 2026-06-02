// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#pragma once
#ifndef INCLUDE_TASK_FUTURE
    #define INCLUDE_TASK_FUTURE
    #include "fwd.hpp"
    #include "query.hpp"
    #include "scheduler.hpp"
    #include "shared.hpp"
    #include "task.hpp"

namespace fast_task {
    template <class T>
    class future : public std::enable_shared_from_this<future<T>> {
        task task_;
        std::optional<T> result;
        std::exception_ptr ex_ptr;

    public:
        future() = default;
        ~future() = default;

        template <class FN>
        static std::shared_ptr<future> start(FN&& fn, uint16_t bind_id = (uint16_t)-1)
            requires std::is_same_v<std::invoke_result_t<FN>, T>
        {
            std::shared_ptr<future> future_ = std::make_shared<future>();
            future_->task_ = task::create(
                [fn = std::move(fn), future_]() mutable {
                    future_->result = std::make_optional<T>(fn());
                },
                [future_](const std::exception_ptr& ex) {
                    future_->ex_ptr = ex;
                }
            );
            if (bind_id != (uint16_t)-1)
                future_->task_.set_worker_id(bind_id);
            scheduler::start(future_->task_);
            return future_;
        }

        template <class FN>
        static std::shared_ptr<future> start(fast_task::task_query& query, FN&& fn, uint16_t bind_id = (uint16_t)-1)
            requires std::is_same_v<std::invoke_result_t<FN>, T>
        {
            std::shared_ptr<future> future_ = std::make_shared<future>();
            future_->task_ = task::create(
                [fn = std::move(fn), future_]() mutable {
                    future_->result = std::make_optional<T>(fn());
                },
                [future_](const std::exception_ptr& ex) {
                    future_->ex_ptr = ex;
                }
            );
            if (bind_id != (uint16_t)-1)
                future_->task_.set_worker_id(bind_id);
            query.add(future_->task_);
            return future_;
        }

        template <class FN>
        std::shared_ptr<future<std::invoke_result_t<FN, T>>> chain(FN&& fn, uint16_t bind_id = (uint16_t)-1) &;

        template <class FN>
        std::shared_ptr<future<std::invoke_result_t<FN, T>>> chain(FN&& fn, uint16_t bind_id = (uint16_t)-1) &&;

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
            if (!task_.is_ended())
                task_.await_task();
            if (ex_ptr)
                std::rethrow_exception(ex_ptr);
            if (task_.is_cancellation_requested())
                throw std::runtime_error("Task has been canceled. Can not receive result.");
            return *result;
        }

        T take() {
            if (!task_.is_ended())
                task_.await_task();
            if (ex_ptr)
                std::rethrow_exception(ex_ptr);
            if (task_.is_cancellation_requested())
                throw std::runtime_error("Task has been canceled. Can not receive result.");
            return std::move(*result);
        }

        template <class FN>
        void when_ready(FN&& fn)
            requires std::is_same_v<std::invoke_result_t<FN, future&>, void>
        {
            if (task_.is_ended())
                fn(*this);
            else
                task_.callback(task::create([this, fn = std::move(fn)]() mutable {
                    fn(*this);
                }));
        }

        template <class FN>
        void when_ready(FN&& fn)
            requires std::is_invocable_v<FN>
        {
            if (task_.is_ended())
                fn();
            else
                task_.callback(task::create([fn = std::move(fn)]() mutable {
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
            if (!task_.is_ended())
                task_.await_task();
            if (ex_ptr)
                std::rethrow_exception(ex_ptr);
            if (task_.is_cancellation_requested())
                throw std::runtime_error("Task has been canceled. Can not receive result.");
        }

        template <class Dur_resolution, class Dur_type>
        bool wait_for(std::chrono::duration<Dur_resolution, Dur_type> duration) {
            return wait_until(std::chrono::high_resolution_clock::now() + duration);
        }

        bool wait_until(std::chrono::time_point<std::chrono::high_resolution_clock> time) {
            if (!task_.is_ended())
                if (!task_.await_task_until(time))
                    return false;
            if (ex_ptr)
                std::rethrow_exception(ex_ptr);
            if (task_.is_cancellation_requested())
                throw std::runtime_error("Task has been canceled. Can not receive result.");
            return true;
        }

        void wait_no_except() {
            if (!task_.is_ended())
                task_.await_task();
        }

        template <class Dur_resolution, class Dur_type>
        bool wait_for_no_except(std::chrono::duration<Dur_resolution, Dur_type> duration) {
            return wait_until_no_except(std::chrono::high_resolution_clock::now() + duration);
        }

        bool wait_until_no_except(std::chrono::time_point<std::chrono::high_resolution_clock> time) {
            if (!task_.is_ended())
                if (!task_.await_task_until(time))
                    return false;
            return true;
        }

        bool has_exception() const {
            return (bool)ex_ptr;
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

        bool enter_wait_until(const task& t, enter_state& state, std::chrono::high_resolution_clock::time_point time) {
            return task_.enter_wait_until(t, state, time);
        }
    };

    template <>
    class FT_API future<void> : public std::enable_shared_from_this<future<void>> {
        task task_;
        std::exception_ptr ex_ptr;
        bool has_result = false;

    public:
        future() = default;
        ~future() = default;

        template <class FN>
        static std::shared_ptr<future> start(FN&& fn, uint16_t bind_id = (uint16_t)-1)
            requires std::is_same_v<std::invoke_result_t<FN>, void>
        {
            std::shared_ptr<future> future_ = std::make_shared<future>();
            future_->task_ = task::create(
                [fn = std::move(fn), future_]() mutable {
                    fn();
                    future_->has_result = true;
                },
                [future_](const std::exception_ptr& ex) {
                    future_->ex_ptr = ex;
                }
            );
            if (bind_id != (uint16_t)-1)
                future_->task_.set_worker_id(bind_id);
            scheduler::start(future_->task_);
            return future_;
        }

        template <class FN>
        static std::shared_ptr<future> start(fast_task::task_query& query, FN&& fn, uint16_t bind_id = (uint16_t)-1)
            requires std::is_same_v<std::invoke_result_t<FN>, void>
        {
            std::shared_ptr<future> future_ = std::make_shared<future>();
            future_->task_ = task::create(
                [fn = std::move(fn), future_]() mutable {
                    fn();
                    future_->has_result = true;
                },
                [future_](const std::exception_ptr& ex) {
                    future_->ex_ptr = ex;
                }
            );
            if (bind_id != (uint16_t)-1)
                future_->task_.set_worker_id(bind_id);
            query.add(future_->task_);
            return future_;
        }

        template <class FN>
        std::shared_ptr<future<std::invoke_result_t<FN, void>>> chain(FN&& fn, uint16_t bind_id = (uint16_t)-1) &;

        template <class FN>
        std::shared_ptr<future<std::invoke_result_t<FN, void>>> chain(FN&& fn, uint16_t bind_id = (uint16_t)-1) &&;

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
                task_.callback(task::create([this, fn = std::move(fn)]() mutable {
                    fn(*this);
                }));
        }

        template <class FN>
        void when_ready(FN&& fn)
            requires std::is_invocable_v<FN>
        {
            if (task_.is_ended())
                fn();
            else
                task_.callback(task::create([fn = std::move(fn)]() mutable {
                    fn();
                }));
        }

        void callback(const task& task);
        bool is_ready();
        void wait();

        template <class Dur_resolution, class Dur_type>
        bool wait_for(std::chrono::duration<Dur_resolution, Dur_type> duration) {
            return wait_until(std::chrono::high_resolution_clock::now() + duration);
        }

        bool wait_until(std::chrono::time_point<std::chrono::high_resolution_clock> time);
        void wait_no_except();

        template <class Dur_resolution, class Dur_type>
        bool wait_for_no_except(std::chrono::duration<Dur_resolution, Dur_type> duration) {
            return wait_until_no_except(std::chrono::high_resolution_clock::now() + duration);
        }

        bool wait_until_no_except(std::chrono::time_point<std::chrono::high_resolution_clock> time);
        bool has_exception() const;
        bool is_canceled() const;
        void cancel();
        bool enter_wait(const task&, enter_state& t);
        bool enter_wait_until(const task&, enter_state& t, std::chrono::high_resolution_clock::time_point time);
    };

    extern template class FT_API future<void>;

    template <class T>
    using future_ptr = std::shared_ptr<future<T>>;

    template <class T>
    template <class FN>
    future_ptr<std::invoke_result_t<FN, T>> future<T>::chain(FN&& fn, uint16_t bind_id) & {
        using ResT = std::invoke_result_t<FN, T>;
        std::shared_ptr<future> future_ = std::make_shared<future>();
        future_->task_ = task::create(
            [fn = std::move(fn), future_, prev_future = this->shared_from_this()]() mutable {
                if constexpr (std::is_same_v<ResT, void>) {
                    fn(prev_future->get());
                    future_->has_result = true;
                } else
                    future_->result = std::make_optional<ResT>(fn(prev_future->get()));
            },
            [future_](const std::exception_ptr& ex) {
                future_->ex_ptr = ex;
            }
        );
        if (bind_id != (uint16_t)-1)
            future_->task_.set_worker_id(bind_id);
        callback(future_->task_);
        return future_;
    }

    template <class T>
    template <class FN>
    future_ptr<std::invoke_result_t<FN, T>> future<T>::chain(FN&& fn, uint16_t bind_id) && {
        using ResT = std::invoke_result_t<FN, T>;
        std::shared_ptr<future> future_ = std::make_shared<future>();
        future_->task_ = task::create(
            [fn = std::move(fn), future_, prev_future = this->shared_from_this()]() mutable {
                if constexpr (std::is_same_v<ResT, void>) {
                    fn(prev_future->take());
                    future_->has_result = true;
                } else
                    future_->result = std::make_optional<ResT>(fn(prev_future->take()));
            },
            [future_](const std::exception_ptr& ex) {
                future_->ex_ptr = ex;
            }
        );
        if (bind_id != (uint16_t)-1)
            future_->task_.set_worker_id(bind_id);
        callback(future_->task_);
        return future_;
    }

    namespace future_tool {
        template <class T, class FN>
        future_ptr<void> for_each(T& container, fast_task::task_query& query, FN&& fn) {
            if (container.empty())
                return future<void>::make_ready();
            std::vector<future_ptr<void>> futures;
            futures.reserve(container.size());
            for (auto& item : container)
                futures.push_back(future<void>::start(query, [item, fn]() { fn(item); }));

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
        future_ptr<void> for_each_move(T&& container, fast_task::task_query& query, FN&& fn) {
            if (container.empty())
                return future<void>::make_ready();
            std::vector<future_ptr<void>> futures;
            futures.reserve(container.size());
            for (auto&& item : container)
                futures.push_back(future<void>::start(query, [it = std::move(item), fn]() mutable {
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
        void for_each_wait(T& container, fast_task::task_query& query, FN&& fn) {
            if (container.empty())
                return;
            std::vector<future_ptr<void>> futures;
            futures.reserve(container.size());
            for (auto& item : container)
                futures.push_back(future<void>::start(query, [&item, &fn]() { fn(item); }));

            try {
                for (auto& future_ : futures)
                    future_->wait();
            } catch (...) {
                for (auto& future_ : futures)
                    future_->cancel();
                throw;
            }
        }

        template <class T, class FN>
        void for_each_wait(T& container, FN&& fn) {
            if (container.empty())
                return;
            std::vector<future_ptr<void>> futures;
            futures.reserve(container.size());
            for (auto& item : container)
                futures.push_back(future<void>::start([&item, &fn]() { fn(item); }));

            try {
                for (auto& future_ : futures)
                    future_->wait();
            } catch (...) {
                for (auto& future_ : futures)
                    future_->cancel();
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
        std::vector<Result> process(const T& container, fast_task::task_query& query, FN&& fn) {
            if (container.empty())
                return {};

            std::vector<future_ptr<Result>> futures;
            futures.reserve(container.size());
            for (auto& item : container)
                futures.push_back(future<Result>::start(query, [item, fn = fn]() mutable { return fn(item); }));

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
        future_ptr<std::vector<Ret>> accumulate(fast_task::task_query& query, const std::vector<future_ptr<Ret>>& futures) {
            if (futures.empty())
                return future<std::vector<Ret>>::make_ready({});
            return future<std::vector<Ret>>::start(query, [fut = futures] {
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
        future_ptr<std::vector<Ret>> accumulate(fast_task::task_query& query, std::vector<future_ptr<Ret>>&& futures) {
            if (futures.empty())
                return future<std::vector<Ret>>::make_ready({});
            return future<std::vector<Ret>>::start(query, [fut = std::move(futures)] {
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

        inline FT_API future_ptr<void> combine_all(fast_task::task_query& query, const std::vector<future_ptr<void>>& futures) {
            if (futures.empty())
                return future<void>::make_ready();
            std::vector<future_ptr<void>> fut = {futures.begin(), futures.end()};
            return future<void>::start(query, [fut = std::move(fut)] {
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

        inline FT_API future_ptr<void> combine_all(fast_task::task_query& query, std::vector<future_ptr<void>>&& futures) {
            if (futures.empty())
                return future<void>::make_ready();
            return future<void>::start(query, [fut = std::move(futures)] {
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
}
#endif
