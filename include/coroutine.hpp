// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_COROUTINE
#define FAST_TASK_COROUTINE
#include "shared.hpp"
#include "task.hpp"

namespace fast_task {
    template <class T>
    struct task_promise final : public task_promise_base {
        task_promise() noexcept {}

        ~task_promise() {}

        std::shared_ptr<task> get_return_object() {
            auto h_promise = std::coroutine_handle<task_promise<T>>::from_promise(*this);

            std::coroutine_handle<> h_frame = h_promise;

            auto on_start = [](void* handle_addr) {
                auto h = std::coroutine_handle<>::from_address(handle_addr);
                h.resume();
            };

            auto on_destruct = [](void* handle_addr) {
                auto h = std::coroutine_handle<>::from_address(handle_addr);
                h.destroy();
            };

            task_object = std::make_shared<task>(
                h_frame.address(),
                on_start,
                [](void* handle_addr) {}, //no special treatment for the on_await
                [](void* handle_addr) {}, //no special treatment for the on_cancel, the flag set automatically
                on_destruct,
                true, //coroutines could yield
                true  //the coroutine is stackless
            );
            return task_object;
        }

        void unhandled_exception() noexcept {
            results = std::current_exception();
        }

        template <class Ret>
            requires std::is_constructible_v<T, Ret&&>
        void return_value(Ret&& val) noexcept(std::is_nothrow_constructible_v<T, Ret&&>) {
            results = val;
        }

        T& result() & {
            return std::visit(
                [](auto& it) -> T& {
                    using GotType = std::decay_t<decltype(it)>;
                    if constexpr (std::is_same_v<GotType, T>)
                        return it;
                    else if constexpr (std::is_same_v<GotType, std::exception_ptr>)
                        std::rethrow_exception(it);
                    else
                        throw std::runtime_error("The coroutine returned noting");
                },
                results
            );
        }

        using r_val = std::conditional_t<std::is_arithmetic_v<T> || std::is_pointer_v<T>, T, T&&>;

        r_val result() && {
            return std::move(
                std::visit(
                    [](auto& it) -> T& {
                        using GotType = std::decay_t<decltype(it)>;
                        if constexpr (std::is_same_v<GotType, T>)
                            return it;
                        else if constexpr (std::is_same_v<GotType, std::exception_ptr>)
                            std::rethrow_exception(it);
                        else
                            throw std::runtime_error("The coroutine returned noting");
                    },
                    results
                )
            );
        }

    private:
        struct FT_API no_result {};

        std::variant<T, std::exception_ptr, no_result> results = no_result{};
    };

    template <class T>
    struct task_promise<T&> final : public task_promise_base {
        task_promise() noexcept {}

        ~task_promise() {}

        std::shared_ptr<task> get_return_object() {
            auto h_promise = std::coroutine_handle<task_promise<T&>>::from_promise(*this);

            std::coroutine_handle<> h_frame = h_promise;

            auto on_start = [](void* handle_addr) {
                auto h = std::coroutine_handle<>::from_address(handle_addr);
                h.resume();
            };

            auto on_destruct = [](void* handle_addr) {
                auto h = std::coroutine_handle<>::from_address(handle_addr);
                h.destroy();
            };

            task_object = std::make_shared<task>(
                h_frame.address(),
                on_start,
                [](void* handle_addr) {}, //no special treatment for the on_await
                [](void* handle_addr) {}, //no special treatment for the on_cancel, the flag set automatically
                on_destruct,
                true, //coroutines could yield
                true  //the coroutine is stackless
            );
            return task_object;
        }

        void unhandled_exception() noexcept {
            results = std::current_exception();
        }

        template <class Ret>
            requires std::is_constructible_v<T, Ret&&>
        void return_value(Ret&& val) noexcept(std::is_nothrow_constructible_v<T, Ret&&>) {
            results.emplace(std::move(val));
        }

        T& result() {
            return std::visit(
                [](auto& it) -> T& {
                    using GotType = std::decay_t<decltype(it)>;
                    if constexpr (std::is_same_v<GotType, T>)
                        return it;
                    else if constexpr (std::is_same_v<GotType, std::exception_ptr>)
                        std::rethrow_exception(it);
                    else
                        throw std::runtime_error("The coroutine returned noting");
                },
                results
            );
        }

    private:
        struct FT_API no_result {};

        std::variant<T, std::exception_ptr, no_result> results = no_result{};
    };

    template <>
    struct FT_API task_promise<void> final : public task_promise_base {
        task_promise() noexcept {}

        ~task_promise() {}

        std::shared_ptr<task> get_return_object() {
            auto h_promise = std::coroutine_handle<task_promise<void>>::from_promise(*this);

            std::coroutine_handle<> h_frame = h_promise;

            auto on_start = [](void* handle_addr) {
                auto h = std::coroutine_handle<>::from_address(handle_addr);
                h.resume();
            };

            auto on_destruct = [](void* handle_addr) {
                auto h = std::coroutine_handle<>::from_address(handle_addr);
                h.destroy();
            };

            task_object = std::make_shared<task>(
                h_frame.address(),
                on_start,
                [](void* handle_addr) {}, //no special treatment for the on_await
                [](void* handle_addr) {}, //no special treatment for the on_cancel, the flag set automatically
                on_destruct,
                true, //coroutines could yield
                true  //the coroutine is stackless
            );
            return task_object;
        }

        void unhandled_exception() {
            results = std::current_exception();
        }

        void return_void() noexcept {
            results = has_result{};
        }

        void result() {
            return std::visit(
                [](auto& it) -> void {
                    using GotType = std::decay_t<decltype(it)>;
                    if constexpr (std::is_same_v<GotType, has_result>)
                        ;
                    else if constexpr (std::is_same_v<GotType, std::exception_ptr>)
                        std::rethrow_exception(it);
                    else
                        throw no_return_value{};
                },
                results
            );
        }

    private:
        struct FT_API has_result {};

        struct FT_API no_result {};

        std::variant<has_result, std::exception_ptr, no_result> results = no_result{};
    };

    template <class T>
    class [[nodiscard]] task_coro {
    public:
        using promise_type = fast_task::task_promise<T>;

        std::shared_ptr<fast_task::task> task_handle;

        task_coro(std::shared_ptr<task> t) : task_handle(std::move(t)) {}

        task_coro(task_coro&&) noexcept = default;
        task_coro& operator=(task_coro&&) noexcept = default;

        task_coro(const task_coro&) = delete;
        task_coro& operator=(const task_coro&) = delete;

        std::shared_ptr<fast_task::task> operator->() const {
            return task_handle;
        }

        operator std::shared_ptr<fast_task::task>() const {
            return task_handle;
        }

        std::shared_ptr<fast_task::task> get_task() const {
            return task_handle;
        }

        auto operator co_await() const& noexcept {
            struct result_awaiter {
                std::shared_ptr<fast_task::task> task_handle;

                bool await_ready() noexcept {
                    return task_handle->is_ended();
                }

                bool await_suspend(std::coroutine_handle<> h) {
                    auto on_start_resume = [](void* handle_addr) {
                        auto awaiting_handle = std::coroutine_handle<>::from_address(handle_addr);
                        awaiting_handle.resume();
                    };

                    auto on_nop = [](void* handle_addr) {};

                    auto bridge_task = std::make_shared<fast_task::task>(
                        h.address(),
                        on_start_resume,
                        on_nop,
                        on_nop,
                        on_nop,
                        false,
                        true
                    );
                    if (task_handle->is_ended())
                        return false;
                    task_handle->callback(bridge_task);
                    return true;
                }

                T await_resume() {
                    if constexpr (!std::is_same_v<T, void>) {
                        void* handle_address = nullptr;
                        task_handle->access_dummy([&](void* data) {
                            handle_address = data;
                        });

                        if (!handle_address)
                            throw std::runtime_error("Coroutine task has no valid handle address.");

                        auto handle = std::coroutine_handle<fast_task::task_promise<T>>::from_address(handle_address);
                        fast_task::task_promise<T>& promise = handle.promise();
                        return std::move(promise.result());
                    }
                }
            };

            return result_awaiter{task_handle};
        }
    };

    inline auto operator co_await(std::shared_ptr<task>&& t) noexcept {
        struct FT_API result_awaiter {
            std::shared_ptr<task> t;

            bool await_ready() noexcept {
                return t->is_ended();
            }

            bool await_suspend(std::coroutine_handle<> h) {
                auto on_start_resume = [](void* handle_addr) {
                    auto awaiting_handle = std::coroutine_handle<>::from_address(handle_addr);
                    awaiting_handle.resume();
                };

                auto on_nop = [](void* handle_addr) {};

                auto bridge_task = std::make_shared<fast_task::task>(
                    h.address(),
                    on_start_resume,
                    on_nop,
                    on_nop,
                    on_nop,
                    false,
                    true
                );
                if (t->is_ended())
                    return false;
                t->callback(bridge_task);
                return true;
            }

            void await_resume() {}
        };

        return result_awaiter{t};
    }

    template <class T>
    class task_auto_start_coro : public task_coro<T> {
    public:
        task_auto_start_coro(std::shared_ptr<task> t) : task_coro<T>(std::move(t)) {
            scheduler::start(task_coro<T>::task_handle);
        }

        task_auto_start_coro(task_auto_start_coro&&) noexcept = default;
        task_auto_start_coro& operator=(task_auto_start_coro&&) noexcept = default;

        task_auto_start_coro(const task_auto_start_coro&) = delete;
        task_auto_start_coro& operator=(const task_auto_start_coro&) = delete;
    };
}

namespace fast_task::coroutine {
    template <class T, class FN>
    task_coro<void> async_for_each(T&& container, fast_task::task_query& query, FN&& fn) {
        if (container.empty())
            return [] -> fast_task::task_coro<void> {
                co_return;
            }();
        std::vector<fast_task::task_coro<void>> coros;
        for (auto& item : container) {
            auto cor = [item = std::move(item), fn] -> fast_task::task_coro<void> {
                fn(item);
                co_return;
            }();
            query.add(cor);
            coros.emplace_back(cor);
        }

        auto res = [fut = std::move(coros)] -> fast_task::task_coro<void> {
            try {
                for (auto& coro : fut)
                    co_await coro;
            } catch (...) {
                for (auto& coro : fut)
                    coro->notify_cancel();
                throw;
            }
        }();
        query.add(res);
        return res;
    }

    template <class T, class FN>
    task_coro<void> async_for_each(T&& container, FN&& fn) {
        if (container.empty())
            return [] -> fast_task::task_coro<void> {
                co_return;
            }();
        std::vector<fast_task::task_coro<void>> coros;
        for (auto& item : container) {
            auto cor = [item = std::move(item), fn] -> fast_task::task_coro<void> {
                fn(item);
                co_return;
            }();

            fast_task::scheduler::start(cor);
            coros.emplace_back(cor);
        }

        auto res = [fut = std::move(coros)] -> fast_task::task_coro<void> {
            try {
                for (auto& coro : fut)
                    co_await coro;
            } catch (...) {
                for (auto& coro : fut)
                    coro->notify_cancel();
                throw;
            }
        }();
        fast_task::scheduler::start(res);
        return res;
    }

    template <class T, class FN>
    void for_each(T& container, fast_task::task_query& query, FN&& fn) {
        if (container.empty())
            return;
        std::vector<fast_task::task_coro<void>> coros;
        for (auto& item : container) {
            auto cor = [](auto& item, auto& fn) -> fast_task::task_coro<void> {
                fn(item);
                co_return;
            }(item, fn);
            query.add(cor);
            coros.emplace_back(cor);
        }

        try {
            for (auto& coro : coros)
                coro->await_task();
        } catch (...) {
            for (auto& coro : coros)
                coro->notify_cancel();
            throw;
        }
    }

    template <class T, class FN>
    void for_each(T& container, FN&& fn) {
        if (container.empty())
            return;
        std::vector<fast_task::task_coro<void>> coros;
        for (auto& item : container) {
            auto cor = [](auto& item, auto& fn) -> fast_task::task_coro<void> {
                fn(item);
                co_return;
            }(item, fn);
            fast_task::scheduler::start(cor);
            coros.emplace_back(cor);
        }

        try {
            for (auto& coro : coros)
                coro->await_task();
        } catch (...) {
            for (auto& coro : coros)
                coro->notify_cancel();
            throw;
        }
    }

    template <class T>
    task_auto_start_coro<void> wait_all(T&& coros) {
        for (auto& coro : coros)
            co_await coro;
        co_return;
    }

    template <class T>
    void wait_all_blocking(T& coros) {
        if (coros.empty())
            return;

        // Start all tasks first
        for (auto& coro : coros)
            fast_task::scheduler::start(coro);

        // Now, block and wait for each one
        try {
            for (auto& coro : coros)
                coro->await_task(); // This blocks
        } catch (...) {
            for (auto& coro : coros)
                coro->notify_cancel();
            throw;
        }
    }
}

template <class T, class... Args>
struct std::coroutine_traits<fast_task::task_coro<T>, Args...> {
    using promise_type = typename fast_task::task_coro<T>::promise_type;
};

template <class T, class... Args>
struct std::coroutine_traits<fast_task::task_auto_start_coro<T>, Args...> {
    using promise_type = typename fast_task::task_auto_start_coro<T>::promise_type;
};

#endif