// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_INCLUDE_COROUTINE_CORE
#define FAST_TASK_INCLUDE_COROUTINE_CORE
#include "../exceptions.hpp"
#include "../shared.hpp"
#include "../task/task.hpp"
#include "promise.hpp"
#include <concepts>
#include <variant>

namespace fast_task {
    namespace detail {
        struct FT_API task_result_awaiter {
            enter_state state;
            task t;

            bool await_ready() noexcept {
                return t.is_ended();
            }

            template <class Promise>
            bool await_suspend(std::coroutine_handle<Promise> h) {
                if constexpr (std::derived_from<Promise, task_promise_base>) {
                    return !t.enter_wait(h.promise().task_object, state);
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
                    if (t.is_ended())
                        return false;
                    t.callback(bridge_task);
                    return true;
                }
            }

            void await_resume() {}
        };
    }

    template <class T>
    struct task_promise final : public task_promise_base {
        task_promise() noexcept {}

        ~task_promise() {}

        task get_return_object() {
            auto h_promise = std::coroutine_handle<task_promise<T>>::from_promise(*this);

            std::coroutine_handle<> h_frame = h_promise;

            static task_vtable vt = {
                nullptr, //no special treatment for the on_await
                nullptr, //no special treatment for the on_cancel, the flag set automatically
                [](void* handle_addr) {
                    std::coroutine_handle<>::from_address(handle_addr).resume();
                },
                nullptr,
                [](void* handle_addr) {
                    std::coroutine_handle<>::from_address(handle_addr).destroy();
                },
                false
            };

            task_object = task(
                h_frame.address(),
                &vt,
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
                        throw std::runtime_error("The coroutine returned nothing");
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
                            throw std::runtime_error("The coroutine returned nothing");
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

        task get_return_object() {
            auto h_promise = std::coroutine_handle<task_promise<T&>>::from_promise(*this);

            std::coroutine_handle<> h_frame = h_promise;

            static task_vtable vt = {
                nullptr, //no special treatment for the on_await
                nullptr, //no special treatment for the on_cancel, the flag set automatically
                [](void* handle_addr) {
                    std::coroutine_handle<>::from_address(handle_addr).resume();
                },
                nullptr,
                [](void* handle_addr) {
                    std::coroutine_handle<>::from_address(handle_addr).destroy();
                },
                false
            };

            task_object = task(
                h_frame.address(),
                &vt,
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
                        throw std::runtime_error("The coroutine returned nothing");
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

        task get_return_object() {
            auto h_promise = std::coroutine_handle<task_promise<void>>::from_promise(*this);

            std::coroutine_handle<> h_frame = h_promise;

            static task_vtable vt = {
                nullptr, //no special treatment for the on_await
                nullptr, //no special treatment for the on_cancel, the flag set automatically
                [](void* handle_addr) {
                    std::coroutine_handle<>::from_address(handle_addr).resume();
                },
                nullptr,
                [](void* handle_addr) {
                    std::coroutine_handle<>::from_address(handle_addr).destroy();
                },
                false
            };

            task_object = task(
                h_frame.address(),
                &vt,
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
        struct result_awaiter {
            enter_state state;
            fast_task::task task_handle;

            bool await_ready() noexcept {
                return task_handle.is_ended();
            }

            template <class Promise>
            bool await_suspend(std::coroutine_handle<Promise> h) {
                if constexpr (std::derived_from<Promise, task_promise_base>) {
                    return !task_handle.enter_wait(h.promise().task_object, state);
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
                    if (task_handle.is_ended())
                        return false;
                    task_handle.callback(bridge_task);
                    return true;
                }
            }

            auto await_resume() {
                void* handle_address = nullptr;
                task_handle.access_dummy([&](void* data) {
                    handle_address = data;
                });

                if (!handle_address)
                    throw std::runtime_error("Coroutine task has no valid handle address.");

                auto handle = std::coroutine_handle<fast_task::task_promise<T>>::from_address(handle_address);
                fast_task::task_promise<T>& promise = handle.promise();
                if constexpr (!std::is_same_v<T, void>) {
                    return std::move(promise.result());
                } else {
                    promise.result();
                }
            }
        };

    public:
        using promise_type = fast_task::task_promise<T>;

        fast_task::task task_handle;

        task_coro(task t) : task_handle(std::move(t)) {}

        task_coro(task_coro&&) noexcept = default;
        task_coro& operator=(task_coro&&) noexcept = default;

        task_coro(const task_coro&) = delete;
        task_coro& operator=(const task_coro&) = delete;

        const fast_task::task* operator->() const {
            return &task_handle;
        }

        operator fast_task::task() const {
            return task_handle;
        }

        fast_task::task get_task() const {
            return task_handle;
        }

        auto operator co_await() const& noexcept {
            return result_awaiter{{}, task_handle};
        }

        template <class U = T>
        U sync_get() const {
            task_handle.await_task();
            if constexpr (!std::is_same_v<U, void>) {
                T result{};
                task_handle.access_dummy([&result](void* addr) {
                    auto h = std::coroutine_handle<fast_task::task_promise<T>>::from_address(addr);
                    result = h.promise().result();
                });
                return result;
            }
        }
    };

    inline auto operator co_await(const task& t) noexcept {
        return detail::task_result_awaiter{{}, t};
    }

    template <class T>
    class task_auto_start_coro : public task_coro<T> {
    public:
        task_auto_start_coro(task t) : task_coro<T>(std::move(t)) {
            scheduler::start(task_coro<T>::task_handle);
        }

        task_auto_start_coro(task_auto_start_coro&&) noexcept = default;
        task_auto_start_coro& operator=(task_auto_start_coro&&) noexcept = default;

        task_auto_start_coro(const task_auto_start_coro&) = delete;
        task_auto_start_coro& operator=(const task_auto_start_coro&) = delete;
    };
}

template <class T, class... Args>
struct std::coroutine_traits<fast_task::task_coro<T>, Args...> {
    using promise_type = typename fast_task::task_coro<T>::promise_type;
};

template <class T, class... Args>
struct std::coroutine_traits<fast_task::task_auto_start_coro<T>, Args...> {
    using promise_type = typename fast_task::task_auto_start_coro<T>::promise_type;
};

#endif /* FAST_TASK_INCLUDE_COROUTINE_CORE */
