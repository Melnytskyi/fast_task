// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_INCLUDE_COROUTINE_CORE
#define FAST_TASK_INCLUDE_COROUTINE_CORE
#include "../exceptions.hpp"
#include "../shared.hpp"
#include "../task/scheduler.hpp"
#include "../task/task.hpp"
#include "promise.hpp"
#include <concepts>
#include <memory>
#include <optional>
#include <variant>

namespace fast_task {
    namespace detail {
        template <class PromiseType>
        void coro_resume_thunk(void* handle_addr) {
            auto h = std::coroutine_handle<PromiseType>::from_address(handle_addr);
            auto& p = h.promise();
            struct task_object_guard {
                task_promise_base& promise;

                ~task_object_guard() noexcept {
                    promise.task_object.reset();
                }
            };
            p.task_object = scheduler::current_context_task();
            task_object_guard guard{p};
            h.resume();
        }

        struct FT_API task_result_awaiter {
            enter_state state;
            task t;

            bool await_ready() noexcept {
                return !t || t.is_ended();
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
                    if (!t || t.is_ended())
                        return false;
                    t.callback(bridge_task);
                    t.start();
                    return true;
                }
            }

            void await_resume() {}
        };
    }

    template <class T>
    struct task_promise : public task_promise_base {
        task_promise() noexcept {}

        ~task_promise() {}

        template <class DerivedPromise>
        static task create_task_for(std::coroutine_handle<DerivedPromise> h_promise) {
            std::coroutine_handle<> h_frame = h_promise;

            static task_vtable vt = {
                nullptr, //no special treatment for the on_await
                nullptr, //no special treatment for the on_cancel, the flag set automatically
                &detail::coro_resume_thunk<DerivedPromise>,
                nullptr,
                [](void* handle_addr) {
                    std::coroutine_handle<>::from_address(handle_addr).destroy();
                },
                false
            };

            return task(
                h_frame.address(),
                &vt,
                true, //coroutines could yield
                true  //the coroutine is stackless
            );
        }

        task get_return_object() {
            return create_task_for(std::coroutine_handle<task_promise<T>>::from_promise(*this));
        }

        void unhandled_exception() noexcept {
            results.template emplace<1>(std::current_exception());
        }

        template <class Ret>
            requires std::is_constructible_v<T, Ret&&>
        void return_value(Ret&& val) noexcept(std::is_nothrow_constructible_v<T, Ret&&>) {
            results.template emplace<0>(std::forward<Ret>(val));
        }

        T& result() & {
            if (results.index() == 0)
                return std::get<0>(results);
            if (results.index() == 1)
                std::rethrow_exception(std::get<1>(results));
            throw no_return_value{};
        }

        using r_val = std::conditional_t<std::is_arithmetic_v<T> || std::is_pointer_v<T>, T, T&&>;

        r_val result() && {
            if (results.index() == 0)
                return std::move(std::get<0>(results));
            if (results.index() == 1)
                std::rethrow_exception(std::get<1>(results));
            throw no_return_value{};
        }

    private:
        struct FT_API no_result {};

        std::variant<T, std::exception_ptr, no_result> results = no_result{};
    };

    template <class T>
    struct task_promise<T&> : public task_promise_base {
        task_promise() noexcept {}

        ~task_promise() {}

        template <class DerivedPromise>
        static task create_task_for(std::coroutine_handle<DerivedPromise> h_promise) {
            std::coroutine_handle<> h_frame = h_promise;

            static task_vtable vt = {
                nullptr, //no special treatment for the on_await
                nullptr, //no special treatment for the on_cancel, the flag set automatically
                &detail::coro_resume_thunk<DerivedPromise>,
                nullptr,
                [](void* handle_addr) {
                    std::coroutine_handle<>::from_address(handle_addr).destroy();
                },
                false
            };

            return task(
                h_frame.address(),
                &vt,
                true, //coroutines could yield
                true  //the coroutine is stackless
            );
        }

        task get_return_object() {
            return create_task_for(std::coroutine_handle<task_promise<T&>>::from_promise(*this));
        }

        void unhandled_exception() noexcept {
            results.template emplace<1>(std::current_exception());
        }

        void return_value(T& val) noexcept {
            results.template emplace<0>(std::addressof(val));
        }

        T& result() {
            if (results.index() == 0)
                return *std::get<0>(results);
            if (results.index() == 1)
                std::rethrow_exception(std::get<1>(results));
            throw no_return_value{};
        }

    private:
        struct FT_API no_result {};

        std::variant<T*, std::exception_ptr, no_result> results = no_result{};
    };

    template <>
    struct FT_API task_promise<void> : public task_promise_base {
        task_promise() noexcept {}

        ~task_promise() {}

        template <class DerivedPromise>
        static task create_task_for(std::coroutine_handle<DerivedPromise> h_promise) {
            std::coroutine_handle<> h_frame = h_promise;

            static task_vtable vt = {
                nullptr, //no special treatment for the on_await
                nullptr, //no special treatment for the on_cancel, the flag set automatically
                &detail::coro_resume_thunk<DerivedPromise>,
                nullptr,
                [](void* handle_addr) {
                    std::coroutine_handle<>::from_address(handle_addr).destroy();
                },
                false
            };

            return task(
                h_frame.address(),
                &vt,
                true, //coroutines could yield
                true  //the coroutine is stackless
            );
        }

        task get_return_object() {
            return create_task_for(std::coroutine_handle<task_promise<void>>::from_promise(*this));
        }

        void unhandled_exception() noexcept {
            results.template emplace<1>(std::current_exception());
        }

        void return_void() noexcept {
            results.template emplace<0>();
        }

        void result() {
            if (results.index() == 0)
                return;
            if (results.index() == 1)
                std::rethrow_exception(std::get<1>(results));
            throw no_return_value{};
        }

    private:
        struct FT_API has_result {};

        struct FT_API no_result {};

        std::variant<has_result, std::exception_ptr, no_result> results = no_result{};
    };

    template <class T>
    class [[nodiscard]] task_coro {
    protected:
        template <class PromiseType, bool MoveResult>
        struct result_awaiter_impl {
            enter_state state;
            fast_task::task task_handle;

            bool await_ready() noexcept {
                return !task_handle || task_handle.is_ended();
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
                    if (!task_handle || task_handle.is_ended())
                        return false;
                    task_handle.callback(bridge_task);
                    task_handle.start();
                    return true;
                }
            }

            using return_type = std::conditional_t<
                std::is_same_v<T, void>,
                void,
                std::conditional_t<
                    std::is_reference_v<T>,
                    T,
                    std::conditional_t<MoveResult, T, std::add_lvalue_reference_t<const T>>
                >
            >;

            return_type await_resume() {
                void* handle_address = nullptr;
                task_handle.access_dummy([&](void* data) {
                    handle_address = data;
                });

                if (!handle_address)
                    throw no_return_value{};

                auto handle = std::coroutine_handle<PromiseType>::from_address(handle_address);
                PromiseType& promise = handle.promise();
                if constexpr (std::is_same_v<T, void>) {
                    promise.result();
                } else if constexpr (std::is_reference_v<T>) {
                    return promise.result();
                } else if constexpr (MoveResult) {
                    return std::move(promise.result());
                } else {
                    return promise.result();
                }
            }
        };

        template <class PromiseType>
        static T sync_get_impl(const fast_task::task& handle) {
            handle.await_task();
            if constexpr (std::is_same_v<T, void>) {
                handle.access_dummy([](void* addr) {
                    if (!addr)
                        throw no_return_value{};
                    auto h = std::coroutine_handle<PromiseType>::from_address(addr);
                    h.promise().result();
                });
            } else if constexpr (std::is_reference_v<T>) {
                std::remove_reference_t<T>* ptr = nullptr;
                handle.access_dummy([&ptr](void* addr) {
                    if (!addr)
                        throw no_return_value{};
                    auto h = std::coroutine_handle<PromiseType>::from_address(addr);
                    ptr = std::addressof(h.promise().result());
                });
                if (!ptr)
                    throw no_return_value{};
                return *ptr;
            } else {
                std::optional<T> result;
                handle.access_dummy([&result](void* addr) {
                    if (!addr)
                        throw no_return_value{};
                    auto h = std::coroutine_handle<PromiseType>::from_address(addr);
                    if constexpr (std::is_move_constructible_v<T>)
                        result.emplace(std::move(h.promise().result()));
                    else
                        result.emplace(h.promise().result());
                });
                if (!result.has_value())
                    throw no_return_value{};
                return std::move(*result);
            }
        }

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
            return result_awaiter_impl<promise_type, false>{{}, task_handle};
        }

        auto operator co_await() && noexcept {
            return result_awaiter_impl<promise_type, true>{{}, std::move(task_handle)};
        }

        template <class U = T>
        U sync_get() const {
            return sync_get_impl<promise_type>(task_handle);
        }
    };

    inline auto operator co_await(const task& t) noexcept {
        return detail::task_result_awaiter{{}, t};
    }

    template <class T>
    class task_auto_start_coro : public task_coro<T> {
    public:
        struct promise_type : public task_promise<T> {
            task_auto_start_coro<T> get_return_object() {
                task t = task_promise<T>::create_task_for(
                    std::coroutine_handle<promise_type>::from_promise(*this)
                );
                this->task_object = t;
                return task_auto_start_coro<T>{std::move(t)};
            }

            auto initial_suspend() noexcept {
                struct auto_start_awaiter {
                    promise_type& promise;

                    bool await_ready() noexcept {
                        return false;
                    }

                    void await_suspend(std::coroutine_handle<>) {
                        task t = std::move(promise.task_object);
                        if (t)
                            scheduler::start(std::move(t));
                    }

                    void await_resume() noexcept {}
                };

                return auto_start_awaiter{*this};
            }
        };

        task_auto_start_coro(task t) : task_coro<T>(std::move(t)) {}

        task_auto_start_coro(task_auto_start_coro&&) noexcept = default;
        task_auto_start_coro& operator=(task_auto_start_coro&&) noexcept = default;

        task_auto_start_coro(const task_auto_start_coro&) = delete;
        task_auto_start_coro& operator=(const task_auto_start_coro&) = delete;

        auto operator co_await() const& noexcept {
            return typename task_coro<T>::template result_awaiter_impl<promise_type, false>{{}, this->task_handle};
        }

        auto operator co_await() && noexcept {
            return typename task_coro<T>::template result_awaiter_impl<promise_type, true>{{}, std::move(this->task_handle)};
        }

        template <class U = T>
        U sync_get() const {
            return task_coro<T>::template sync_get_impl<promise_type>(this->task_handle);
        }
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
