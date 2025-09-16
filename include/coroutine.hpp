// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_COROUTINE
#define FAST_TASK_COROUTINE
#include "shared.hpp"
#include "task.hpp"
#include <coroutine>
#include <exception>
#include <type_traits>
#include <variant>

namespace fast_task {
    struct FT_API promise_base {
        struct FT_API initial_start {
            bool await_ready() const noexcept {
                return false;
            }

            void await_suspend(std::coroutine_handle<> aw_coroutine) {
                task::run([aw_coroutine] { aw_coroutine.resume(); });
            }

            void await_resume() noexcept {}
        };

        promise_base() noexcept {}

        auto initial_suspend() noexcept {
            return initial_start{};
        }

        std::suspend_always final_suspend() noexcept {
            if (v_continuation)
                task::run([aw_coroutine = std::move(v_continuation)] { aw_coroutine.resume(); });
            return {};
        }

        void set_continuation(std::coroutine_handle<> continuation) noexcept {
            v_continuation = continuation;
        }

    private:
        std::coroutine_handle<> v_continuation;
    };

    template <class T>
    struct coroutine;

    template <class T>
    struct coro_promise final : public promise_base {
        coro_promise() noexcept {}

        ~coro_promise() {}

        coroutine<T> get_return_object() noexcept;

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
    struct coro_promise<T&> final : public promise_base {
        coro_promise() noexcept {}

        ~coro_promise() {}

        coroutine<T&> get_return_object() noexcept;

        void unhandled_exception() noexcept {
            results = std::current_exception();
        }

        template <class Ret>
            requires std::is_constructible_v<T, Ret&&>
        void return_value(Ret&& val) noexcept(std::is_nothrow_constructible_v<T, Ret&&>) {
            results.emplace(val);
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
    struct FT_API coro_promise<void> final : public promise_base {
        coro_promise() noexcept {}

        ~coro_promise() {}

        coroutine<void> get_return_object() noexcept;

        void unhandled_exception() noexcept {
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
                        throw std::runtime_error("The coroutine returned noting");
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
    struct coroutine : public std::coroutine_handle<coro_promise<T>> {
        using promise_type = coro_promise<T>;
        using value_type = T;

        coroutine() noexcept : v_coroutine(nullptr) {}

        explicit coroutine(std::coroutine_handle<promise_type> coroutine) noexcept : v_coroutine(coroutine) {}

        coroutine(coroutine&& other) noexcept : v_coroutine(other.v_coroutine) {
            other.v_coroutine = nullptr;
        }

        coroutine(const coroutine&) = delete;
        coroutine& operator=(const coroutine&) = delete;

        coroutine& operator=(coroutine&& other) {
            if (std::addressof(other) != this) {
                if (v_coroutine)
                    v_coroutine.destroy();
                v_coroutine = other.v_coroutine;
                other.v_coroutine = nullptr;
            }
            return *this;
        }

        ~coroutine() {
            if (v_coroutine)
                v_coroutine.destroy();
        }

        bool is_ready() const noexcept {
            return v_coroutine ? v_coroutine.done() : false;
        }

        auto operator co_await() const& noexcept {
            struct FT_API aw : awaitable {
                using awaitable::awaitable;

                decltype(auto) await_resume() {
                    if (!this->v_coroutine)
                        throw std::runtime_error("Promise is not defined");
                    return this->v_coroutine.promise().result();
                }
            };

            return aw{v_coroutine};
        }

        auto operator co_await() const&& noexcept {
            struct FT_API aw : awaitable {
                using awaitable::awaitable;

                decltype(auto) await_resume() {
                    if (!this->v_coroutine)
                        throw std::runtime_error("Promise is not defined");
                    return std::move(this->v_coroutine.promise()).result();
                }
            };

            return aw{v_coroutine};
        }

        auto when_ready() const noexcept {
            struct FT_API aw : awaitable {
                using awaitable::awaitable;

                void await_resume() const noexcept {}
            };

            return aw{v_coroutine};
        }


    private:
        std::coroutine_handle<promise_type> v_coroutine;

        struct FT_API awaitable {
            std::coroutine_handle<promise_type> v_coroutine;

            awaitable(std::coroutine_handle<promise_type> coro) noexcept : v_coroutine(coro) {}

            bool await_ready() const noexcept {
                return !v_coroutine || v_coroutine.done();
            }

            void await_suspend(std::coroutine_handle<> aw_coroutine) noexcept {
                v_coroutine.promise().set_continuation(aw_coroutine);
            }
        };
    };

    template <class T>
    inline coroutine<T> coro_promise<T>::get_return_object() noexcept {
        return coroutine<T>{
            std::coroutine_handle<coro_promise>::from_promise(*this)
        };
    }

    template <class T>
    inline coroutine<T&> coro_promise<T&>::get_return_object() noexcept {
        return coroutine<T&>{
            std::coroutine_handle<coro_promise>::from_promise(*this)
        };
    }

    inline FT_API coroutine<void> coro_promise<void>::get_return_object() noexcept {
        return coroutine<void>{
            std::coroutine_handle<coro_promise<void>>::from_promise(*this)
        };
    }

    inline auto co_switch() {
        struct FT_API switch_to_fast_task {
            bool await_ready() const noexcept {
                return false;
            }

            void await_suspend(std::coroutine_handle<> awaiting_coroutine) {
                task::run([awaiting_coroutine]() {
                    awaiting_coroutine.resume();
                });
            }

            void await_resume() noexcept {}
        };

        return switch_to_fast_task{};
    }

    template <class T>
    inline T wait_for_coroutine_sync(coroutine<T> (*coro_fn)()) {
        task_condition_variable cv;
        std::exception_ptr ex;
        task_mutex mt;
        mutex_unify unified(mt);
        std::optional<T> res;
        auto temp_cor = [&] mutable -> coroutine<void> {
            try {
                res = std::move(co_await coro_fn());
            } catch (...) {
                ex = std::current_exception();
            }
            std::unique_lock lock(mt);
            cv.notify_all();
        }();
        std::unique_lock lock(unified);
        while (!res && !ex)
            cv.wait(lock);
        if (ex)
            std::rethrow_exception(ex);
        return std::move(*res);
    }
}

#endif