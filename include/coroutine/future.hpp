// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef INCLUDE_COROUTINE_FUTURE
#define INCLUDE_COROUTINE_FUTURE
#include "../task/future.hpp"
#include "core.hpp"
#include "detail/lock_misc.hpp"

namespace fast_task {
    namespace detail {
        template <class T>
        struct future_mov_result_awaiter {
            enter_state state;
            future_ptr<T> t;

            bool await_ready() noexcept {
                return t->is_ready();
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
                    if (t->is_ready())
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
                return t->is_ready();
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
                    if (t->is_ready())
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
    template<class T>
    inline auto operator co_await(future_ptr<T>&& t) noexcept {
        return detail::future_mov_result_awaiter{{}, std::move(t)};
    }

    template <class T>
    inline auto operator co_await(const future_ptr<T>& t) noexcept {
        return detail::future_cop_result_awaiter{{}, std::move(t)};
    }
}

#endif /* INCLUDE_COROUTINE_FUTURE */
