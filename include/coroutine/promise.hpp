#ifndef INCLUDE_COROUTINE_PROMISE
#define INCLUDE_COROUTINE_PROMISE

#include "../task/fwd.hpp"
#include "../task/this_task.hpp"

namespace fast_task {
    struct FT_API task_promise_base {
        std::shared_ptr<task> task_object;
        std::suspend_always initial_suspend() noexcept {
            return {};
        }

        auto final_suspend() noexcept {
            struct final_awaiter {
                std::shared_ptr<fast_task::task> t;

                bool await_ready() noexcept {
                    return false;
                }

                void await_suspend(std::coroutine_handle<>) noexcept {
                    if (t) {
                        fast_task::this_task::the_coroutine_ended(t);
                        t.reset();
                    }
                }

                void await_resume() noexcept {}
            };

            return final_awaiter{std::move(task_object)};
        }
    };

    struct FT_API base_coro_handle {
        std::coroutine_handle<> handle;
        task_promise_base* promise = nullptr;

        template <class Promise>
        base_coro_handle(std::coroutine_handle<Promise> h)
            : handle(h), promise(&h.promise()) {}

        base_coro_handle() = default;
        base_coro_handle(const base_coro_handle&) = default;
        base_coro_handle(base_coro_handle&& other) noexcept = default;

        base_coro_handle& operator=(const base_coro_handle&) = default;
        base_coro_handle& operator=(base_coro_handle&& other) noexcept = default;
    };
}

#endif /* INCLUDE_COROUTINE_PROMISE */
