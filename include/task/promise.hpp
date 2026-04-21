#ifndef INCLUDE_TASK_PROMISE
#define INCLUDE_TASK_PROMISE

#include "fwd.hpp"

namespace fast_task {
    struct FT_API_LOCAL task_promise_base {
        std::shared_ptr<task> task_object;
        std::suspend_always initial_suspend() noexcept;
        std::suspend_always final_suspend() noexcept;
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

#endif /* INCLUDE_TASK_PROMISE */
