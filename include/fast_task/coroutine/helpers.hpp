// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_INCLUDE_COROUTINE_HELPERS
#define FAST_TASK_INCLUDE_COROUTINE_HELPERS
#include "../task/queue.hpp"
#include "../task/scheduler.hpp"
#include "core.hpp"

namespace fast_task::coroutine {
    template <class T, class FN>
    task_coro<void> async_for_each(T&& container, fast_task::queue& queue, FN&& fn) {
        if (container.empty()) {
            auto res = []() -> fast_task::task_coro<void> {
                co_return;
            }();
            queue.add(res.get_task());
            return res;
        }
        std::vector<fast_task::task_coro<void>> coros;
        for (auto& item : container) {
            auto cor = [](auto item, auto fn) -> fast_task::task_coro<void> {
                fn(item);
                co_return;
            }(std::move(item), fn);
            queue.add(cor.get_task());
            coros.emplace_back(std::move(cor));
        }

        auto res = [](std::vector<fast_task::task_coro<void>> fut) -> fast_task::task_coro<void> {
            std::exception_ptr ex;
            try {
                for (auto& coro : fut)
                    co_await coro;
            } catch (...) {
                ex = std::current_exception();
                for (auto& coro : fut)
                    coro->notify_cancel();
            }
            if (ex) {
                for (auto& coro : fut) {
                    try {
                        co_await coro;
                    } catch (...) {}
                }
                std::rethrow_exception(ex);
            }
            co_return;
        }(std::move(coros));
        queue.add(res.get_task());
        return res;
    }

    template <class T, class FN>
    task_coro<void> async_for_each(T&& container, FN&& fn) {
        if (container.empty()) {
            auto res = []() -> fast_task::task_coro<void> {
                co_return;
            }();
            fast_task::scheduler::start(res.get_task());
            return res;
        }
        std::vector<fast_task::task_coro<void>> coros;
        for (auto& item : container) {
            auto cor = [](auto item, auto fn) -> fast_task::task_coro<void> {
                fn(item);
                co_return;
            }(std::move(item), fn);

            fast_task::scheduler::start(cor.get_task());
            coros.emplace_back(std::move(cor));
        }

        auto res = [](std::vector<fast_task::task_coro<void>> fut) -> fast_task::task_coro<void> {
            std::exception_ptr ex;
            try {
                for (auto& coro : fut)
                    co_await coro;
            } catch (...) {
                ex = std::current_exception();
                for (auto& coro : fut)
                    coro->notify_cancel();
            }
            if (ex) {
                for (auto& coro : fut) {
                    try {
                        co_await coro;
                    } catch (...) {}
                }
                std::rethrow_exception(ex);
            }
            co_return;
        }(std::move(coros));
        fast_task::scheduler::start(res.get_task());
        return res;
    }

    template <class T, class FN>
    void for_each(T& container, fast_task::queue& queue, FN&& fn) {
        if (container.empty())
            return;
        std::vector<fast_task::task_coro<void>> coros;
        try {
            for (auto& item : container) {
                auto cor = [](auto& item, auto& fn) -> fast_task::task_coro<void> {
                    fn(item);
                    co_return;
                }(item, fn);
                queue.add(cor.get_task());
                coros.emplace_back(std::move(cor));
            }

            for (auto& coro : coros)
                coro.sync_get();
        } catch (...) {
            for (auto& coro : coros)
                coro->notify_cancel();
            for (auto& coro : coros)
                coro->await_task();
            throw;
        }
    }

    template <class T, class FN>
    void for_each(T& container, FN&& fn) {
        if (container.empty())
            return;
        std::vector<fast_task::task_coro<void>> coros;
        try {
            for (auto& item : container) {
                auto cor = [](auto& item, auto& fn) -> fast_task::task_coro<void> {
                    fn(item);
                    co_return;
                }(item, fn);
                fast_task::scheduler::start(cor.get_task());
                coros.emplace_back(std::move(cor));
            }

            for (auto& coro : coros)
                coro.sync_get();
        } catch (...) {
            for (auto& coro : coros)
                coro->notify_cancel();
            for (auto& coro : coros)
                coro->await_task();
            throw;
        }
    }

    template <class T>
    task_auto_start_coro<void> wait_all(T coros) {
        for (auto& coro : coros)
            co_await coro;
        co_return;
    }

    template <class T>
    void wait_all_blocking(T& coros) {
        if (coros.empty())
            return;

        try {
            for (auto& coro : coros)
                fast_task::scheduler::start(coro);

            for (auto& coro : coros)
                coro.sync_get();
        } catch (...) {
            for (auto& coro : coros)
                coro->notify_cancel();
            for (auto& coro : coros)
                coro->await_task();
            throw;
        }
    }
}


#endif /* FAST_TASK_INCLUDE_COROUTINE_HELPERS */
