// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef INCLUDE_COROUTINE_HELPERS
#define INCLUDE_COROUTINE_HELPERS
#include "../task/query.hpp"
#include "../task/scheduler.hpp"
#include "core.hpp"

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


#endif /* INCLUDE_COROUTINE_HELPERS */
