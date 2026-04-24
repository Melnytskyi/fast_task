// Copyright Danyil Melnytskyi 2025-Present

#ifndef BDDA50FC_229D_4850_966C_6FAA9A66D3D5
#define BDDA50FC_229D_4850_966C_6FAA9A66D3D5
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <task.hpp>
#include <coroutine.hpp>
#include <future.hpp>
#include <gtest/gtest.h>
#include <atomic>
#include <memory>
#include <stdexcept>
#include <thread>

// ---------------------------------------------------------------------------
// SchedulerFixture
// Base class for tests that require the task scheduler.
// SetUpTestSuite / TearDownTestSuite run once per test executable.
// ---------------------------------------------------------------------------
class SchedulerFixture : public ::testing::Test {
public:
    static void SetUpTestSuite() {
        size_t n = std::max(2u, std::thread::hardware_concurrency());
        fast_task::scheduler::create_executor(n);
        // Spin-wait until all executor threads have actually started
        while (fast_task::scheduler::total_executors() < n)
            std::this_thread::yield();
    }

    static void TearDownTestSuite() {
        fast_task::scheduler::shut_down();
    }
};

// ---------------------------------------------------------------------------
// run_task(fn)
// Runs a callable as a stackful task and blocks the native thread until done.
// Any exception thrown inside the task is rethrown in the caller.
// ---------------------------------------------------------------------------
template <class F>
void run_task(F&& fn) {
    std::exception_ptr ex;
    auto t = std::make_shared<fast_task::task>(
        std::forward<F>(fn),
        [&ex](const std::exception_ptr& e) { ex = e; });
    fast_task::scheduler::start(t);
    t->await_task();
    if (ex)
        std::rethrow_exception(ex);
}

// ---------------------------------------------------------------------------
// run_coro(coro)
// Starts a task_coro and blocks the native thread until it completes.
// ---------------------------------------------------------------------------
template <class T>
void run_coro(fast_task::task_coro<T>& coro) {
    fast_task::scheduler::start(coro.get_task());
    coro->await_task();
}

// ---------------------------------------------------------------------------
// get_coro_result(coro)
// After a task_coro<T> has completed, retrieves the stored result.
// The coroutine frame must still be alive (it suspends at final_suspend).
// ---------------------------------------------------------------------------
template <class T>
T get_coro_result(fast_task::task_coro<T>& coro) {
    T result{};
    coro->access_dummy([&result](void* addr) {
        auto h = std::coroutine_handle<fast_task::task_promise<T>>::from_address(addr);
        result = h.promise().result();
    });
    return result;
}


#endif /* BDDA50FC_229D_4850_966C_6FAA9A66D3D5 */
