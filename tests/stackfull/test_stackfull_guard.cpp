// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>
#include <exceptions.hpp>
#include <atomic>
#include <stdexcept>

class StackfullGuardTest : public SchedulerFixture {};

// ---------------------------------------------------------------------------
// Exception-callback tests (platform independent)
// ---------------------------------------------------------------------------

// Verify that a normal C++ exception thrown inside a task reaches the
// on_exception callback with the correct type and message.
TEST_F(StackfullGuardTest, ExceptionCallback_ReceivesCorrectException) {
    std::atomic<bool> called{false};
    std::string message;

    auto t = std::make_shared<fast_task::task>(
        [] { throw std::runtime_error("guard_test"); },
        [&](const std::exception_ptr& ep) {
            called.store(true);
            try {
                std::rethrow_exception(ep);
            } catch (const std::runtime_error& e) {
                message = e.what();
            }
        }
    );
    fast_task::scheduler::start(t);
    t->await_task();

    EXPECT_TRUE(called.load());
    EXPECT_EQ(message, "guard_test");
}

// Verify that RAII destructors run for local objects when a normal exception
// is thrown inside a task.
TEST_F(StackfullGuardTest, ExceptionCallback_RaiiDestructorCalledOnException) {
    struct DtorGuard {
        std::atomic<bool>& flag;
        ~DtorGuard() { flag.store(true, std::memory_order_release); }
    };

    std::atomic<bool> dtor_called{false};
    std::atomic<bool> handler_called{false};

    auto t = std::make_shared<fast_task::task>(
        [&] {
            DtorGuard guard{dtor_called};
            throw std::runtime_error("raii_test");
        },
        [&](const std::exception_ptr&) {
            handler_called.store(true);
        }
    );
    fast_task::scheduler::start(t);
    t->await_task();

    EXPECT_TRUE(handler_called.load()) << "Exception handler must be called";
    EXPECT_TRUE(dtor_called.load()) << "RAII destructor must run before handler";
}

// ---------------------------------------------------------------------------
// Stack-overflow tests (Linux x86_64 only — requires the SIGSEGV handler that
// redirects execution to throw fast_task::stack_overflow)
// ---------------------------------------------------------------------------

#if defined(__x86_64__) && defined(__linux__)

// Recursive function that deliberately exhausts the task's 1 MB stack.
// Each frame allocates a 4 kB volatile buffer to accelerate the overflow.
[[noreturn]] __attribute__((noinline)) static void recurse_overflow() {
    volatile char buf[4096] = {};
    (void)buf[0];
    recurse_overflow();
}

// Verify that a stack overflow inside a task is caught by the on_exception
// callback and arrives as fast_task::stack_overflow.
TEST_F(StackfullGuardTest, StackOverflow_ExceptionCallbackCalled) {
    std::atomic<bool> handler_called{false};
    std::atomic<bool> got_stack_overflow{false};

    auto t = std::make_shared<fast_task::task>(
        [] { recurse_overflow(); },
        [&](const std::exception_ptr& ep) {
            handler_called.store(true);
            try {
                std::rethrow_exception(ep);
            } catch (const fast_task::stack_overflow&) {
                got_stack_overflow.store(true);
            } catch (...) {
            }
        }
    );
    fast_task::scheduler::start(t);
    t->await_task();

    EXPECT_TRUE(handler_called.load()) << "on_exception callback must be called on stack overflow";
    EXPECT_TRUE(got_stack_overflow.load()) << "Exception must be fast_task::stack_overflow";
}

// Verify that RAII destructors for objects on the task stack are called even
// when the stack overflows (i.e., C++ unwinding works through the guard-page
// recovery path).
TEST_F(StackfullGuardTest, StackOverflow_RaiiDestructorCalled) {
    struct DtorGuard {
        std::atomic<bool>& flag;
        ~DtorGuard() { flag.store(true, std::memory_order_release); }
    };

    std::atomic<bool> dtor_called{false};
    std::atomic<bool> handler_called{false};

    auto t = std::make_shared<fast_task::task>(
        [&] {
            // The guard is in the outermost task frame; the unwinder will reach
            // it while walking up from the overflow point.
            DtorGuard guard{dtor_called};
            recurse_overflow(); // never returns normally
        },
        [&](const std::exception_ptr&) {
            handler_called.store(true);
        }
    );
    fast_task::scheduler::start(t);
    t->await_task();

    EXPECT_TRUE(handler_called.load()) << "Exception handler must be called";
    EXPECT_TRUE(dtor_called.load()) << "RAII destructor must run during stack-overflow unwind";
}

#endif // defined(__x86_64__) && defined(__linux__)
