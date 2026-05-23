// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>
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
