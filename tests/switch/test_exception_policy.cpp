// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)
//
// Tests for the exception policy compile-time behaviour.
// The library can be built with different exception policies (CHECK / PRESERVE).
// We simply verify that tasks complete normally and that exceptions propagate
// under the default policy.

#include <helpers.hpp>
#include <stdexcept>

class ExceptionPolicyTest : public SchedulerFixture {};

TEST_F(ExceptionPolicyTest, NormalTaskCompletes) {
    bool ok = false;
    run_task([&] { ok = true; });
    EXPECT_TRUE(ok);
}

TEST_F(ExceptionPolicyTest, ExceptionReachesExHandle) {
    bool caught = false;
    auto t = std::make_shared<fast_task::task>(
        [] { throw std::runtime_error("policy_test"); },
        [&](const std::exception_ptr& ep) {
            try {
                std::rethrow_exception(ep);
            } catch (const std::runtime_error& e) {
                caught = (std::string(e.what()) == "policy_test");
            }
        }
    );
    fast_task::scheduler::start(t);
    t->await_task();
    EXPECT_TRUE(caught);
}

TEST_F(ExceptionPolicyTest, RunTaskHelperRethrows) {
    EXPECT_THROW(
        run_task([] { throw std::logic_error("rethrow"); }),
        std::logic_error
    );
}

TEST_F(ExceptionPolicyTest, NestedExceptionFromChildTask) {
    std::atomic<bool> child_threw{false};
    run_task([&] {
        auto child = std::make_shared<fast_task::task>(
            [] { throw std::invalid_argument("child"); },
            [&](const std::exception_ptr&) { child_threw = true; }
        );
        fast_task::scheduler::start(child);
        child->await_task();
    });
    EXPECT_TRUE(child_threw.load());
}
