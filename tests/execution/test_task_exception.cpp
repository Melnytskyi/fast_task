// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>
#include <atomic>
#include <stdexcept>

class TaskExceptionTest : public SchedulerFixture {};

TEST_F(TaskExceptionTest, ExHandleReceivesException) {
    std::atomic<bool> handler_called{false};
    std::string message;

    auto t = std::make_shared<fast_task::task>(
        [] { throw std::runtime_error("oops"); },
        [&](const std::exception_ptr& ep) {
            handler_called = true;
            try {
                std::rethrow_exception(ep);
            } catch (const std::exception& e) {
                message = e.what();
            }
        }
    );

    fast_task::scheduler::start(t);
    t->await_task();

    EXPECT_TRUE(handler_called.load());
    EXPECT_EQ(message, "oops");
}

TEST_F(TaskExceptionTest, NoExHandlerTaskStillCompletes) {
    auto t = std::make_shared<fast_task::task>(
        [] { throw std::runtime_error("silent"); }
    );
    fast_task::scheduler::start(t);
    t->await_task();
    SUCCEED();
}

TEST_F(TaskExceptionTest, ContextSwitchCounterIncreases) {
    size_t switches = 0;
    run_task([&] {
        fast_task::this_task::yield();
        fast_task::this_task::yield();
    });

    std::shared_ptr<fast_task::task> t_ref;
    auto t = std::make_shared<fast_task::task>([&] {
        fast_task::this_task::yield();
    });
    t_ref = t;
    fast_task::scheduler::start(t);
    t->await_task();
    EXPECT_GE(t_ref->get_counter_context_switch(), 1u);
}

TEST_F(TaskExceptionTest, RunTaskHelperRethrows) {
    EXPECT_THROW(
        run_task([] { throw std::logic_error("test"); }),
        std::logic_error
    );
}
