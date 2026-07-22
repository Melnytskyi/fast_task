// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>
#include <atomic>

TEST(BindExecutor, CreateAndClose) {
    fast_task::scheduler::create_executor(2);
    uint16_t id = fast_task::scheduler::create_bind_only_executor(1, true);
    fast_task::scheduler::close_bind_only_executor(id);
    fast_task::scheduler::shut_down();
}

TEST(BindExecutor, TaskRunsOnBindExecutor) {
    fast_task::scheduler::create_executor(2);
    uint16_t id = fast_task::scheduler::create_bind_only_executor(1, true);

    std::atomic<bool> ran{false};
    auto t = fast_task::task::create([&] { ran = true; });
    t.set_worker_id(id);
    fast_task::scheduler::start(t);
    t.await_task();

    EXPECT_TRUE(ran.load());

    fast_task::scheduler::close_bind_only_executor(id);
    fast_task::scheduler::shut_down();
}

TEST(BindExecutor, Assign) {
    fast_task::scheduler::create_executor(2);
    uint16_t id = fast_task::scheduler::create_bind_only_executor(1, true);

    // reassign with different count
    fast_task::scheduler::assign_bind_only_executor(id, 2, true);

    std::atomic<int> done{0};
    auto t1 = fast_task::task::create([&] { ++done; });
    auto t2 = fast_task::task::create([&] { ++done; });
    t1.set_worker_id(id);
    t2.set_worker_id(id);
    fast_task::scheduler::start(t1);
    fast_task::scheduler::start(t2);
    t1.await_task();
    t2.await_task();

    EXPECT_EQ(done.load(), 2);

    fast_task::scheduler::close_bind_only_executor(id);
    fast_task::scheduler::shut_down();
}

TEST(BindExecutor, SetWorkerIdOnTask) {
    fast_task::scheduler::create_executor(2);
    uint16_t id = fast_task::scheduler::create_bind_only_executor(1, true);

    std::atomic<bool> ran{false};
    auto t = fast_task::task::create([&] { ran = true; });
    t.set_worker_id(id);
    EXPECT_FALSE(ran.load());
    fast_task::scheduler::start(t);
    t.await_task();
    EXPECT_TRUE(ran.load());

    fast_task::scheduler::close_bind_only_executor(id);
    fast_task::scheduler::shut_down();
}

TEST(BindExecutor, CloseAbortTasksAbortsQueuedAndAllowsShutdown) {
    fast_task::scheduler::create_executor(2);
    uint16_t id = fast_task::scheduler::create_bind_only_executor(0, false);
    std::atomic<bool> queued_ran{false};

    auto queued = fast_task::task::create([&] { queued_ran.store(true, std::memory_order_release); });
    queued.set_worker_id(id);
    fast_task::scheduler::start(queued);

    fast_task::scheduler::close_bind_only_executor(id, true);
    queued.await_task();
    EXPECT_FALSE(queued_ran.load(std::memory_order_acquire));

    fast_task::scheduler::await_no_tasks();
    fast_task::scheduler::shut_down();
}
