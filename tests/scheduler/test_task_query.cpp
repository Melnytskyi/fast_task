// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>
#include <atomic>

class TaskQueryTest : public SchedulerFixture {};

TEST_F(TaskQueryTest, AddAndWait) {
    fast_task::task_query q;
    std::atomic<int> done{0};

    auto make_task = [&] {
        return std::make_shared<fast_task::task>([&] {
            fast_task::this_task::sleep_for(std::chrono::milliseconds(10));
            ++done;
        });
    };

    auto t1 = make_task();
    auto t2 = make_task();
    q.add(t1);
    q.add(t2);
    fast_task::scheduler::start(t1);
    fast_task::scheduler::start(t2);
    q.wait();

    EXPECT_EQ(done.load(), 2);
}

TEST_F(TaskQueryTest, WaitFor) {
    fast_task::task_query q;
    auto t = std::make_shared<fast_task::task>([&] {
        fast_task::this_task::sleep_for(std::chrono::milliseconds(500));
    });
    q.add(t);
    fast_task::scheduler::start(t);

    bool completed = q.wait_for(50); // should time out
    EXPECT_FALSE(completed);
    t->notify_cancel();
    q.wait();
}

TEST_F(TaskQueryTest, InQuery) {
    fast_task::task_query q;
    auto t = std::make_shared<fast_task::task>([&] {
        fast_task::this_task::sleep_for(std::chrono::milliseconds(50));
    });
    q.add(t);
    EXPECT_TRUE(q.in_query(t));
    fast_task::scheduler::start(t);
    q.wait();
    EXPECT_FALSE(q.in_query(t));
}

TEST_F(TaskQueryTest, MaxAtExecution) {
    fast_task::task_query q;
    q.set_max_at_execution(1);
    EXPECT_EQ(q.get_max_at_execution(), 1u);

    std::atomic<int> concurrent{0};
    std::atomic<int> max_concurrent{0};

    auto make_worker = [&] {
        return std::make_shared<fast_task::task>([&] {
            int val = ++concurrent;
            int exp = max_concurrent.load();
            while (exp < val && !max_concurrent.compare_exchange_weak(exp, val))
                ;
            fast_task::this_task::sleep_for(std::chrono::milliseconds(20));
            --concurrent;
        });
    };

    for (int i = 0; i < 4; ++i) {
        auto t = make_worker();
        q.add(t);
        fast_task::scheduler::start(t);
    }
    q.wait();
    EXPECT_LE(max_concurrent.load(), 1);
}

TEST_F(TaskQueryTest, EnableDisable) {
    fast_task::task_query q;
    q.disable();
    std::atomic<bool> ran{false};
    auto t = std::make_shared<fast_task::task>([&] { ran = true; });
    q.add(t);
    fast_task::scheduler::start(t);

    fast_task::this_thread::sleep_for(std::chrono::milliseconds(50));
    // Disabled query shouldn't let tasks complete via query's throttle
    // re-enable and wait
    q.enable();
    q.wait();
    EXPECT_TRUE(ran.load());
}
