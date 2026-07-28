// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>
#include <atomic>

class TaskQueueTest : public SchedulerFixture {};

TEST_F(TaskQueueTest, AddAndWait) {
    fast_task::queue q;
    q.enable();
    std::atomic<int> done{0};

    auto make_task = [&] {
        return fast_task::task::create([&] {
            fast_task::this_task::sleep_for(std::chrono::milliseconds(10));
            ++done;
        });
    };

    auto t1 = make_task();
    auto t2 = make_task();
    q.add(t1);
    q.add(t2);
    q.wait();

    EXPECT_EQ(done.load(), 2);
}

TEST_F(TaskQueueTest, WaitFor) {
    fast_task::queue q;
    q.enable();
    auto t = fast_task::task::create([&] {
        fast_task::this_task::sleep_for(std::chrono::milliseconds(100));
    });
    q.add(t);

    bool completed = q.wait_for(std::chrono::milliseconds(50));
    EXPECT_FALSE(completed);
    q.wait();
}

TEST_F(TaskQueueTest, InQueue) {
    fast_task::queue q;
    auto t = fast_task::task::create([&] {
        fast_task::this_task::sleep_for(std::chrono::milliseconds(50));
    });
    q.add(t);
    EXPECT_TRUE(q.in_queue(t));
    q.enable();
    q.wait();
    EXPECT_FALSE(q.in_queue(t));
}

TEST_F(TaskQueueTest, MaxAtExecution) {
    fast_task::queue q;
    q.enable();
    q.set_max_at_execution(1);
    EXPECT_EQ(q.get_max_at_execution(), 1u);

    std::atomic<int> concurrent{0};
    std::atomic<int> max_concurrent{0};

    auto make_worker = [&] {
        return fast_task::task::create([&] {
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
    }
    q.wait();
    EXPECT_LE(max_concurrent.load(), 1);
}

TEST_F(TaskQueueTest, EnableDisable) {
    fast_task::queue q;
    std::atomic<bool> ran{false};
    auto t = fast_task::task::create([&] { ran = true; });
    q.add(t);

    fast_task::native::this_thread::sleep_for(std::chrono::milliseconds(50));


    EXPECT_FALSE(ran.load());
    q.enable();
    q.wait();
    EXPECT_TRUE(ran.load());
}
