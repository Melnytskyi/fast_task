// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>
#include <threading.hpp>
#include <atomic>

TEST(Thread, JoinableAndJoin) {
    std::atomic<bool> ran{false};
    fast_task::thread t([&] { ran = true; });
    EXPECT_TRUE(t.joinable());
    t.join();
    EXPECT_FALSE(t.joinable());
    EXPECT_TRUE(ran.load());
}

TEST(Thread, Detach) {
    std::atomic<bool> ran{false};
    fast_task::mutex m;
    fast_task::condition_variable cv;

    fast_task::thread t([&] {
        ran = true;
        cv.notify_one();
    });
    t.detach();
    EXPECT_FALSE(t.joinable());

    // wait for detached thread to finish
    m.lock();
    if (!ran.load())
        cv.wait_for(m, std::chrono::milliseconds(500));
    m.unlock();
    EXPECT_TRUE(ran.load());
}

TEST(Thread, GetId) {
    fast_task::thread::id main_id = fast_task::this_thread::get_id();
    fast_task::thread::id thread_id;

    fast_task::thread t([&] {
        thread_id = fast_task::this_thread::get_id();
    });
    t.join();

    EXPECT_NE(main_id, thread_id);
}

TEST(Thread, HardwareConcurrency) {
    unsigned int hc = fast_task::thread::hardware_concurrency();
    EXPECT_GT(hc, 0u);
}

TEST(Thread, Args) {
    int result = 0;
    fast_task::thread t([](int a, int b, int& out) {
        out = a + b;
    }, 3, 7, std::ref(result));
    t.join();
    EXPECT_EQ(result, 10);
}
