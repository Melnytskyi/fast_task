// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <atomic>
#include <helpers.hpp>
#include <native.hpp>

TEST(ConditionVariable, NotifyOne) {
    fast_task::native::mutex m;
    fast_task::native::condition_variable cv;
    bool ready = false;

    fast_task::native::thread waiter([&] {
        m.lock();
        while (!ready)
            cv.wait(m);
        m.unlock();
    });

    fast_task::native::this_thread::sleep_for(std::chrono::milliseconds(10));
    {
        fast_task::lock_guard lg(m);
        ready = true;
    }
    cv.notify_one();
    waiter.join();
    SUCCEED();
}

TEST(ConditionVariable, NotifyAll) {
    fast_task::native::mutex m;
    fast_task::native::condition_variable cv;
    std::atomic<int> woken{0};
    bool go = false;

    auto waiter = [&] {
        m.lock();
        while (!go)
            cv.wait(m);
        ++woken;
        m.unlock();
    };

    fast_task::native::thread t1(waiter);
    fast_task::native::thread t2(waiter);
    fast_task::native::thread t3(waiter);

    fast_task::native::this_thread::sleep_for(std::chrono::milliseconds(10));
    {
        fast_task::lock_guard lg(m);
        go = true;
    }
    cv.notify_all();

    t1.join();
    t2.join();
    t3.join();
    EXPECT_EQ(woken.load(), 3);
}

TEST(ConditionVariable, WaitForTimeout) {
    fast_task::native::mutex m;
    fast_task::native::condition_variable cv;
    bool timed_out = false;

    m.lock();
    auto status = cv.wait_for(m, std::chrono::milliseconds(50));
    timed_out = (status == fast_task::cv_status::timeout);
    m.unlock();

    EXPECT_TRUE(timed_out);
}

TEST(ConditionVariable, WaitForSucceeds) {
    fast_task::native::mutex m;
    fast_task::native::condition_variable cv;
    bool ready = false;

    fast_task::native::thread notifier([&] {
        fast_task::native::this_thread::sleep_for(std::chrono::milliseconds(10));
        m.lock();
        ready = true;
        m.unlock();
        cv.notify_one();
    });

    m.lock();
    auto status = cv.wait_for(m, std::chrono::milliseconds(500));
    bool got_ready = ready;
    m.unlock();

    notifier.join();
    EXPECT_EQ(status, fast_task::cv_status::no_timeout);
    EXPECT_TRUE(got_ready);
}
