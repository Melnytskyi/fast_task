// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <atomic>
#include <fast_task/native.hpp>
#include <helpers.hpp>
#include <vector>

namespace {
    struct affinity_restore {
        std::vector<uint32_t> saved = fast_task::native::this_thread::get_affinity();

        ~affinity_restore() {
            if (!saved.empty())
                fast_task::native::this_thread::set_affinity(saved);
        }
    };
}

TEST(Thread, JoinableAndJoin) {
    std::atomic<bool> ran{false};
    fast_task::native::thread t([&] { ran = true; });
    EXPECT_TRUE(t.joinable());
    t.join();
    EXPECT_FALSE(t.joinable());
    EXPECT_TRUE(ran.load());
}

TEST(Thread, Detach) {
    std::atomic<bool> ran{false};
    fast_task::native::mutex m;
    fast_task::native::condition_variable cv;

    fast_task::native::thread t([&] {
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
    fast_task::native::thread::id main_id = fast_task::native::this_thread::get_id();
    fast_task::native::thread::id thread_id;

    fast_task::native::thread t(
        [&] {
            thread_id = fast_task::native::this_thread::get_id();
        }
    );
    t.join();

    EXPECT_NE(main_id, thread_id);
}

TEST(Thread, HardwareConcurrency) {
    unsigned int hc = fast_task::native::thread::hardware_concurrency();
    EXPECT_GT(hc, 0u);
}

TEST(Thread, Args) {
    int result = 0;
    fast_task::native::thread t(
        [](int a, int b, int& out) {
            out = a + b;
        },
        3,
        7,
        std::ref(result)
    );
    t.join();
    EXPECT_EQ(result, 10);
}

TEST(Thread, ThisThreadAffinityRoundTrip) {
    const auto original = fast_task::native::this_thread::get_affinity();
    if (original.empty())
        GTEST_SKIP() << "the platform does not report a cpu mask";
    affinity_restore restore;

    const uint32_t cpu = original.front();
    ASSERT_TRUE(fast_task::native::this_thread::set_affinity(std::vector<uint32_t>{cpu}));
    EXPECT_EQ(fast_task::native::this_thread::get_affinity(), std::vector<uint32_t>{cpu});

    ASSERT_TRUE(fast_task::native::this_thread::set_affinity(original));
    EXPECT_EQ(fast_task::native::this_thread::get_affinity(), original);
}

TEST(Thread, ConstructorAffinityIsAppliedBeforeTheBody) {
    const auto original = fast_task::native::this_thread::get_affinity();
    if (original.empty())
        GTEST_SKIP() << "the platform does not report a cpu mask";
    const uint32_t cpu = original.front();

    std::vector<uint32_t> observed;
    fast_task::native::thread t(fast_task::native::cpu_affinity{{cpu}}, [&] {
        observed = fast_task::native::this_thread::get_affinity();
    });
    EXPECT_TRUE(t.affinity_applied());
    t.join();
    EXPECT_EQ(observed, std::vector<uint32_t>{cpu});
}

TEST(Thread, ImpossibleAffinityIsRecordedNotFatal) {
    std::atomic<bool> ran{false};
    fast_task::native::thread t(fast_task::native::cpu_affinity{{1000000u}}, [&] { ran = true; });
    EXPECT_FALSE(t.affinity_applied());
    t.join();
    EXPECT_TRUE(ran.load());
}

TEST(Thread, SetAffinityFromAnotherThread) {
    const auto original = fast_task::native::this_thread::get_affinity();
    if (original.empty())
        GTEST_SKIP() << "the platform does not report a cpu mask";
    const uint32_t cpu = original.front();

    fast_task::native::mutex m;
    fast_task::native::condition_variable cv;
    bool release = false;
    std::vector<uint32_t> observed;

    fast_task::native::thread t([&] {
        m.lock();
        while (!release)
            cv.wait_for(m, std::chrono::seconds(5));
        observed = fast_task::native::this_thread::get_affinity();
        m.unlock();
    });
    ASSERT_TRUE(t.set_affinity(std::vector<uint32_t>{cpu}));
    ASSERT_EQ(t.get_affinity(), std::vector<uint32_t>{cpu});

    m.lock();
    release = true;
    cv.notify_one();
    m.unlock();
    t.join();
    EXPECT_EQ(observed, std::vector<uint32_t>{cpu});
}
