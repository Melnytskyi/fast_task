// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>
#include <atomic>

class NativeTaskSyncTest : public SchedulerFixture {};

// ---- mutex shared between native thread and task context ----

TEST_F(NativeTaskSyncTest, NativeThreadAndTaskShareMutex) {
    fast_task::mutex mtx;
    int value = 0;


    std::atomic<bool> native_done{false};
    std::atomic<bool> native_holds_lock{false};
    fast_task::native::thread native([&] {
        fast_task::unique_lock<fast_task::mutex> lk(mtx);
        native_holds_lock = true;
        fast_task::native::this_thread::sleep_for(std::chrono::milliseconds(20));
        value = 10;
        native_done = true;
    });

    while (!native_holds_lock.load()) {
        fast_task::native::this_thread::yield();
    }

    // Task tries to acquire the same mutex
    std::atomic<int> task_value{0};
    auto t = fast_task::task::create([&] {
        fast_task::lock_guard<fast_task::mutex> lk(mtx);
        task_value = value + 1;
    });
    fast_task::scheduler::start(t);
    t.await_task();
    native.join();

    EXPECT_TRUE(native_done.load());
    EXPECT_EQ(task_value.load(), 11);
}

// ---- protected_value shared between tasks ----

TEST_F(NativeTaskSyncTest, ProtectedValueFromMultipleTasks) {
    fast_task::mutex mtx;
    int shared = 0;

    auto worker = [&] {
        fast_task::lock_guard<fast_task::mutex> lk(mtx);
        int v = shared;
        fast_task::this_task::yield();
        shared = v + 1;
    };

    std::vector<fast_task::task> tasks;
    for (int i = 0; i < 5; ++i) {
        tasks.push_back(fast_task::task::create(worker));
        fast_task::scheduler::start(tasks.back());
    }
    fast_task::task::await_multiple(tasks, true);

    EXPECT_EQ(shared, 5);
}

// ---- rw_mutex with mixed readers and one writer ----

TEST_F(NativeTaskSyncTest, RwMutexMixedReaderWriter) {
    fast_task::rw_mutex mtx;
    std::atomic<int> readers_concurrent{0};
    int written_value = 0;

    auto reader = [&] {
        fast_task::read_lock lk(mtx);
        ++readers_concurrent;
        fast_task::this_task::yield();
        --readers_concurrent;
    };

    auto writer = [&] {
        fast_task::write_lock lk(mtx);
        written_value = 42;
    };

    auto r1 = fast_task::task::create(reader);
    auto r2 = fast_task::task::create(reader);
    auto w = fast_task::task::create(writer);

    fast_task::scheduler::start(r1);
    fast_task::scheduler::start(r2);
    fast_task::scheduler::start(w);

    auto tasks = std::vector<fast_task::task>{r1, r2, w};
    fast_task::task::await_multiple(tasks, true);

    EXPECT_EQ(written_value, 42);
}
