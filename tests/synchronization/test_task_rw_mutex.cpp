// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>
#include <atomic>

class TaskRwMutexTest : public SchedulerFixture {};

TEST_F(TaskRwMutexTest, BasicWriteLock) {
    fast_task::task_rw_mutex m;
    run_task([&] {
        m.write_lock();
        EXPECT_TRUE(m.is_write_locked());
        m.write_unlock();
        EXPECT_FALSE(m.is_write_locked());
    });
}

TEST_F(TaskRwMutexTest, BasicReadLock) {
    fast_task::task_rw_mutex m;
    run_task([&] {
        m.read_lock();
        EXPECT_TRUE(m.is_read_locked());
        m.read_unlock();
        EXPECT_FALSE(m.is_read_locked());
    });
}

TEST_F(TaskRwMutexTest, MultipleReaders) {
    fast_task::task_rw_mutex m;
    std::atomic<int> concurrent{0};
    std::atomic<int> max_concurrent{0};

    auto reader = [&] {
        m.read_lock();
        int val = ++concurrent;
        int exp = max_concurrent.load();
        while (exp < val && !max_concurrent.compare_exchange_weak(exp, val))
            ;
        fast_task::this_task::sleep_for(std::chrono::milliseconds(20));
        --concurrent;
        m.read_unlock();
    };

    run_task([&] {
        auto t1 = std::make_shared<fast_task::task>([&] { reader(); });
        auto t2 = std::make_shared<fast_task::task>([&] { reader(); });
        auto t3 = std::make_shared<fast_task::task>([&] { reader(); });
        fast_task::scheduler::start(t1);
        fast_task::scheduler::start(t2);
        fast_task::scheduler::start(t3);
        std::vector<std::shared_ptr<fast_task::task>> tasks3{t1, t2, t3};
        fast_task::task::await_multiple(tasks3, true);
    });

    EXPECT_GT(max_concurrent.load(), 1);
}

TEST_F(TaskRwMutexTest, WriterExcludesReaders) {
    fast_task::task_rw_mutex m;
    std::atomic<bool> writer_done{false};
    std::atomic<bool> reader_saw_write_incomplete{false};

    run_task([&] {
        m.write_lock();

        auto reader = std::make_shared<fast_task::task>([&] {
            m.read_lock();
            reader_saw_write_incomplete = !writer_done.load();
            m.read_unlock();
        });
        fast_task::scheduler::start(reader);

        fast_task::this_task::sleep_for(std::chrono::milliseconds(20));
        writer_done = true;
        m.write_unlock();

        reader->await_task();
    });

    EXPECT_FALSE(reader_saw_write_incomplete.load());
}

TEST_F(TaskRwMutexTest, RaiiReadLock) {
    fast_task::task_rw_mutex m;
    run_task([&] {
        {
            fast_task::read_lock rl(m);
            EXPECT_TRUE(m.is_read_locked());
        }
        EXPECT_FALSE(m.is_read_locked());
    });
}

TEST_F(TaskRwMutexTest, RaiiWriteLock) {
    fast_task::task_rw_mutex m;
    run_task([&] {
        {
            fast_task::write_lock wl(m);
            EXPECT_TRUE(m.is_write_locked());
        }
        EXPECT_FALSE(m.is_write_locked());
    });
}

TEST_F(TaskRwMutexTest, AsyncReadLock) {
    fast_task::task_rw_mutex m;
    std::atomic<bool> completed{false};

    run_task([&] {
        auto coro = [&]() -> fast_task::task_coro<void> {
            m.read_lock();
            completed = true;
            m.read_unlock();
            co_return;
        }();
        fast_task::scheduler::start(coro.get_task());
        coro->await_task();
    });

    EXPECT_TRUE(completed.load());
}

TEST_F(TaskRwMutexTest, AsyncWriteLock) {
    fast_task::task_rw_mutex m;
    std::atomic<bool> completed{false};

    run_task([&] {
        auto coro = [&]() -> fast_task::task_coro<void> {
            m.write_lock();
            completed = true;
            m.write_unlock();
            co_return;
        }();
        fast_task::scheduler::start(coro.get_task());
        coro->await_task();
    });

    EXPECT_TRUE(completed.load());
}
