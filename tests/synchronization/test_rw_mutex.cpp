// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>
#include <atomic>

class TaskRwMutexTest : public SchedulerFixture {};

TEST_F(TaskRwMutexTest, BasicWriteLock) {
    fast_task::rw_mutex m;
    run_task([&] {
        m.write_lock();
        EXPECT_TRUE(m.is_write_locked());
        m.write_unlock();
        EXPECT_FALSE(m.is_write_locked());
    });
}

TEST_F(TaskRwMutexTest, BasicReadLock) {
    fast_task::rw_mutex m;
    run_task([&] {
        m.read_lock();
        EXPECT_TRUE(m.is_read_locked());
        m.read_unlock();
        EXPECT_FALSE(m.is_read_locked());
    });
}

TEST_F(TaskRwMutexTest, MultipleReaders) {
    fast_task::rw_mutex m;
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
        auto t1 = fast_task::task::create([&] { reader(); });
        auto t2 = fast_task::task::create([&] { reader(); });
        auto t3 = fast_task::task::create([&] { reader(); });
        fast_task::scheduler::start(t1);
        fast_task::scheduler::start(t2);
        fast_task::scheduler::start(t3);
        std::vector<fast_task::task> tasks3{t1, t2, t3};
        fast_task::task::await_multiple(tasks3, true);
    });

    EXPECT_GT(max_concurrent.load(), 1);
}

TEST_F(TaskRwMutexTest, WriterExcludesReaders) {
    fast_task::rw_mutex m;
    std::atomic<bool> writer_done{false};
    std::atomic<bool> reader_saw_write_incomplete{false};

    run_task([&] {
        m.write_lock();

        auto reader = fast_task::task::create([&] {
            m.read_lock();
            reader_saw_write_incomplete = !writer_done.load();
            m.read_unlock();
        });
        fast_task::scheduler::start(reader);

        fast_task::this_task::sleep_for(std::chrono::milliseconds(20));
        writer_done = true;
        m.write_unlock();

        reader.await_task();
    });

    EXPECT_FALSE(reader_saw_write_incomplete.load());
}

TEST_F(TaskRwMutexTest, RaiiReadLock) {
    fast_task::rw_mutex m;
    run_task([&] {
        {
            fast_task::read_lock rl(m);
            EXPECT_TRUE(m.is_read_locked());
        }
        EXPECT_FALSE(m.is_read_locked());
    });
}

TEST_F(TaskRwMutexTest, RaiiWriteLock) {
    fast_task::rw_mutex m;
    run_task([&] {
        {
            fast_task::write_lock wl(m);
            EXPECT_TRUE(m.is_write_locked());
        }
        EXPECT_FALSE(m.is_write_locked());
    });
}

TEST_F(TaskRwMutexTest, AsyncReadLock) {
    fast_task::rw_mutex m;
    std::atomic<bool> completed{false};

    run_task([&] {
        auto coro_fn = [&]() -> fast_task::task_coro<void> {
            m.read_lock();
            completed = true;
            m.read_unlock();
            co_return;
        };
        auto coro = coro_fn();
        fast_task::scheduler::start(coro.get_task());
        coro->await_task();
    });

    EXPECT_TRUE(completed.load());
}

TEST_F(TaskRwMutexTest, TryLocksFailWhileWriterHolds) {
    fast_task::rw_mutex m;
    run_task([&] {
        m.write_lock();
        EXPECT_TRUE(m.is_own());
        EXPECT_FALSE(m.try_read_lock());
        EXPECT_FALSE(m.try_write_lock());
        m.write_unlock();
        EXPECT_FALSE(m.is_own());

        m.read_lock();
        EXPECT_TRUE(m.try_read_lock());
        EXPECT_FALSE(m.try_write_lock());
        m.read_unlock();
        m.read_unlock();

        EXPECT_TRUE(m.try_write_lock());
        m.write_unlock();
    });
}

TEST_F(TaskRwMutexTest, ReadersWaitWhileAWriterIsQueued) {
    fast_task::rw_mutex m;
    std::atomic<bool> writer_inside{false};
    std::atomic<bool> first_reader_left{false};
    std::atomic<bool> second_reader_violated{false};

    run_task([&] {
        m.read_lock();

        auto writer = fast_task::task::create([&] {
            m.write_lock();
            writer_inside = true;
            fast_task::this_task::sleep_for(std::chrono::milliseconds(20));
            writer_inside = false;
            m.write_unlock();
        });
        fast_task::scheduler::start(writer);

        fast_task::this_task::sleep_for(std::chrono::milliseconds(20));

        auto reader = fast_task::task::create([&] {
            m.read_lock();
            if (!first_reader_left.load() || writer_inside.load())
                second_reader_violated = true;
            m.read_unlock();
        });
        fast_task::scheduler::start(reader);

        fast_task::this_task::sleep_for(std::chrono::milliseconds(20));
        first_reader_left = true;
        m.read_unlock();

        reader.await_task();
        writer.await_task();
    });

    EXPECT_FALSE(second_reader_violated.load());
}

TEST_F(TaskRwMutexTest, ParkedWritersRunOneAtATime) {
    fast_task::rw_mutex m;
    std::atomic<int> inside{0};
    std::atomic<int> max_inside{0};
    std::atomic<int> done{0};

    auto writer = [&] {
        m.write_lock();
        int val = ++inside;
        int expected = max_inside.load();
        while (expected < val && !max_inside.compare_exchange_weak(expected, val))
            ;
        fast_task::this_task::sleep_for(std::chrono::milliseconds(5));
        --inside;
        m.write_unlock();
        ++done;
    };

    run_task([&] {
        m.read_lock();
        std::vector<fast_task::task> tasks;
        for (int i = 0; i < 4; ++i) {
            tasks.push_back(fast_task::task::create(writer));
            fast_task::scheduler::start(tasks.back());
        }
        fast_task::this_task::sleep_for(std::chrono::milliseconds(20));
        m.read_unlock();
        fast_task::task::await_multiple(tasks, true);
    });

    EXPECT_EQ(max_inside.load(), 1);
    EXPECT_EQ(done.load(), 4);
}

TEST_F(TaskRwMutexTest, ReaderWriterHandoffStress) {
    fast_task::rw_mutex m;
    std::atomic<long long> counter{0};
    const int iterations = 300;

    auto reader = [&] {
        for (int i = 0; i < iterations; ++i) {
            m.read_lock();
            EXPECT_TRUE(m.is_read_locked());
            m.read_unlock();
        }
    };
    auto writer = [&] {
        for (int i = 0; i < iterations; ++i) {
            m.write_lock();
            counter.fetch_add(1);
            m.write_unlock();
        }
    };

    run_task([&] {
        auto r1 = fast_task::task::create(reader);
        auto r2 = fast_task::task::create(reader);
        auto w1 = fast_task::task::create(writer);
        auto w2 = fast_task::task::create(writer);
        fast_task::scheduler::start(r1);
        fast_task::scheduler::start(r2);
        fast_task::scheduler::start(w1);
        fast_task::scheduler::start(w2);
        std::vector<fast_task::task> tasks{r1, r2, w1, w2};
        fast_task::task::await_multiple(tasks, true);
    });

    EXPECT_EQ(counter.load(), iterations * 2);
}

TEST_F(TaskRwMutexTest, AsyncWriteLock) {
    fast_task::rw_mutex m;
    std::atomic<bool> completed{false};

    run_task([&] {
        auto coro_fn = [&]() -> fast_task::task_coro<void> {
            m.write_lock();
            completed = true;
            m.write_unlock();
            co_return;
        };
        auto coro = coro_fn();
        fast_task::scheduler::start(coro.get_task());
        coro->await_task();
    });

    EXPECT_TRUE(completed.load());
}

TEST_F(TaskRwMutexTest, WriterTimeoutWakesParkedReaders) {
    fast_task::rw_mutex rw;
    std::atomic<bool> writer_started{false};
    std::atomic<bool> writer_done{false};
    std::atomic<bool> writer_acquired{true};
    std::atomic<bool> reader2_acquired{false};

    rw.read_lock();

    auto writer = fast_task::task::run([&] {
        writer_started.store(true, std::memory_order_release);
        bool ok = rw.try_write_lock_for(std::chrono::milliseconds(25));
        writer_acquired.store(ok, std::memory_order_release);
        if (ok)
            rw.write_unlock();
        writer_done.store(true, std::memory_order_release);
    });

    while (!writer_started.load(std::memory_order_acquire))
        std::this_thread::yield();
    std::this_thread::sleep_for(std::chrono::milliseconds(5));

    auto reader2 = fast_task::task::run([&] {
        rw.read_lock();
        reader2_acquired.store(true, std::memory_order_release);
        rw.read_unlock();
    });

    writer.await_task();
    EXPECT_TRUE(writer_done.load(std::memory_order_acquire));
    EXPECT_FALSE(writer_acquired.load(std::memory_order_acquire));

    rw.read_unlock();
    reader2.await_task();
    EXPECT_TRUE(reader2_acquired.load(std::memory_order_acquire));
}
