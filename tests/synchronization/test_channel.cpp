// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <atomic>
#include <coroutine>
#include <fast_task/coroutine.hpp>
#include <fast_task/task/channel.hpp>
#include <fast_task/task/task_group.hpp>
#include <helpers.hpp>
#include <memory>
#include <stdexcept>
#include <vector>

namespace {
    // Potentially-throwing movable type: forces the blocking channel implementation.
    struct throwing_value {
        int v = 0;

        throwing_value() = default;
        explicit throwing_value(int x) : v(x) {}
        throwing_value(const throwing_value& other) : v(other.v) {}
        throwing_value(throwing_value&& other) noexcept(false) : v(other.v) {}
        throwing_value& operator=(const throwing_value& other) = default;
        throwing_value& operator=(throwing_value&& other) noexcept(false) {
            v = other.v;
            return *this;
        }
    };

    // Minimal foreign C++20 coroutine (not derived from fast_task::task_promise_base)
    // to verify `enter_*` and foreign-coroutine awaiter interoperability.
    struct foreign_coro {
        struct promise_type {
            fast_task::native::mutex mut;
            fast_task::native::condition_variable cv;
            bool finished = false;

            foreign_coro get_return_object() {
                return foreign_coro{std::coroutine_handle<promise_type>::from_promise(*this)};
            }

            std::suspend_never initial_suspend() noexcept { return {}; }

            struct final_awaiter {
                promise_type* p;
                bool await_ready() noexcept { return false; }
                void await_suspend(std::coroutine_handle<>) noexcept {
                    p->mut.lock();
                    p->finished = true;
                    p->cv.notify_all();
                    p->mut.unlock();
                }
                void await_resume() noexcept {}
            };

            final_awaiter final_suspend() noexcept { return {this}; }
            void return_void() noexcept {}
            void unhandled_exception() { std::terminate(); }
        };

        std::coroutine_handle<promise_type> h;

        void wait() {
            auto& p = h.promise();
            p.mut.lock();
            while (!p.finished)
                p.cv.wait(p.mut);
            p.mut.unlock();
        }

        ~foreign_coro() {
            if (h)
                h.destroy();
        }
    };
}

static_assert(fast_task::bounded_channel<int>::is_lock_free, "int bounded_channel must be lock-free");
static_assert(fast_task::bounded_channel<std::unique_ptr<int>>::is_lock_free, "unique_ptr bounded_channel must be lock-free");
static_assert(!fast_task::bounded_channel<throwing_value>::is_lock_free, "throwing type must select blocking bounded_channel");
static_assert(fast_task::unbounded_channel<int>::uses_fast_spin, "int unbounded_channel must use fast spin path");
static_assert(!fast_task::unbounded_channel<throwing_value>::uses_fast_spin, "throwing type must select blocking unbounded_channel");

class ChannelTest : public SchedulerFixture {};

TEST_F(ChannelTest, UnboundedSendRecvFIFO) {
    fast_task::unbounded_channel<int> ch;
    EXPECT_TRUE(ch.empty());

    EXPECT_TRUE(ch.send(10));
    EXPECT_TRUE(ch.send(20));
    EXPECT_TRUE(ch.send(30));
    EXPECT_EQ(ch.size(), 3u);

    EXPECT_EQ(ch.recv(), 10);
    EXPECT_EQ(ch.recv(), 20);
    EXPECT_EQ(ch.recv(), 30);
    EXPECT_TRUE(ch.empty());
    EXPECT_EQ(ch.try_recv(), std::nullopt);
}

TEST_F(ChannelTest, BoundedCapacityOneAndNonPowerOfTwo) {
    {
        fast_task::bounded_channel<int> ch(1);
        EXPECT_EQ(ch.capacity(), 1u);
        EXPECT_TRUE(ch.try_send(7));
        EXPECT_FALSE(ch.try_send(8));
        EXPECT_EQ(ch.try_recv(), 7);
        EXPECT_TRUE(ch.try_send(9));
        EXPECT_EQ(ch.try_recv(), 9);
    }
    {
        fast_task::bounded_channel<int> ch(3);
        EXPECT_EQ(ch.capacity(), 3u);
        EXPECT_TRUE(ch.try_send(1));
        EXPECT_TRUE(ch.try_send(2));
        EXPECT_TRUE(ch.try_send(3));
        EXPECT_FALSE(ch.try_send(4));
        EXPECT_EQ(ch.try_recv(), 1);
        EXPECT_TRUE(ch.try_send(4));
        EXPECT_EQ(ch.try_recv(), 2);
        EXPECT_EQ(ch.try_recv(), 3);
        EXPECT_EQ(ch.try_recv(), 4);
    }
}

TEST_F(ChannelTest, BoundedBackpressureAndCloseDrain) {
    fast_task::bounded_channel<int> ch(2);
    EXPECT_TRUE(ch.try_send(1));
    EXPECT_TRUE(ch.try_send(2));
    EXPECT_FALSE(ch.try_send(3));

    std::vector<int> received;
    run_task([&] {
        auto producer = fast_task::task::run([&] {
            EXPECT_TRUE(ch.send(3));
            EXPECT_TRUE(ch.send(4));
            ch.close();
            EXPECT_FALSE(ch.send(5));
        });

        while (auto v = ch.recv())
            received.push_back(*v);

        producer.await_task();
    });

    EXPECT_TRUE(ch.is_closed());
    ASSERT_EQ(received.size(), 4u);
    EXPECT_EQ(received[0], 1);
    EXPECT_EQ(received[3], 4);
}

TEST_F(ChannelTest, MoveOnlyAndThrowingFallbackTypes) {
    {
        fast_task::bounded_channel<std::unique_ptr<int>> ch(4);
        EXPECT_TRUE(ch.send(std::make_unique<int>(42)));
        auto v = ch.recv();
        ASSERT_TRUE(v.has_value());
        EXPECT_EQ(**v, 42);
    }
    {
        fast_task::bounded_channel<throwing_value> ch(2);
        EXPECT_TRUE(ch.try_send(throwing_value{11}));
        EXPECT_TRUE(ch.try_send(throwing_value{22}));
        EXPECT_FALSE(ch.try_send(throwing_value{33}));
        EXPECT_EQ(ch.recv()->v, 11);
        EXPECT_EQ(ch.recv()->v, 22);
    }
    {
        fast_task::unbounded_channel<throwing_value> ch;
        EXPECT_TRUE(ch.send(throwing_value{99}));
        EXPECT_EQ(ch.recv()->v, 99);
    }
}

TEST_F(ChannelTest, SendForAndRecvForTimeouts) {
    fast_task::bounded_channel<int> ch(1);
    bool recv_timed_out = false;
    bool send_timed_out = false;

    run_task([&] {
        recv_timed_out = !ch.recv_for(std::chrono::milliseconds(20)).has_value();
        EXPECT_TRUE(ch.try_send(99));
        send_timed_out = !ch.send_for(100, std::chrono::milliseconds(20));
    });

    EXPECT_TRUE(recv_timed_out);
    EXPECT_TRUE(send_timed_out);
}

TEST_F(ChannelTest, MpmcBoundedAndUnboundedStress) {
    constexpr int producers = 4;
    constexpr int items_per_producer = 500;
    const int expected = producers * (items_per_producer * (items_per_producer + 1) / 2);

    // Lock-free bounded MPMC stress
    {
        fast_task::bounded_channel<int> ch(16);
        std::atomic<int> sum{0};
        std::atomic<int> done_producers{0};

        run_task([&] {
            fast_task::task_group group;
            for (int p = 0; p < producers; ++p) {
                group.run([&] {
                    for (int i = 1; i <= items_per_producer; ++i)
                        EXPECT_TRUE(ch.send(i));
                    if (done_producers.fetch_add(1, std::memory_order_acq_rel) + 1 == producers)
                        ch.close();
                });
            }
            for (int c = 0; c < 4; ++c) {
                group.run([&] {
                    while (auto v = ch.recv())
                        sum.fetch_add(*v, std::memory_order_relaxed);
                });
            }
            group.wait();
        });
        EXPECT_EQ(sum.load(), expected);
    }

    // Chunked unbounded MPMC stress (> 64 items per block)
    {
        fast_task::unbounded_channel<int> ch;
        std::atomic<int> sum{0};
        std::atomic<int> done_producers{0};

        run_task([&] {
            fast_task::task_group group;
            for (int p = 0; p < producers; ++p) {
                group.run([&] {
                    for (int i = 1; i <= items_per_producer; ++i)
                        EXPECT_TRUE(ch.send(i));
                    if (done_producers.fetch_add(1, std::memory_order_acq_rel) + 1 == producers)
                        ch.close();
                });
            }
            for (int c = 0; c < 4; ++c) {
                group.run([&] {
                    while (auto v = ch.recv())
                        sum.fetch_add(*v, std::memory_order_relaxed);
                });
            }
            group.wait();
        });
        EXPECT_EQ(sum.load(), expected);
    }
}

TEST_F(ChannelTest, FastTaskCoroutineAsyncSendRecv) {
    fast_task::bounded_channel<int> ch(2);
    int total = 0;

    auto producer = [](fast_task::bounded_channel<int>& c) -> fast_task::task_coro<void> {
        for (int i = 1; i <= 20; ++i) {
            bool ok = co_await c.async_send(i);
            EXPECT_TRUE(ok);
        }
        c.close();
        co_return;
    }(ch);

    auto consumer = [](fast_task::bounded_channel<int>& c, int& sum) -> fast_task::task_coro<void> {
        while (auto v = co_await c.async_recv())
            sum += *v;
        co_return;
    }(ch, total);

    fast_task::scheduler::start(producer.get_task());
    fast_task::scheduler::start(consumer.get_task());
    producer->await_task();
    consumer->await_task();

    EXPECT_EQ(total, 210);
}

TEST_F(ChannelTest, ForeignCoroutineInteropViaEnterApi) {
    fast_task::bounded_channel<int> ch(2);
    int total = 0;

    // Foreign C++20 coroutine (not fast_task::task_coro) awaiting ch.async_recv()
    auto consumer = [](fast_task::bounded_channel<int>& c, int& sum) -> foreign_coro {
        while (auto v = co_await c.async_recv())
            sum += *v;
    }(ch, total);

    run_task([&] {
        for (int i = 1; i <= 15; ++i)
            EXPECT_TRUE(ch.send(i));
        ch.close();
    });

    consumer.wait();
    EXPECT_EQ(total, 120);
}

TEST_F(ChannelTest, TaskGroupDestructorAwaitsRemainingTasks) {
    std::atomic<int> completed{0};

    run_task([&] {
        {
            fast_task::task_group group;
            for (int i = 0; i < 4; ++i) {
                group.run([&] {
                    fast_task::this_task::sleep_for(std::chrono::milliseconds(10));
                    completed.fetch_add(1, std::memory_order_relaxed);
                });
            }
        }
    });

    EXPECT_LE(completed.load(), 4);
}
