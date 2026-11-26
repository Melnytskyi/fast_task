// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <atomic>
#include <coroutine>
#include <fast_task/coroutine.hpp>
#include <fast_task/task.hpp>
#include <helpers.hpp>
#include <numeric>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
    struct foreign_sync_coro {
        struct promise_type {
            fast_task::native::mutex mut;
            fast_task::native::condition_variable cv;
            bool finished = false;

            foreign_sync_coro get_return_object() {
                return foreign_sync_coro{std::coroutine_handle<promise_type>::from_promise(*this)};
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

        ~foreign_sync_coro() {
            if (h)
                h.destroy();
        }
    };
}

class SyncPrimitivesExtTest : public SchedulerFixture {};

TEST_F(SyncPrimitivesExtTest, ManualResetEventWaitResetAndForeignCoro) {
    fast_task::manual_reset_event ev;
    EXPECT_FALSE(ev.is_set());

    std::atomic<int> woken{0};
    auto foreign = [](fast_task::manual_reset_event& e, std::atomic<int>& cnt) -> foreign_sync_coro {
        co_await e.async_wait();
        cnt.fetch_add(1, std::memory_order_relaxed);
    }(ev, woken);

    run_task([&] {
        fast_task::task_group g;
        for (int i = 0; i < 3; ++i) {
            g.run([&] {
                ev.wait();
                woken.fetch_add(1, std::memory_order_relaxed);
            });
        }
        fast_task::this_task::sleep_for(std::chrono::milliseconds(15));
        EXPECT_EQ(woken.load(), 0);
        ev.set();
        g.wait();
    });

    foreign.wait();
    EXPECT_EQ(woken.load(), 4);
    EXPECT_TRUE(ev.is_set());

    ev.reset();
    EXPECT_FALSE(ev.is_set());
    run_task([&] {
        EXPECT_FALSE(ev.wait_for(std::chrono::milliseconds(15)));
    });
}

TEST_F(SyncPrimitivesExtTest, AutoResetEventWakesOneAtATime) {
    fast_task::auto_reset_event ev;
    std::atomic<int> woken{0};

    run_task([&] {
        auto t1 = fast_task::task::run([&] {
            ev.wait();
            woken.fetch_add(1, std::memory_order_relaxed);
        });
        auto t2 = fast_task::task::run([&] {
            ev.wait();
            woken.fetch_add(1, std::memory_order_relaxed);
        });

        fast_task::this_task::sleep_for(std::chrono::milliseconds(15));
        ev.set();
        fast_task::this_task::sleep_for(std::chrono::milliseconds(20));
        EXPECT_EQ(woken.load(), 1);

        ev.set();
        t1.await_task();
        t2.await_task();
    });

    EXPECT_EQ(woken.load(), 2);
    EXPECT_FALSE(ev.try_wait());
}

TEST_F(SyncPrimitivesExtTest, OnceFlagSingleExecutionAndExceptionRetry) {
    fast_task::once_flag flag;
    std::atomic<int> attempts{0};
    std::atomic<int> successes{0};

    run_task([&] {
        // First call throws -> flag rolls back so subsequent call succeeds.
        EXPECT_THROW(
            fast_task::call_once(flag, [&] {
                attempts.fetch_add(1, std::memory_order_relaxed);
                throw std::runtime_error("init_fail");
            }),
            std::runtime_error
        );
        EXPECT_FALSE(flag.is_done());

        fast_task::task_group g;
        for (int i = 0; i < 8; ++i) {
            g.run([&] {
                fast_task::call_once(flag, [&] {
                    fast_task::this_task::sleep_for(std::chrono::milliseconds(10));
                    successes.fetch_add(1, std::memory_order_relaxed);
                });
            });
        }
        g.wait();
    });

    EXPECT_TRUE(flag.is_done());
    EXPECT_EQ(attempts.load(), 1);
    EXPECT_EQ(successes.load(), 1);
}

TEST_F(SyncPrimitivesExtTest, LatchFanOutFanInAndCoroutineWait) {
    constexpr int N = 16;
    fast_task::latch done(N);
    std::atomic<int> counter{0};

    auto waiter = [](fast_task::latch& l) -> fast_task::task_coro<void> {
        co_await l.async_wait();
        co_return;
    }(done);
    fast_task::scheduler::start(waiter.get_task());

    run_task([&] {
        for (int i = 0; i < N; ++i) {
            fast_task::task::run([&] {
                counter.fetch_add(1, std::memory_order_relaxed);
                done.count_down();
            });
        }
        done.wait();
    });

    waiter->await_task();
    EXPECT_TRUE(done.try_wait());
    EXPECT_EQ(counter.load(), N);
}

TEST_F(SyncPrimitivesExtTest, BarrierMultiPhaseAndCompletion) {
    constexpr int workers = 4;
    constexpr int phases = 6;
    std::atomic<int> completion_runs{0};
    std::atomic<int> total_steps{0};

    fast_task::barrier bar(workers, [&]() noexcept {
        completion_runs.fetch_add(1, std::memory_order_relaxed);
    });

    run_task([&] {
        fast_task::task_group g;
        for (int w = 0; w < workers; ++w) {
            g.run([&] {
                for (int p = 0; p < phases; ++p) {
                    total_steps.fetch_add(1, std::memory_order_relaxed);
                    bar.arrive_and_wait();
                }
            });
        }
        g.wait();
    });

    EXPECT_EQ(completion_runs.load(), phases);
    EXPECT_EQ(total_steps.load(), workers * phases);
}

TEST_F(SyncPrimitivesExtTest, OneshotEmbeddedDetachedExceptionAndForeignCoro) {
    // Embedded zero-alloc oneshot
    {
        fast_task::oneshot<int> os;
        run_task([&] {
            auto t = fast_task::task::run([&] {
                os.set_value(1234);
            });
            EXPECT_EQ(os.get(), 1234);
            t.await_task();
        });
    }

    // Detached sender/receiver with coroutine + foreign coroutine
    {
        auto [tx, rx] = fast_task::make_oneshot<std::string>();
        std::string got;
        auto foreign = [](fast_task::oneshot_receiver<std::string> r, std::string& out) -> foreign_sync_coro {
            out = co_await r.async_get();
        }(std::move(rx), got);

        run_task([&] {
            EXPECT_TRUE(tx.send("hello-oneshot"));
        });
        foreign.wait();
        EXPECT_EQ(got, "hello-oneshot");
    }

    // Broken sender (dropped without sending) returns nullopt
    {
        auto [tx, rx] = fast_task::make_oneshot<int>();
        {
            auto dropped = std::move(tx);
            (void)dropped;
        }
        EXPECT_EQ(rx.recv(), std::nullopt);
    }

    // Exception propagation
    {
        auto [tx, rx] = fast_task::make_oneshot<int>();
        tx.set_exception(std::make_exception_ptr(std::runtime_error("oneshot_err")));
        EXPECT_THROW((void)rx.get(), std::runtime_error);
    }
}

TEST_F(SyncPrimitivesExtTest, CancellationSourceTreeCallbacksAndAwait) {
    fast_task::cancellation_source root;
    fast_task::cancellation_source child(root.token());

    std::atomic<int> cb_count{0};
    fast_task::cancellation_callback cb1(root.token(), [&] { cb_count.fetch_add(1); });
    fast_task::cancellation_callback cb2(child.token(), [&] { cb_count.fetch_add(1); });

    std::atomic<bool> foreign_woke{false};
    auto foreign = [](fast_task::cancellation_token tok, std::atomic<bool>& woke) -> foreign_sync_coro {
        co_await tok.async_wait();
        woke.store(true, std::memory_order_release);
    }(child.token(), foreign_woke);

    EXPECT_FALSE(root.is_cancelled());
    EXPECT_FALSE(child.is_cancelled());
    EXPECT_TRUE(root.cancel());
    EXPECT_FALSE(root.cancel()); // idempotent

    foreign.wait();
    EXPECT_TRUE(root.is_cancelled());
    EXPECT_TRUE(child.is_cancelled());
    EXPECT_TRUE(foreign_woke.load());
    EXPECT_EQ(cb_count.load(), 2);
}

TEST_F(SyncPrimitivesExtTest, SpscChannelWaitFreeAndCoroutine) {
    fast_task::spsc_channel<int> ch(16);
    EXPECT_EQ(ch.capacity(), 16u);
    constexpr int count = 2000;
    int sum = 0;

    auto consumer = [](fast_task::spsc_channel<int>& c, int& out) -> fast_task::task_coro<void> {
        while (auto v = co_await c.async_recv())
            out += *v;
        co_return;
    }(ch, sum);
    fast_task::scheduler::start(consumer.get_task());

    run_task([&] {
        for (int i = 1; i <= count; ++i)
            EXPECT_TRUE(ch.send(i));
        ch.close();
    });

    consumer->await_task();
    EXPECT_EQ(sum, count * (count + 1) / 2);
}

TEST_F(SyncPrimitivesExtTest, WatchChannelMultiSubscriberAndCoroutine) {
    fast_task::watch_channel<int> ch(0);
    auto rx1 = ch.subscribe();
    auto rx2 = ch.subscribe();
    EXPECT_EQ(rx1.borrow_copy(), 0);

    std::vector<int> seen_by_coro;
    auto coro = [](fast_task::watch_receiver<int> r, std::vector<int>& out) -> fast_task::task_coro<void> {
        while (co_await r.async_changed())
            out.push_back(r.borrow_copy());
        co_return;
    }(rx2, seen_by_coro);
    fast_task::scheduler::start(coro.get_task());

    run_task([&] {
        EXPECT_TRUE(ch.send(10));
        EXPECT_TRUE(rx1.changed());
        EXPECT_EQ(rx1.borrow_copy(), 10);

        fast_task::this_task::sleep_for(std::chrono::milliseconds(10));
        EXPECT_TRUE(ch.send(42));
        EXPECT_TRUE(rx1.changed());
        EXPECT_EQ(rx1.borrow_copy(), 42);
        ch.close();
        EXPECT_FALSE(rx1.changed());
    });

    coro->await_task();
    ASSERT_FALSE(seen_by_coro.empty());
    EXPECT_EQ(seen_by_coro.back(), 42);
}

TEST_F(SyncPrimitivesExtTest, SeqlockConcurrentReadersAndWriter) {
    struct Pair {
        uint64_t a;
        uint64_t b;
    };
    fast_task::seqlock<Pair> sl(Pair{0, 0});
    std::atomic<bool> stop{false};
    std::atomic<bool> torn{false};

    run_task([&] {
        fast_task::task_group g;
        for (int r = 0; r < 3; ++r) {
            g.run([&] {
                while (!stop.load(std::memory_order_relaxed)) {
                    Pair p = sl.read();
                    if (p.a != p.b)
                        torn.store(true, std::memory_order_relaxed);
                }
            });
        }
        for (uint64_t i = 1; i <= 5000; ++i)
            sl.write(Pair{i, i});
        stop.store(true, std::memory_order_relaxed);
        g.wait();
    });

    EXPECT_FALSE(torn.load());
    Pair final_val = sl.read();
    EXPECT_EQ(final_val.a, 5000u);
    EXPECT_EQ(final_val.b, 5000u);
}

TEST_F(SyncPrimitivesExtTest, TickerPeriodicAndSkipPolicy) {
    fast_task::ticker t(std::chrono::milliseconds(10), fast_task::missed_tick_policy::skip);
    auto start = fast_task::clock::now();
    run_task([&] {
        t.tick();
        t.tick();
    });
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(fast_task::clock::now() - start);
    EXPECT_GE(elapsed.count(), 15);
}

TEST_F(SyncPrimitivesExtTest, RateLimiterBurstAndAcquire) {
    // 200 permits/sec (5ms each), burst of 3
    fast_task::rate_limiter rl(200.0, 3);
    EXPECT_TRUE(rl.try_acquire());
    EXPECT_TRUE(rl.try_acquire());
    EXPECT_TRUE(rl.try_acquire());
    EXPECT_FALSE(rl.try_acquire());

    run_task([&] {
        auto start = fast_task::clock::now();
        rl.acquire();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(fast_task::clock::now() - start);
        EXPECT_GE(elapsed.count(), 3);
    });
}

TEST_F(SyncPrimitivesExtTest, ParallelForAndReduceAndAsyncHelper) {
    constexpr size_t N = 50'000;
    std::vector<int> data(N, 0);

    run_task([&] {
        fast_task::parallel_for(size_t(0), N, [&](size_t b, size_t e) {
            for (size_t i = b; i < e; ++i)
                data[i] = static_cast<int>(i % 100);
        }, 512);

        int64_t sum = fast_task::parallel_reduce(
            size_t(0), N, int64_t(0),
            [&](size_t b, size_t e) {
                int64_t local = 0;
                for (size_t i = b; i < e; ++i)
                    local += data[i];
                return local;
            },
            std::plus<int64_t>{},
            512
        );
        EXPECT_EQ(sum, static_cast<int64_t>(N / 100) * (99 * 100 / 2));

        // Exception propagation in parallel_for
        EXPECT_THROW(
            fast_task::parallel_for(size_t(0), size_t(1000), [](size_t b, size_t e) {
                if (b <= 500 && 500 < e)
                    throw std::runtime_error("pf_err");
            }, 64),
            std::runtime_error
        );
    });

    // Type-deducing fast_task::async()
    auto f1 = fast_task::async([] { return 21 * 2; });
    auto f2 = fast_task::async([] { return std::string("deduced"); });
    EXPECT_EQ(f1->get(), 42);
    EXPECT_EQ(f2->get(), "deduced");
}
