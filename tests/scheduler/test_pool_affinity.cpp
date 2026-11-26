// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <algorithm>
#include <atomic>
#include <helpers.hpp>
#include <vector>

namespace {
    std::vector<uint32_t> allowed_cpus() {
        return fast_task::native::this_thread::get_affinity();
    }

    std::vector<uint32_t> sorted(std::vector<uint32_t> cpus) {
        std::sort(cpus.begin(), cpus.end());
        return cpus;
    }

    fast_task::scheduler::worker_pool_options affinity_options(uint16_t workers,
                                                               fast_task::scheduler::pool_affinity_mode mode,
                                                               std::vector<uint32_t> cpus) {
        fast_task::scheduler::worker_pool_options o;
        o.initial_workers = workers;
        o.start_with_worker_per_core = false;
        o.min_workers = 0;
        o.affinity.mode = mode;
        o.affinity.cpus = std::move(cpus);
        return o;
    }

    bool wait_workers(fast_task::scheduler::worker_pool& pool, uint16_t n) {
        const auto deadline = fast_task::clock::now() + std::chrono::seconds(5);
        while (pool.stats().active_workers < n && fast_task::clock::now() < deadline)
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        return pool.stats().active_workers >= n;
    }

    template <class Pred>
    bool eventually(Pred&& pred, std::chrono::milliseconds limit = std::chrono::seconds(5)) {
        const auto deadline = fast_task::clock::now() + limit;
        while (fast_task::clock::now() < deadline) {
            if (pred())
                return true;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        return pred();
    }

    struct release_guard {
        std::atomic<bool>& flag;
        ~release_guard() { flag.store(true, std::memory_order_release); }
    };

    fast_task::task observer(std::atomic<int>& started,
                             std::atomic<bool>& release,
                             std::vector<uint32_t>& mask_out) {
        return fast_task::task::create([&] {
            mask_out = fast_task::native::this_thread::get_affinity();
            started.fetch_add(1, std::memory_order_acq_rel);
            while (!release.load(std::memory_order_acquire))
                std::this_thread::yield();
        });
    }
}

TEST(PoolAffinity, MaskAppliesToEveryWorker) {
    const auto cpus = allowed_cpus();
    if (cpus.size() < 2)
        GTEST_SKIP() << "needs at least two cpus in the current mask";
    const std::vector<uint32_t> mask{cpus[0], cpus[1]};

    auto pool = fast_task::scheduler::worker_pool::create(
        affinity_options(2, fast_task::scheduler::pool_affinity_mode::mask, mask));
    ASSERT_TRUE(wait_workers(pool, 2));

    std::atomic<int> started{0};
    std::atomic<bool> release{false};
    release_guard guard{release};
    std::vector<uint32_t> first;
    std::vector<uint32_t> second;

    pool.post(observer(started, release, first));
    pool.post(observer(started, release, second));

    ASSERT_TRUE(eventually([&started] { return started.load() == 2; }))
        << "both tasks have to run concurrently to see both workers";
    release.store(true, std::memory_order_release);

    ASSERT_TRUE(pool.wait_idle(fast_task::clock::now() + std::chrono::seconds(5)));
    EXPECT_EQ(pool.stats().affinity_failures, 0u);
    EXPECT_EQ(sorted(first), sorted(mask));
    EXPECT_EQ(sorted(second), sorted(mask));
    fast_task::scheduler::shut_down();
}

TEST(PoolAffinity, RoundRobinPinsOneCpuPerWorker) {
    const auto cpus = allowed_cpus();
    if (cpus.size() < 2)
        GTEST_SKIP() << "needs at least two cpus in the current mask";
    const std::vector<uint32_t> list{cpus[0], cpus[1]};

    auto pool = fast_task::scheduler::worker_pool::create(
        affinity_options(2, fast_task::scheduler::pool_affinity_mode::round_robin, list));
    ASSERT_TRUE(wait_workers(pool, 2));

    std::atomic<int> started{0};
    std::atomic<bool> release{false};
    release_guard guard{release};
    std::vector<uint32_t> first;
    std::vector<uint32_t> second;

    pool.post(observer(started, release, first));
    pool.post(observer(started, release, second));

    ASSERT_TRUE(eventually([&started] { return started.load() == 2; }));
    release.store(true, std::memory_order_release);

    ASSERT_TRUE(pool.wait_idle(fast_task::clock::now() + std::chrono::seconds(5)));
    EXPECT_EQ(pool.stats().affinity_failures, 0u);

    ASSERT_EQ(first.size(), 1u);
    ASSERT_EQ(second.size(), 1u);
    auto pair = sorted({first[0], second[0]});
    EXPECT_EQ(pair, sorted(list));
}

TEST(PoolAffinity, RoundRobinWithoutCpusThrows) {
    EXPECT_THROW(
        fast_task::scheduler::worker_pool::create(
            affinity_options(0, fast_task::scheduler::pool_affinity_mode::round_robin, {})),
        std::invalid_argument);
}

TEST(PoolAffinity, RejectedMaskIsCountedNotFatal) {
    if (allowed_cpus().empty())
        GTEST_SKIP() << "the platform does not report a cpu mask";

    auto pool = fast_task::scheduler::worker_pool::create(
        affinity_options(1, fast_task::scheduler::pool_affinity_mode::mask, {1000000u}));
    ASSERT_TRUE(wait_workers(pool, 1));

    std::atomic<int> started{0};
    std::atomic<bool> release{false};
    release_guard guard{release};
    std::vector<uint32_t> observed;
    pool.post(observer(started, release, observed));

    ASSERT_TRUE(eventually([&started] { return started.load() == 1; }));
    release.store(true, std::memory_order_release);
    ASSERT_TRUE(pool.wait_idle(fast_task::clock::now() + std::chrono::seconds(5)));

    EXPECT_GE(pool.stats().affinity_failures, 1u);
    EXPECT_FALSE(observed.empty()) << "the worker must have run on the inherited mask";
    fast_task::scheduler::shut_down();
}

TEST(PoolAffinity, EmptyListKeepsTheInheritedMask) {
    const auto inherited = allowed_cpus();
    if (inherited.empty())
        GTEST_SKIP() << "the platform does not report a cpu mask";

    auto pool = fast_task::scheduler::worker_pool::create(
        affinity_options(1, fast_task::scheduler::pool_affinity_mode::mask, {}));
    ASSERT_TRUE(wait_workers(pool, 1));

    std::atomic<int> started{0};
    std::atomic<bool> release{false};
    release_guard guard{release};
    std::vector<uint32_t> observed;
    auto t = observer(started, release, observed);
    pool.post(t);

    ASSERT_TRUE(eventually([&started] { return started.load() == 1; }));
    release.store(true, std::memory_order_release);

    ASSERT_TRUE(pool.wait_idle(fast_task::clock::now() + std::chrono::seconds(5)));
    EXPECT_EQ(pool.stats().affinity_failures, 0u);
    EXPECT_EQ(sorted(observed), sorted(inherited));
    fast_task::scheduler::shut_down();
}
