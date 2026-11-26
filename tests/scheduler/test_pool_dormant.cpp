// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <atomic>
#include <thread>

#include <fast_task/interrupt.hpp>
#include <helpers.hpp>

namespace {
    fast_task::scheduler::worker_pool_options dormant_options(uint16_t workers) {
        fast_task::scheduler::worker_pool_options o;
        o.initial_workers = workers;
        o.start_with_worker_per_core = false;
        o.min_workers = 0;
        o.max_workers = 8;
        return o;
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

    bool park_one(fast_task::scheduler::worker_pool& pool) {
        if (pool.stats().target_workers == 0)
            return false;
        pool.remove_workers(1);
        return eventually([&pool] {
            const auto st = pool.stats();
            return st.dormant_workers >= 1 && st.active_workers == st.target_workers;
        });
    }
}

TEST(PoolDormant, ExcessWorkerParksAndRejoins) {
    auto pool = fast_task::scheduler::worker_pool::create(dormant_options(2));
    ASSERT_TRUE(eventually([&pool] { return pool.stats().active_workers == 2; }));

    ASSERT_TRUE(park_one(pool));
    EXPECT_EQ(pool.stats().active_workers, 1u);
    EXPECT_EQ(pool.stats().target_workers, 1u);
    EXPECT_EQ(pool.stats().live_threads, 2u);

    pool.add_workers(1);
    ASSERT_TRUE(eventually([&pool] { return pool.stats().dormant_workers == 0; }));
    EXPECT_TRUE(eventually([&pool] { return pool.stats().active_workers == 2; }));
    EXPECT_EQ(pool.stats().live_threads, 2u);

    fast_task::scheduler::shut_down();
}

TEST(PoolDormant, DormantWorkerServesItsOwnBurst) {
    auto pool = fast_task::scheduler::worker_pool::create(dormant_options(2));
    ASSERT_TRUE(eventually([&pool] { return pool.stats().active_workers == 2; }));
    ASSERT_TRUE(park_one(pool));

    constexpr int N = 16;
    std::atomic<int> ran{0};
    for (int i = 0; i < N; ++i)
        pool.post(fast_task::task::create([&ran] { ran.fetch_add(1); }));

    EXPECT_TRUE(eventually([&ran] { return ran.load() == N; }));
    EXPECT_EQ(ran.load(), N);

    fast_task::scheduler::shut_down();
}

TEST(PoolDormant, BorrowedWorkerRunsTheNestedBurst) {
    auto lender_opts = dormant_options(2);
    lender_opts.allow_dormant_sharing = true;
    auto lender = fast_task::scheduler::worker_pool::create(lender_opts);
    ASSERT_TRUE(eventually([&lender] { return lender.stats().active_workers == 2; }));
    ASSERT_TRUE(park_one(lender));

    auto borrower_opts = dormant_options(1);
    borrower_opts.max_workers = 2;
    auto borrower = fast_task::scheduler::worker_pool::create(borrower_opts);
    ASSERT_TRUE(eventually([&borrower] { return borrower.stats().active_workers == 1; }));

    std::atomic<bool> nested_ran{false};
    borrower.post(fast_task::task::create([&borrower, &nested_ran] {
        borrower.post(fast_task::task::create([&nested_ran] { nested_ran.store(true); }));
        fast_task::interrupt_unsafe_region no_preempt;
        for (int i = 0; i < 3000 && !nested_ran.load(); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }));

    EXPECT_TRUE(eventually([&nested_ran] { return nested_ran.load(); }, std::chrono::seconds(10)));
    EXPECT_TRUE(eventually([&borrower, &lender] {
        return borrower.stats().borrowed_in == 0 && lender.stats().borrowed_out == 0;
    }));
    EXPECT_EQ(borrower.stats().borrowed_in, 0u);
    EXPECT_EQ(lender.stats().borrowed_out, 0u);

    fast_task::scheduler::shut_down();
}

TEST(PoolDormant, SingleThreadLenderIsNeverLent) {
    auto lender_opts = dormant_options(1);
    lender_opts.allow_dormant_sharing = true;
    auto lender = fast_task::scheduler::worker_pool::create(lender_opts);
    ASSERT_TRUE(eventually([&lender] { return lender.stats().active_workers == 1; }));

    lender.remove_workers(1);
    ASSERT_TRUE(eventually([&lender] {
        const auto st = lender.stats();
        return st.dormant_workers == 1 && st.active_workers == 0;
    }));
    ASSERT_EQ(lender.stats().active_workers, 0u);

    auto borrower_opts = dormant_options(1);
    borrower_opts.max_workers = 2;
    auto borrower = fast_task::scheduler::worker_pool::create(borrower_opts);
    ASSERT_TRUE(eventually([&borrower] { return borrower.stats().active_workers == 1; }));

    std::atomic<bool> nested_ran{false};
    std::atomic<bool> ran_while_blocked{false};
    borrower.post(fast_task::task::create([&borrower, &nested_ran, &ran_while_blocked] {
        borrower.post(fast_task::task::create([&nested_ran] { nested_ran.store(true); }));
        fast_task::interrupt_unsafe_region no_preempt;
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        ran_while_blocked.store(nested_ran.load());
    }));

    EXPECT_TRUE(eventually([&nested_ran] { return nested_ran.load(); }));
    EXPECT_FALSE(ran_while_blocked.load());
    EXPECT_EQ(lender.stats().borrowed_out, 0u);
    EXPECT_EQ(borrower.stats().borrowed_in, 0u);

    fast_task::scheduler::shut_down();
}

TEST(PoolDormant, AffinityPinnedLenderIsSkipped) {
    auto lender_opts = dormant_options(2);
    lender_opts.allow_dormant_sharing = true;
    lender_opts.affinity.cpus = {0};
    auto lender = fast_task::scheduler::worker_pool::create(lender_opts);
    ASSERT_TRUE(eventually([&lender] { return lender.stats().active_workers == 2; }));
    ASSERT_TRUE(park_one(lender));

    auto borrower_opts = dormant_options(1);
    borrower_opts.max_workers = 2;
    auto borrower = fast_task::scheduler::worker_pool::create(borrower_opts);
    ASSERT_TRUE(eventually([&borrower] { return borrower.stats().active_workers == 1; }));

    std::atomic<bool> nested_ran{false};
    std::atomic<bool> ran_while_blocked{false};
    borrower.post(fast_task::task::create([&borrower, &nested_ran, &ran_while_blocked] {
        borrower.post(fast_task::task::create([&nested_ran] { nested_ran.store(true); }));
        fast_task::interrupt_unsafe_region no_preempt;
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        ran_while_blocked.store(nested_ran.load());
    }));

    EXPECT_TRUE(eventually([&nested_ran] { return nested_ran.load(); }));
    EXPECT_FALSE(ran_while_blocked.load());
    EXPECT_EQ(lender.stats().borrowed_out, 0u);

    fast_task::scheduler::shut_down();
}

TEST(PoolDormant, SharingIsOffByDefault) {
    auto lender = fast_task::scheduler::worker_pool::create(dormant_options(2));
    ASSERT_TRUE(eventually([&lender] { return lender.stats().active_workers == 2; }));
    ASSERT_TRUE(park_one(lender));

    auto borrower_opts = dormant_options(1);
    borrower_opts.max_workers = 2;
    auto borrower = fast_task::scheduler::worker_pool::create(borrower_opts);
    ASSERT_TRUE(eventually([&borrower] { return borrower.stats().active_workers == 1; }));

    std::atomic<bool> nested_ran{false};
    std::atomic<bool> ran_while_blocked{false};
    borrower.post(fast_task::task::create([&borrower, &nested_ran, &ran_while_blocked] {
        borrower.post(fast_task::task::create([&nested_ran] { nested_ran.store(true); }));
        fast_task::interrupt_unsafe_region no_preempt;
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        ran_while_blocked.store(nested_ran.load());
    }));

    EXPECT_TRUE(eventually([&nested_ran] { return nested_ran.load(); }));
    EXPECT_FALSE(ran_while_blocked.load());
    EXPECT_EQ(lender.stats().borrowed_out, 0u);

    fast_task::scheduler::shut_down();
}
