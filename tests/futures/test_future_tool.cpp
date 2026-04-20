// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <algorithm>
#include <atomic>
#include <future.hpp>
#include <helpers.hpp>
#include <numeric>
#include <vector>

class FutureToolTest : public SchedulerFixture {};

// ---- for_each ----

TEST_F(FutureToolTest, ForEachProcessesAll) {
    std::vector<int> input = {1, 2, 3, 4, 5};
    std::atomic<int> sum{0};
    auto f = fast_task::future_tool::for_each(input, [&](int v) { sum += v; });
    f->wait();
    EXPECT_EQ(sum.load(), 15);
}

TEST_F(FutureToolTest, ForEachEmpty) {
    std::vector<int> empty;
    auto f = fast_task::future_tool::for_each(empty, [](int) {});
    EXPECT_TRUE(f->is_ready());
    f->get();
}

// ---- for_each_move ----

TEST_F(FutureToolTest, ForEachMoveProcessesAll) {
    std::vector<std::string> input = {"a", "b", "c"};
    std::atomic<int> count{0};
    auto f = fast_task::future_tool::for_each_move(std::move(input), [&](std::string s) { ++count; });
    f->wait();
    EXPECT_EQ(count.load(), 3);
}

// ---- for_each_wait ----

TEST_F(FutureToolTest, ForEachWaitBlocks) {
    std::vector<int> input = {10, 20};
    std::atomic<int> sum{0};
    fast_task::future_tool::for_each_wait(input, [&](int v) { sum += v; });
    EXPECT_EQ(sum.load(), 30);
}

// ---- process ----

TEST_F(FutureToolTest, ProcessReturnsResults) {
    std::vector<int> input = {1, 2, 3};
    auto results = fast_task::future_tool::process<int>(input, [](int v) { return v * v; });
    std::sort(results.begin(), results.end());
    EXPECT_EQ(results, (std::vector<int>{1, 4, 9}));
}

// ---- chain ----

TEST_F(FutureToolTest, ChainTransforms) {
    auto f = fast_task::future<int>::start([] { return 5; });
    auto chained = fast_task::future_tool::chain<int, int>(
        f, std::function<int(int)>([](int v) { return v * 3; }));
    EXPECT_EQ(chained->get(), 15);
}

// ---- accumulate ----

// NOTE: future_tool::accumulate is disabled due to a library bug:
// it calls fut.for_each(...) on a std::vector which has no such member.

// ---- combine_all ----

TEST_F(FutureToolTest, CombineAll) {
    std::vector<fast_task::future_ptr<void>> futures;
    std::atomic<int> count{0};
    futures.push_back(fast_task::future<void>::start([&] { ++count; }));
    futures.push_back(fast_task::future<void>::start([&] { ++count; }));

    auto all = fast_task::future_tool::combine_all(futures);
    all->wait();
    EXPECT_EQ(count.load(), 2);
}
