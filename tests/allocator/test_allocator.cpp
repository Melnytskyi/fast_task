// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <allocator.hpp>
#include <array>
#include <helpers.hpp>
#include <list>
#include <set>
#include <thread>
#include <vector>

#include "tasks/util/fixed_task_allocator.hpp"

TEST(Allocator, AllocateAndFree) {
    void* p = fast_task::allocate(64);
    ASSERT_NE(p, nullptr);
    fast_task::free(p);
}

TEST(Allocator, AllocateZeroBytes) {
    void* p = fast_task::allocate(0);
    fast_task::free(p);
}

TEST(Allocator, MultipleFreeIndependent) {
    void* a = fast_task::allocate(128);
    void* b = fast_task::allocate(256);
    ASSERT_NE(a, b);
    fast_task::free(a);
    fast_task::free(b);
}

TEST(Allocator, TaggedNewDelete) {
    int* p = new(fast_task::at) int(42);
    ASSERT_NE(p, nullptr);
    EXPECT_EQ(*p, 42);
    operator delete(p, fast_task::at);
}

TEST(Allocator, TaggedNewArrayDelete) {
    int* p = new(fast_task::at) int[10];
    ASSERT_NE(p, nullptr);
    for (int i = 0; i < 10; ++i)
        p[i] = i;
    EXPECT_EQ(p[9], 9);
    operator delete[](p, fast_task::at);
}

TEST(Allocator, VectorInt) {
    std::vector<int, fast_task::allocator<int>> v;
    for (int i = 0; i < 100; ++i)
        v.push_back(i);
    ASSERT_EQ(v.size(), 100u);
    for (int i = 0; i < 100; ++i)
        EXPECT_EQ(v[i], i);
}

TEST(Allocator, ListString) {
    std::list<std::string, fast_task::allocator<std::string>> l;
    l.push_back("hello");
    l.push_back("world");
    ASSERT_EQ(l.size(), 2u);
    auto it = l.begin();
    EXPECT_EQ(*it++, "hello");
    EXPECT_EQ(*it,   "world");
}

TEST(Allocator, AllocatorEquality) {
    fast_task::allocator<int> a1;
    fast_task::allocator<double> a2;
    EXPECT_TRUE(a1 == a2);
    EXPECT_FALSE(a1 != a2);
}

TEST(Allocator, AllocatorAllocateDeallocate) {
    fast_task::allocator<int> alloc;
    int* p = alloc.allocate(10);
    ASSERT_NE(p, nullptr);
    for (int i = 0; i < 10; ++i)
        p[i] = i * 2;
    EXPECT_EQ(p[5], 10);
    (void)alloc.deallocate(p, 10);
}

using namespace fast_task;

TEST(BlockAllocator, SingleThreadAllocFree) {
    task_object* p = task_alloc::allocate();
    ASSERT_NE(p, nullptr);
    task_alloc::deallocate(p);
}

TEST(BlockAllocator, Alignment) {
    for (int i = 0; i < 100; ++i) {
        task_object* p = task_alloc::allocate();
        ASSERT_NE(p, nullptr);
        EXPECT_EQ(reinterpret_cast<uintptr_t>(p) & 63, 0u)
            << "Block " << i << " at " << p << " not 64-byte aligned";
        task_alloc::deallocate(p);
    }
}

TEST(BlockAllocator, BootstrapBatch) {
    std::vector<task_object*> blocks;
    blocks.reserve(200);
    for (int i = 0; i < 200; ++i) {
        task_object* p = task_alloc::allocate();
        ASSERT_NE(p, nullptr);
        blocks.push_back(p);
    }
    std::set<task_object*> unique(blocks.begin(), blocks.end());
    EXPECT_EQ(unique.size(), blocks.size());

    for (auto* p : blocks)
        task_alloc::deallocate(p);
}

TEST(BlockAllocator, LIFOReuse) {
    task_object* first = task_alloc::allocate();
    task_object* second = task_alloc::allocate();
    ASSERT_NE(first, second);

    task_alloc::deallocate(second);
    task_object* reused = task_alloc::allocate();
    EXPECT_EQ(reused, second) << "Expected LIFO reuse of second block";

    task_alloc::deallocate(first);
    task_object* reused_first = task_alloc::allocate();
    EXPECT_EQ(reused_first, first) << "Expected LIFO reuse of first block";

    task_alloc::deallocate(reused_first);
    task_alloc::deallocate(reused);
}

TEST(BlockAllocator, WatermarkBulkReturn) {
    std::vector<task_object*> blocks;
    blocks.reserve(300);
    for (int i = 0; i < 257; ++i) {
        task_object* p = task_alloc::allocate();
        ASSERT_NE(p, nullptr);
        blocks.push_back(p);
    }
    for (auto* p : blocks)
        task_alloc::deallocate(p);

    for (int i = 0; i < 129; ++i) {
        task_object* p = task_alloc::allocate();
        ASSERT_NE(p, nullptr);
    }
    task_object* p = task_alloc::allocate();
    ASSERT_NE(p, nullptr);
    task_alloc::deallocate(p);
}

TEST(BlockAllocator, GeometricGrowth) {
    std::vector<task_object*> blocks1, blocks2, blocks3;
    blocks1.reserve(200);
    for (int i = 0; i < 200; ++i) {
        task_object* p = task_alloc::allocate();
        ASSERT_NE(p, nullptr);
        blocks1.push_back(p);
    }
    for (auto* p : blocks1)
        task_alloc::deallocate(p);

    blocks2.reserve(300);
    for (int i = 0; i < 300; ++i) {
        task_object* p = task_alloc::allocate();
        ASSERT_NE(p, nullptr);
        blocks2.push_back(p);
    }
    for (auto* p : blocks2)
        task_alloc::deallocate(p);

    blocks3.reserve(500);
    for (int i = 0; i < 500; ++i) {
        task_object* p = task_alloc::allocate();
        ASSERT_NE(p, nullptr);
        blocks3.push_back(p);
    }
    for (auto* p : blocks3)
        task_alloc::deallocate(p);

    SUCCEED();
}

TEST(BlockAllocator, MultiThreadContention) {
    constexpr int num_threads = 4;
    constexpr int blocks_per_thread = 200;
    std::vector<std::thread> threads;
    std::atomic<bool> failed{false};

    for (int t = 0; t < num_threads; ++t) {
        threads.emplace_back([&failed]() {
            std::vector<task_object*> blocks;
            blocks.reserve(blocks_per_thread);
            for (int i = 0; i < blocks_per_thread; ++i) {
                task_object* p = task_alloc::allocate();
                if (!p) {
                    failed.store(true, std::memory_order_relaxed);
                    return;
                }
                // Verify alignment
                if (reinterpret_cast<uintptr_t>(p) & 63) {
                    failed.store(true, std::memory_order_relaxed);
                    return;
                }
                blocks.push_back(p);
            }
            for (auto* p : blocks)
                task_alloc::deallocate(p);
        });
    }

    for (auto& th : threads)
        th.join();

    EXPECT_FALSE(failed.load()) << "One or more threads encountered an error";
}

TEST(BlockAllocator, CrossThreadAllocFree) {
    task_object* p = nullptr;
    std::thread alloc_thread([&p]() {
        p = task_alloc::allocate();
        ASSERT_NE(p, nullptr);
    });
    alloc_thread.join();

    ASSERT_NE(p, nullptr);
    std::thread free_thread([p]() {
        task_alloc::deallocate(p);
    });
    free_thread.join();

    SUCCEED();
}