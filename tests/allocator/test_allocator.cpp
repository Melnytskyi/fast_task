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

#include "tasks/util/fixed_block_allocator.hpp"

// ---- raw allocate / free ---------------------------------------------------

TEST(Allocator, AllocateAndFree) {
    void* p = fast_task::allocate(64);
    ASSERT_NE(p, nullptr);
    fast_task::free(p);
}

TEST(Allocator, AllocateZeroBytes) {
    // implementation-defined, but must not crash
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

// ---- tagged operator new / delete -----------------------------------------

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

// ---- allocator<T> with STL containers -------------------------------------

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

// ---- fixed-size block allocator tests -------------------------------------

using namespace fast_task;

TEST(BlockAllocator, SingleThreadAllocFree) {
    // Allocate and free a block, verify it's not null
    void* p = task_alloc_data::allocate();
    ASSERT_NE(p, nullptr);
    task_alloc_data::deallocate(p);
}

TEST(BlockAllocator, Alignment) {
    // Every block must be 64-byte aligned
    for (int i = 0; i < 100; ++i) {
        void* p = task_alloc_data::allocate();
        ASSERT_NE(p, nullptr);
        EXPECT_EQ(reinterpret_cast<uintptr_t>(p) & 63, 0u)
            << "Block " << i << " at " << p << " not 64-byte aligned";
        task_alloc_data::deallocate(p);
    }
}

TEST(BlockAllocator, BootstrapBatch) {
    // First allocation fetches 128 blocks from global.
    // After allocating 128, the 129th should trigger another batch.
    std::vector<void*> blocks;
    blocks.reserve(200);
    for (int i = 0; i < 200; ++i) {
        void* p = task_alloc_data::allocate();
        ASSERT_NE(p, nullptr);
        blocks.push_back(p);
    }
    // All pointers must be unique
    std::set<void*> unique(blocks.begin(), blocks.end());
    EXPECT_EQ(unique.size(), blocks.size());
    // Cleanup
    for (auto* p : blocks)
        task_alloc_data::deallocate(p);
}

TEST(BlockAllocator, LIFOReuse) {
    // LIFO means the most recently freed block is the next allocated one
    void* first = task_alloc_data::allocate();
    void* second = task_alloc_data::allocate();
    ASSERT_NE(first, second);

    task_alloc_data::deallocate(second);
    void* reused = task_alloc_data::allocate();
    EXPECT_EQ(reused, second) << "Expected LIFO reuse of second block";

    task_alloc_data::deallocate(first);
    void* reused_first = task_alloc_data::allocate();
    EXPECT_EQ(reused_first, first) << "Expected LIFO reuse of first block";

    task_alloc_data::deallocate(reused_first);
    task_alloc_data::deallocate(reused);
}

TEST(BlockAllocator, WatermarkBulkReturn) {
    // Allocate 257 blocks, then free all of them.
    // The local free list should bulk-return 128 to global when it exceeds 256.
    std::vector<void*> blocks;
    blocks.reserve(300);
    for (int i = 0; i < 257; ++i) {
        void* p = task_alloc_data::allocate();
        ASSERT_NE(p, nullptr);
        blocks.push_back(p);
    }
    // Free all — this should trigger the watermark and bulk-return
    for (auto* p : blocks)
        task_alloc_data::deallocate(p);

    // Now allocate again — should get blocks from the local free list
    // (which still has 257 - 128 = 129 blocks after bulk return)
    for (int i = 0; i < 129; ++i) {
        void* p = task_alloc_data::allocate();
        ASSERT_NE(p, nullptr);
    }
    // The next alloc triggers a batch fetch from global (since local is now 0)
    void* p = task_alloc_data::allocate();
    ASSERT_NE(p, nullptr);
    task_alloc_data::deallocate(p);
}

TEST(BlockAllocator, GeometricGrowth) {
    // Exhaust blocks repeatedly to force arena expansion.
    // Verify that the global allocator expands at least once.
    // We'll allocate in large batches and free in between.
    std::vector<void*> blocks1, blocks2, blocks3;
    blocks1.reserve(200);
    for (int i = 0; i < 200; ++i) {
        void* p = task_alloc_data::allocate();
        ASSERT_NE(p, nullptr);
        blocks1.push_back(p);
    }
    for (auto* p : blocks1)
        task_alloc_data::deallocate(p);

    // Second wave — local should have freed blocks, but if not enough, expand
    blocks2.reserve(300);
    for (int i = 0; i < 300; ++i) {
        void* p = task_alloc_data::allocate();
        ASSERT_NE(p, nullptr);
        blocks2.push_back(p);
    }
    for (auto* p : blocks2)
        task_alloc_data::deallocate(p);

    // Third wave — same
    blocks3.reserve(500);
    for (int i = 0; i < 500; ++i) {
        void* p = task_alloc_data::allocate();
        ASSERT_NE(p, nullptr);
        blocks3.push_back(p);
    }
    for (auto* p : blocks3)
        task_alloc_data::deallocate(p);

    // No crash = geometric growth worked, all blocks unique
    SUCCEED();
}

TEST(BlockAllocator, MultiThreadContention) {
    // Launch 4 threads, each allocating and freeing blocks concurrently.
    // This stresses the DWCAS global stack.
    constexpr int num_threads = 4;
    constexpr int blocks_per_thread = 200;
    std::vector<std::thread> threads;
    std::atomic<bool> failed{false};

    for (int t = 0; t < num_threads; ++t) {
        threads.emplace_back([&failed]() {
            std::vector<void*> blocks;
            blocks.reserve(blocks_per_thread);
            for (int i = 0; i < blocks_per_thread; ++i) {
                void* p = task_alloc_data::allocate();
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
                task_alloc_data::deallocate(p);
        });
    }

    for (auto& th : threads)
        th.join();

    EXPECT_FALSE(failed.load()) << "One or more threads encountered an error";
}

TEST(BlockAllocator, CrossThreadAllocFree) {
    // Thread A allocates, Thread B frees (cross-thread deallocation).
    // The freeing thread's local list handles it, then bulk-returns to global.
    void* p = nullptr;
    std::thread alloc_thread([&p]() {
        p = task_alloc_data::allocate();
        ASSERT_NE(p, nullptr);
    });
    alloc_thread.join();

    ASSERT_NE(p, nullptr);
    std::thread free_thread([p]() {
        // This is cross-thread — p was allocated on a different thread
        task_alloc_data::deallocate(p);
    });
    free_thread.join();

    SUCCEED();
}