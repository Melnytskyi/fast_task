// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <helpers.hpp>
#include <allocator.hpp>
#include <vector>
#include <list>
#include <array>

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
    alloc.deallocate(p, 10);
}
