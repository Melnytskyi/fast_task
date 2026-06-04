// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#pragma once
#ifndef FAST_TASK_FIXED_BLOCK_ALLOCATOR
#define FAST_TASK_FIXED_BLOCK_ALLOCATOR

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>

#include <shared.hpp>
#include <interrupt.hpp>

namespace fast_task {

// -----------------------------------------------------------------------
//  Free-list node — embedded inside unallocated 128-byte blocks
// -----------------------------------------------------------------------
struct free_node {
    free_node* next;
};

// -----------------------------------------------------------------------
//  Tagged node — 128-bit DWCAS for ABA-safe lock-free LIFO
// -----------------------------------------------------------------------
struct alignas(16) tagged_node {
    free_node* ptr;
    uint64_t counter;
};

static_assert(sizeof(tagged_node) == 16,
    "tagged_node must be exactly 16 bytes for DWCAS");

// -----------------------------------------------------------------------
//  Global block allocator — owns all arenas, single atomic LIFO
// -----------------------------------------------------------------------
class FT_API_LOCAL global_block_allocator {
public:
    static constexpr size_t block_size = 128;
    static constexpr size_t block_alignment = 64;
    static constexpr size_t init_batch = 128;
    static constexpr size_t max_local = 256;
    static constexpr size_t min_arena_blocks = 128;

private:
    std::atomic<tagged_node> global_stack_;
    std::atomic<size_t> global_available_{0};

    // Arena tracking (only the global singleton owns arenas)
    struct arena {
        arena* next;
        void* base;
        size_t size;
    };
    arena* arena_list_ = nullptr;
    size_t last_arena_size_ = 0;

    // Allocate a new arena via aligned_alloc, slice into blocks,
    // and push the chain onto the global stack.
    void expand() {
        interrupt_unsafe_region ir;

        // Geometric growth: start at min_arena_blocks, double each time
        size_t num_blocks = min_arena_blocks;
        if (last_arena_size_ != 0) {
            num_blocks = last_arena_size_ / block_size * 2;
            if (num_blocks < min_arena_blocks)
                num_blocks = min_arena_blocks;
        }
        size_t arena_size = num_blocks * block_size;

        // arena_size must be a multiple of block_alignment for aligned_alloc
        void* base = std::aligned_alloc(block_alignment, arena_size);
        if (!base)
            throw std::bad_alloc();

        // Track the arena
        auto* a = static_cast<arena*>(std::malloc(sizeof(arena)));
        if (!a) {
            std::free(base);
            throw std::bad_alloc();
        }
        a->base = base;
        a->size = arena_size;
        a->next = arena_list_;
        arena_list_ = a;
        last_arena_size_ = arena_size;

        // Slice into blocks and link them
        auto* begin = static_cast<std::byte*>(base);
        auto* end = begin + arena_size;
        free_node* tail = nullptr;
        free_node* head = nullptr;
        for (auto* pos = begin; pos < end; pos += block_size) {
            auto* node = reinterpret_cast<free_node*>(pos);
            node->next = head;
            head = node;
            if (!tail)
                tail = node;
        }

        // Push the entire chain atomically onto the global stack
        tagged_node old = global_stack_.load(std::memory_order_acquire);
        while (true) {
            tail->next = old.ptr;
            tagged_node desired{head, old.counter + 1};
            if (global_stack_.compare_exchange_weak(old, desired,
                    std::memory_order_release, std::memory_order_acquire)) {
                break;
            }
        }
        global_available_.fetch_add(num_blocks, std::memory_order_relaxed);
    }

    // Walk 'count' nodes from head and return the node at position 'count'
    // (the new head after popping count nodes). Returns nullptr if chain
    // has fewer than count nodes.
    // Also returns the tail (last node of the batch) via output parameter.
    static free_node* advance(free_node* head, size_t count, free_node** out_batch_tail = nullptr) {
        auto* cur = head;
        auto* prev = static_cast<free_node*>(nullptr);
        for (size_t i = 0; i < count && cur; ++i) {
            prev = cur;
            cur = cur->next;
        }
        if (out_batch_tail)
            *out_batch_tail = prev;
        return cur;
    }

public:
    global_block_allocator() noexcept {
        tagged_node init{nullptr, 0};
        global_stack_.store(init, std::memory_order_relaxed);
    }

    ~global_block_allocator() {
        // Free all arenas
        auto* a = arena_list_;
        while (a) {
            auto* next = a->next;
            std::free(a->base);
            std::free(a);
            a = next;
        }
        arena_list_ = nullptr;
    }

    // Pop a batch of up to 'count' blocks from the global LIFO.
    // The returned chain is null-terminated.
    // Returns the head of the popped chain, or nullptr if empty.
    free_node* pop_batch(size_t count) {
        tagged_node old = global_stack_.load(std::memory_order_acquire);
        while (old.ptr) {
            free_node* batch_tail = nullptr;
            // Walk 'count' blocks forward. If the chain has fewer blocks,
            // advance returns nullptr and batch_tail is the last block.
            free_node* new_head = advance(old.ptr, count, &batch_tail);
            tagged_node desired{new_head, old.counter + 1};
            if (global_stack_.compare_exchange_weak(old, desired,
                    std::memory_order_release, std::memory_order_acquire)) {
                // Null-terminate the popped batch so no one walks past it
                batch_tail->next = nullptr;
                return old.ptr;
            }
        }
        // Global stack is empty — expand
        expand();
        return pop_batch(count);
    }

    // Push a chain of blocks back to the global LIFO.
    // 'head' is the first block in the chain, 'tail' is the last.
    void push_batch(free_node* head, free_node* tail, size_t count) {
        tagged_node old = global_stack_.load(std::memory_order_acquire);
        while (true) {
            tail->next = old.ptr;
            tagged_node desired{head, old.counter + 1};
            if (global_stack_.compare_exchange_weak(old, desired,
                    std::memory_order_release, std::memory_order_acquire)) {
                break;
            }
        }
        global_available_.fetch_add(count, std::memory_order_relaxed);
    }

    // Non-copyable, non-movable
    global_block_allocator(const global_block_allocator&) = delete;
    global_block_allocator& operator=(const global_block_allocator&) = delete;
};

// -----------------------------------------------------------------------
//  Singleton global allocator
// -----------------------------------------------------------------------
extern FT_API_LOCAL global_block_allocator g_block_allocator;

// -----------------------------------------------------------------------
//  Thread-local cache — only the free list, arena ownership is global
// -----------------------------------------------------------------------
struct FT_API_LOCAL thread_local_block_cache {
    free_node* free_list = nullptr;
    size_t free_count = 0;

    void allocate_batch() {
        auto* batch = g_block_allocator.pop_batch(global_block_allocator::init_batch);
        if (!batch)
            throw std::bad_alloc();

        // Count actual blocks (the chain is null-terminated by pop_batch)
        size_t actual = 0;
        auto* cur = batch;
        while (cur) {
            ++actual;
            cur = cur->next;
        }

        free_list = batch;
        free_count = actual;
    }

    void* allocate() {
        if (!free_list)
            allocate_batch();

        auto* node = free_list;
        free_list = node->next;
        --free_count;
        return node;
    }

    void deallocate(void* p) {
        auto* node = static_cast<free_node*>(p);
        node->next = free_list;
        free_list = node;
        ++free_count;

        // Watermark: if local list exceeds max_local, bulk-return 128 to global
        if (free_count > global_block_allocator::max_local) {
            auto* head = free_list;
            auto* cur = head;
            size_t count = global_block_allocator::init_batch;
            for (size_t i = 1; i < count; ++i)
                cur = cur->next;
            free_list = cur->next;
            cur->next = nullptr;
            free_count -= count;

            // Find tail of the batch we're returning
            auto* tail = head;
            for (size_t i = 1; i < count; ++i)
                tail = tail->next;

            g_block_allocator.push_batch(head, tail, count);
        }
    }
};

// -----------------------------------------------------------------------
//  Thread-local cache accessor (inline so each TU gets its own thread_local)
// -----------------------------------------------------------------------
inline FT_API_LOCAL thread_local_block_cache& get_tls_cache() noexcept {
    static thread_local thread_local_block_cache cache;
    return cache;
}

} // namespace fast_task

#endif // FAST_TASK_FIXED_BLOCK_ALLOCATOR