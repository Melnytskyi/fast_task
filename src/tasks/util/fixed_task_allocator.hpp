// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#pragma once
#ifndef FAST_TASK_FIXED_TASK_ALLOCATOR
    #define FAST_TASK_FIXED_TASK_ALLOCATOR

    #include <atomic>
    #include <cstddef>
    #include <cstdint>
    #include <cstdlib>
    #include <new>

    #include <internal/task_object.hpp>
    #include <interrupt.hpp>
    #include <native/spin_lock.hpp>
    #include <shared.hpp>

namespace fast_task {
    class FT_API_LOCAL global_task_allocator {
    public:
        static constexpr size_t block_size = 128;
        static constexpr size_t block_alignment = 64;
        static constexpr size_t init_batch = 128;
        static constexpr size_t max_local = 256;
        static constexpr size_t min_arena_blocks = 512;
        static constexpr size_t max_arena_blocks = 65536; //8MB

        struct free_node {
            free_node* next;
        };

        struct alignas(16) tagged_node {
            free_node* ptr;
            uint64_t counter;
        };

        static_assert(sizeof(tagged_node) == 16, "tagged_node must be exactly 16 bytes for DWCAS");

    private:
        std::atomic<tagged_node> global_stack_;
        std::atomic<size_t> global_available_{0};
        std::atomic<bool> expanding_{false};
        std::atomic<bool> is_cleaning{false};

        struct alignas(block_alignment) arena {
            arena* next;
            void* base;
            size_t size;
            size_t cleanup_current_free = 0;
            bool to_release = false;
        };

        native::spin_lock arena_lock;
        arena* arena_list_ = nullptr;
        size_t last_arena_size_ = 0;

        void expand();
        static free_node* advance(free_node* head, size_t count, free_node** out_batch_tail);

    public:
        static arena* get_arena(void* any_node);
        global_task_allocator() noexcept;
        ~global_task_allocator();
        global_task_allocator(const global_task_allocator&) = delete;
        global_task_allocator& operator=(const global_task_allocator&) = delete;

        free_node* pop_batch(size_t count);
        void push_batch(free_node* head, free_node* tail, size_t count);

        void iterate_all(void (*)(task_object* item, void* data), void* data);

        void claim_unused();
    };

    struct FT_API_LOCAL tl_task_alloc_cache {
        global_task_allocator* parent = nullptr;
        global_task_allocator::free_node* free_list = nullptr;
        size_t free_count = 0;

        void allocate_batch();
        task_object* allocate();
        void deallocate(task_object* p);
        void release();
    };

    struct FT_API_LOCAL task_alloc {
        static task_object* allocate();

        static void deallocate(task_object* p);
        static void release();
    };
}

#endif // FAST_TASK_FIXED_TASK_ALLOCATOR