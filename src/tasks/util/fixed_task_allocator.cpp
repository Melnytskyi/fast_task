// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include "fixed_task_allocator.hpp"
#include <tasks/_internal.hpp>
#include <tasks/util/cpu.hpp>
#include <tasks/util/os_alloc.hpp>

namespace fast_task {
    auto global_task_allocator::get_arena(void* any_node) -> arena* {
        return reinterpret_cast<arena*>(
            (reinterpret_cast<uintptr_t>(any_node) & ~static_cast<uintptr_t>(0xFFF)) -
            (reinterpret_cast<task_object*>(any_node)->arena_offset_pages << 12)
        );
    }

    void global_task_allocator::expand() {
        bool expected = false;
        if (!expanding_.compare_exchange_strong(expected, true, std::memory_order_acquire))
            return;
        interrupt_unsafe_region ir;

        size_t num_blocks = min_arena_blocks;
        if (last_arena_size_ != 0) {
            num_blocks = last_arena_size_ / block_size * 2;
            if (num_blocks < min_arena_blocks)
                num_blocks = min_arena_blocks;
        }
        size_t arena_size = num_blocks * block_size;

        void* base = os_alloc(arena_size);
        if (!base) {
            expanding_.store(false, std::memory_order_release);
            throw std::bad_alloc();
        }
        auto* begin = static_cast<std::byte*>(base) + 128;
        auto* end = begin + arena_size - 128;

        auto* a = static_cast<arena*>(base);
        a->base = begin;
        a->size = arena_size - 128;
        a->cleanup_current_free = 0;
        a->to_release = false;
        {
            std::lock_guard guard(arena_lock);
            a->next = arena_list_;
            arena_list_ = a;
            last_arena_size_ = arena_size;
        }
        free_node* tail = nullptr;
        free_node* head = nullptr;

        uintptr_t arena_base = reinterpret_cast<uintptr_t>(base);
        static constexpr uintptr_t page_mask = ~static_cast<uintptr_t>(0xFFF);


        for (auto* pos = begin; pos < end; pos += block_size) {
            auto* node = reinterpret_cast<free_node*>(pos);
            uintptr_t task_addr = reinterpret_cast<uintptr_t>(node);
            uintptr_t page_base = task_addr & page_mask;

            reinterpret_cast<fast_task::task_object*>(node)
                ->arena_offset_pages = static_cast<uint16_t>((page_base - arena_base) >> 12);
#ifndef NDEBUG
            reinterpret_cast<fast_task::task_object*>(node)
                ->status.store(fast_task::task_object::status_e::released, std::memory_order_relaxed);
#endif
            node->next = head;
            head = node;
            if (!tail)
                tail = node;
        }

        tagged_node old = global_stack_.load(std::memory_order_acquire);
        while (true) {
            tail->next = old.ptr;
            tagged_node desired{head, old.counter + 1};
            if (global_stack_.compare_exchange_weak(old, desired, std::memory_order_release, std::memory_order_acquire)) {
                break;
            }
        }
        global_available_.fetch_add(num_blocks, std::memory_order_relaxed);
        expanding_.store(false, std::memory_order_release);
    }

    global_task_allocator::free_node* global_task_allocator::advance(free_node* head, size_t count, free_node** out_batch_tail = nullptr) {
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

    global_task_allocator::global_task_allocator() noexcept {
        tagged_node init{nullptr, 0};
        global_stack_.store(init, std::memory_order_relaxed);
    }

    global_task_allocator::~global_task_allocator() {
        std::lock_guard guard(arena_lock);
        auto* a = arena_list_;
        while (a) {
            auto* next = a->next;
#ifndef NDEBUG
            for (size_t i = 0; i < a->size; i += 128) {
                auto obj = reinterpret_cast<fast_task::task_object*>(static_cast<std::byte*>(a->base) + i);
                assert(obj->status.load(std::memory_order_relaxed) == fast_task::task_object::status_e::released && "The arena is still used");
            }
#endif
            os_free(a, a->size + 128);
            a = next;
        }
        arena_list_ = nullptr;
    }

    global_task_allocator::free_node* global_task_allocator::pop_batch(size_t count) {
        free_node* head = nullptr;
        free_node* tail = nullptr;
        size_t popped = 0;

        while (popped < count) {
            tagged_node old = global_stack_.load(std::memory_order_acquire);
            if (!old.ptr) {
                if (popped == 0) {
                    expand();
                    continue;
                }
                break;
            }
            tagged_node desired{old.ptr->next, old.counter + 1};
            if (global_stack_.compare_exchange_weak(
                    old,
                    desired,
                    std::memory_order_release,
                    std::memory_order_acquire
                )) {
                old.ptr->next = nullptr;
                if (!head)
                    head = tail = old.ptr;
                else {
                    tail->next = old.ptr;
                    tail = old.ptr;
                }
                ++popped;
            }
        }

        global_available_.fetch_sub(popped, std::memory_order_relaxed);
        return head;
    }

    void global_task_allocator::push_batch(free_node* head, free_node* tail, size_t count) {
        tagged_node old = global_stack_.load(std::memory_order_acquire);
        while (true) {
            tail->next = old.ptr;
            tagged_node desired{head, old.counter + 1};
            if (global_stack_.compare_exchange_weak(old, desired, std::memory_order_release, std::memory_order_acquire)) {
                break;
            }
        }
        global_available_.fetch_add(count, std::memory_order_relaxed);
    }

    void global_task_allocator::iterate_all(void (*callback)(task_object* item, void* data), void* data) {
        auto* a = arena_list_;
        while (a) {
            auto* next = a->next;
            for (size_t i = 0; i < a->size; i += 128)
                callback(reinterpret_cast<task_object*>(static_cast<std::byte*>(a->base) + i), data);
            a = next;
        }
    }

    void tl_task_alloc_cache::allocate_batch() {
        auto* batch = glob.gba.pop_batch(global_task_allocator::init_batch);
        if (!batch)
            throw std::bad_alloc();

        size_t actual = 0;
        auto* cur = batch;
        while (cur) {
            ++actual;
            cur = cur->next;
        }

        free_list = batch;
        free_count = actual;
    }

    task_object* tl_task_alloc_cache::allocate() {
        if (!free_list)
            allocate_batch();

        auto* node = free_list;
        free_list = node->next;
        --free_count;
        return reinterpret_cast<task_object*>(node);
    }

    void tl_task_alloc_cache::deallocate(task_object* p) {
        auto* node = reinterpret_cast<global_task_allocator::free_node*>(p);
#ifndef NDEBUG
        p->status.store(fast_task::task_object::status_e::released, std::memory_order_relaxed);
#endif
        node->next = free_list;
        free_list = node;
        ++free_count;

        if (free_count > global_task_allocator::max_local) {
            auto* head = free_list;
            auto* cur = head;
            size_t count = global_task_allocator::init_batch;
            for (size_t i = 1; i < count; ++i)
                cur = cur->next;
            free_list = cur->next;
            cur->next = nullptr;
            free_count -= count;

            auto* tail = head;
            for (size_t i = 1; i < count; ++i)
                tail = tail->next;

            glob.gba.push_batch(head, tail, count);
        }
    }

    void tl_task_alloc_cache::release() {
        if (free_list) {
            auto* head = free_list;
            auto* cur = head;
            while (cur->next)
                cur = cur->next;

            glob.gba.push_batch(head, cur, free_count);
            free_list = nullptr;
            free_count = 0;
        }
    }

    task_object* task_alloc::allocate() {
        return get_loc().task_alloc_cache.allocate();
    }

    void task_alloc::deallocate(task_object* p) {
        get_loc().task_alloc_cache.deallocate(p);
    }

    void global_task_allocator::claim_unused() {
        bool expected = false;
        if (!is_cleaning.compare_exchange_strong(expected, true))
            return;

        struct claim_guard {
            std::atomic<bool>& flag;
            bool used = true;

            ~claim_guard() {
                if (used)
                    flag.store(false, std::memory_order_release);
            }

            void unlock() {
                if (used) {
                    flag.store(false, std::memory_order_release);
                    used = false;
                }
            }
        } guard(is_cleaning);

        tagged_node old = global_stack_.load(std::memory_order_acquire);
        while (true) {
            tagged_node desired{nullptr, old.counter + 1};
            if (global_stack_.compare_exchange_weak(old, desired, std::memory_order_release, std::memory_order_acquire))
                break;
        }
        global_available_.store(0, std::memory_order_relaxed);

        if (!old.ptr)
            return;

        for (auto cur = old.ptr; cur; cur = cur->next)
            get_arena(cur)->cleanup_current_free++;

        arena* old_head;
        {
            std::lock_guard guard(arena_lock);
            old_head = arena_list_;
        }
        for (auto a = old_head; a; a = a->next) {
            a->to_release = a->cleanup_current_free == a->size / block_size;
            a->cleanup_current_free = 0;
        }

        free_node* push_head = nullptr;
        free_node* push_tail = nullptr;
        size_t kept = 0;
        for (auto cur = old.ptr; cur;) {
            auto next = cur->next;
            arena* a = get_arena(cur);
            if (!a->to_release) {
                if (!push_head)
                    push_head = cur;
                else
                    push_tail->next = cur;
                push_tail = cur;
                kept++;
            }
            cur = next;
        }
        if (push_tail)
            push_tail->next = nullptr;
        arena* to_free = nullptr;
        {
            std::lock_guard guard(arena_lock);

            arena** prev_next = &arena_list_;
            arena* cur = arena_list_;
            while (cur) {
                if (cur->to_release) {
                    *prev_next = cur->next;
                    cur->next = to_free;
                    to_free = cur;
                    cur = *prev_next;
                } else {
                    prev_next = &cur->next;
                    cur = cur->next;
                }
            }

            if (arena_list_) {
                arena* tail = arena_list_;
                while (tail->next)
                    tail = tail->next;
                last_arena_size_ = tail->size;
            } else {
                last_arena_size_ = 0;
            }
        }
        guard.unlock();
        if (push_head)
            push_batch(push_head, push_tail, kept);

        while (to_free) {
            arena* next = to_free->next;
            os_free(to_free, to_free->size + sizeof(arena));
            to_free = next;
        }
    }
}
