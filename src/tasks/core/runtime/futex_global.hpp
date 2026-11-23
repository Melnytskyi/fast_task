// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_CORE_FUTEX_GLOBAL
#define FAST_TASK_CORE_FUTEX_GLOBAL

#include <atomic>
#include <cstdint>

#include <fast_task/internal/futex.hpp>
#include <fast_task/native/spin_lock.hpp>
#include <fast_task/shared.hpp>
#include <fast_task/task.hpp>
#include <tasks/core/runtime/hdi.hpp>

namespace fast_task {
    struct FT_API_LOCAL futex_global_t {
        enum class node_type : uint8_t {
            wait,
            unlock_and_wait,
            enter_wait_and_lock
        };

        struct wait_node {
            wait_node* next_addr = nullptr;
            wait_node* prev_addr = nullptr;

            wait_node* next_waiter = nullptr;
            wait_node* prev_waiter = nullptr;

            wait_node* tail_waiter = nullptr;
            void* wait_address;
            node_type type;
            bool needs_awake_check : 1 = false;
            bool in_bucket : 1 = false;
            uint8_t node_data : 6;
            uint16_t awake_check = 0;
            std::atomic_uint32_t native_wake;
            task waiter;
            void* next_wait_addr;

            union {
                bool (*next_wait_addr_check_callback)(void*, bool mark_request);
                void (*lock_callback)(void*, const task& task_obj, futex::node_data);
            };
        };

        struct alignas(hardware_destructive_interference_size) bucket {
            fast_task::native::spin_lock lock;
            wait_node* addresses = nullptr;
        };

        bucket buckets[4096];

        inline bucket& get_bucket(void* addr) {
            size_t h = reinterpret_cast<size_t>(addr);
            h ^= (h >> 20) ^ (h >> 12);
            return buckets[(h ^ (h >> 7) ^ (h >> 4)) & 0xFFF];
        }
    };
}

#endif /* FAST_TASK_CORE_FUTEX_GLOBAL */
