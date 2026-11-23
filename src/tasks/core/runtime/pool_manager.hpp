// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_CORE_POOL_MANAGER
#define FAST_TASK_CORE_POOL_MANAGER

#include <array>
#include <atomic>
#include <cstddef>

#include <fast_task/native/mutex.hpp>
#include <fast_task/shared.hpp>
#include <tasks/core/pool/dormant_broker.hpp>
#include <tasks/core/pool/executor_registry.hpp>
#include <tasks/core/pool/pool.hpp>

namespace fast_task {
    namespace scheduler {
        class worker_pool;
    }

    struct FT_API_LOCAL pool_manager {
        std::array<std::atomic<worker_pool_storage*>, pool_table_size> slots;
        alignas(64) std::byte global_storage_buffer[worker_pool_storage_size];

        std::atomic<scheduler::worker_pool*> global_handle{nullptr};
        std::atomic<worker_pool_storage*> implicit_pool{nullptr};
        global_executor_registry registry;
        std::atomic<bool> dormant_sharing_enabled{false};
        dormant_broker_state dormant_broker;

        fast_task::native::rw_mutex safety;

        pool_manager() noexcept;

        worker_pool_storage* find(uint8_t index) const noexcept {
            return slots[index].load(std::memory_order_acquire);
        }

        worker_pool_storage& global() const noexcept {
            return *slots[global_pool_index].load(std::memory_order_acquire);
        }
    };
}

#endif /* FAST_TASK_CORE_POOL_MANAGER */
