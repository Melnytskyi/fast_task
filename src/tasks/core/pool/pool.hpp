// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_CORE_POOL
#define FAST_TASK_CORE_POOL

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <type_traits>

#include <fast_task/native/condition_variable.hpp>
#include <fast_task/native/mutex.hpp>
#include <fast_task/native/spin_lock.hpp>
#include <fast_task/shared.hpp>
#include <fast_task/task/scheduler.hpp>
#include <tasks/core/notify/event.hpp>
#include <tasks/core/pool/executor_registry.hpp>
#include <tasks/core/pool/pool_balancer.hpp>
#include <tasks/core/pool/pool_ops.hpp>
#include <tasks/core/pool/queue_storage.hpp>
#include <tasks/core/pool/threads_manager.hpp>

namespace fast_task {
    constexpr uint8_t user_pool_count = 255;
    constexpr uint8_t global_pool_index = 255;
    constexpr size_t pool_table_size = 256;

    constexpr size_t worker_pool_storage_size = 8192;

    enum class worker_scale : uint8_t {
        single_worker,
        multi_worker,
    };

    struct FT_API_LOCAL worker_pool_runtime {
        std::atomic<uint32_t> affinity_failures{0};
        std::atomic<uint32_t> affinity_index{0};
        std::atomic<bool> stop_requested{false};
        std::atomic<bool> paused{false};

        alignas(64) std::atomic<size_t> executing_tasks{0};
        alignas(64) std::atomic<size_t> in_run_tasks{0};
        alignas(64) std::atomic<uint64_t> completed_tasks{0};
    };

    struct alignas(64) FT_API_LOCAL worker_pool_storage {
        scheduler::worker_pool_options config;
        worker_pool_runtime runtime;
        threads_manager threads;
        scheduler_event work_event;
        scheduler_event dormant_event;

        worker_pool_ops ops{};
        scheduler::worker_pool* public_handle = nullptr;

        fast_task::native::rw_mutex no_race;

        uint8_t pool_index = global_pool_index;
        bool is_global : 1 = false;
        bool started : 1 = false;
        bool explicitly_configured : 1 = false;
        bool lazily_initialized : 1 = false;
        std::atomic<bool> closing{false};
        std::atomic<bool> slot_released{false};
        std::atomic<uint32_t> active_refs{0};

    protected:
        worker_pool_storage() noexcept = default;

    public:
        worker_pool_storage(const worker_pool_storage&) = delete;
        worker_pool_storage& operator=(const worker_pool_storage&) = delete;
        worker_pool_storage(worker_pool_storage&&) = delete;
        worker_pool_storage& operator=(worker_pool_storage&&) = delete;

        uint8_t index() const noexcept {
            return pool_index;
        }

        bool queue_empty() const noexcept {
            return ops.queue.pending(*this) == 0;
        }
    };

    struct FT_API_LOCAL no_registry {};

    template <scheduler::queue_policy Q, scheduler::idle_policy I, scheduler::worker_balancer B, bool IsGlobal, worker_scale S>
    struct FT_API_LOCAL configured_worker_pool_storage : worker_pool_storage {
        static constexpr bool uses_global_registry = IsGlobal;

        queue_storage<Q> queue_data;
        std::conditional_t<IsGlobal, no_registry, binded_executor_registry> registry_data;
        pool_balancer<B> balancer;

        configured_worker_pool_storage();

        configured_worker_pool_storage(const configured_worker_pool_storage&) = delete;
        configured_worker_pool_storage& operator=(const configured_worker_pool_storage&) = delete;
        configured_worker_pool_storage(configured_worker_pool_storage&&) = delete;
        configured_worker_pool_storage& operator=(configured_worker_pool_storage&&) = delete;
    };

    using global_pool_storage_type = configured_worker_pool_storage<
        scheduler::queue_policy::work_stealing_lifo,
        scheduler::idle_policy::wait,
        scheduler::worker_balancer::none,
        true,
        worker_scale::multi_worker>;

    static_assert(sizeof(global_pool_storage_type) <= worker_pool_storage_size, "the global pool storage must fit into worker_pool_storage_size");
    static_assert(sizeof(configured_worker_pool_storage<scheduler::queue_policy::priority_fifo, scheduler::idle_policy::busy_spin, scheduler::worker_balancer::hill_climb, false, worker_scale::multi_worker>) <= worker_pool_storage_size, "priority_fifo + busy_spin storage exceeds worker_pool_storage_size");
    static_assert(alignof(global_pool_storage_type) <= 64, "worker_pool_storage alignment must not exceed a cache line");
}

#endif /* FAST_TASK_CORE_POOL */
