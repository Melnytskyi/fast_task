// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_CORE_POOL_OPS
#define FAST_TASK_CORE_POOL_OPS

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <vector>

#include <fast_task/shared.hpp>
#include <fast_task/task/scheduler.hpp>
#include <tasks/util/work_stealing_deque.hpp>

namespace fast_task {
    struct executors_local;
    struct worker_pool_storage;

    struct FT_API_LOCAL worker_pool_ops {
        using steal_fn = bool (*)(worker_pool_storage&, executors_local*, task_object*& out) noexcept;

        struct atomic_steal_fn {
            std::atomic<steal_fn> fn{nullptr};

            atomic_steal_fn() noexcept = default;
            atomic_steal_fn(steal_fn f) noexcept : fn(f) {}
            atomic_steal_fn(const atomic_steal_fn& other) noexcept
                : fn(other.fn.load(std::memory_order_relaxed)) {}
            atomic_steal_fn& operator=(const atomic_steal_fn& other) noexcept {
                fn.store(other.fn.load(std::memory_order_relaxed), std::memory_order_release);
                return *this;
            }
            atomic_steal_fn& operator=(steal_fn f) noexcept {
                fn.store(f, std::memory_order_release);
                return *this;
            }
            bool operator()(worker_pool_storage& pool, executors_local* loc, task_object*& out) const noexcept {
                return fn.load(std::memory_order_acquire)(pool, loc, out);
            }
        };

        struct queue_ops {
            bool (*enqueue)(worker_pool_storage&, executors_local*, task_object*) noexcept;
            bool (*requeue)(worker_pool_storage&, task_object*) noexcept;
            bool (*enqueue_cold)(worker_pool_storage&, task_object*) noexcept;
            size_t (*dequeue_bulk)(worker_pool_storage&, executors_local*, task_object** out, size_t max) noexcept;
            bool (*has_queued_work)(const worker_pool_storage&, const executors_local*) noexcept;
            bool (*has_runnable_work)(const worker_pool_storage&, const executors_local*) noexcept;
            atomic_steal_fn steal;
            steal_fn multi_worker_steal = nullptr;
            bool (*wait_until)(worker_pool_storage&, executors_local*, fast_task::time_point) noexcept;
            void (*drain_all)(worker_pool_storage&, std::vector<task_object*>& out) noexcept;
            void (*drain_cold)(worker_pool_storage&) noexcept;
            size_t (*pending)(const worker_pool_storage&) noexcept;
            void (*destroy)(worker_pool_storage&) noexcept;
        } queue;

        struct executor_ops {
            uint32_t (*claim)(worker_pool_storage&, work_stealing_deque<task_object*>*, uint8_t llc) noexcept;
            void (*release)(worker_pool_storage&, uint32_t idx) noexcept;
            void (*store_flags)(worker_pool_storage&, uint32_t idx, uint8_t flags) noexcept;
            uint32_t (*active)(const worker_pool_storage&) noexcept;
            bool (*any_work)(const worker_pool_storage&) noexcept;
        } executors;

        struct balancer_ops {
            void (*arm)(worker_pool_storage&) noexcept;
            void (*run)(worker_pool_storage&) noexcept;
            uint64_t (*samples)(const worker_pool_storage&) noexcept;
        } balancer;
    };
}

#endif /* FAST_TASK_CORE_POOL_OPS */
