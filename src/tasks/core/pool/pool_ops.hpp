// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_CORE_POOL_OPS
#define FAST_TASK_CORE_POOL_OPS

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
        struct queue_ops {
            bool (*enqueue)(worker_pool_storage&, executors_local*, task_object*) noexcept;
            bool (*requeue)(worker_pool_storage&, task_object*) noexcept;
            bool (*enqueue_cold)(worker_pool_storage&, task_object*) noexcept;
            size_t (*dequeue_bulk)(worker_pool_storage&, executors_local*, task_object** out, size_t max) noexcept;
            bool (*has_queued_work)(const worker_pool_storage&, const executors_local*) noexcept;
            bool (*has_runnable_work)(const worker_pool_storage&, const executors_local*) noexcept;
            bool (*steal)(worker_pool_storage&, executors_local*, task_object*& out) noexcept;
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
