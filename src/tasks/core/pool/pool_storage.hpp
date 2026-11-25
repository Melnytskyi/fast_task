// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_CORE_POOL_STORAGE
#define FAST_TASK_CORE_POOL_STORAGE

#include <fast_task/shared.hpp>
#include <fast_task/task/scheduler.hpp>
#include <tasks/core/pool/pool.hpp>

namespace fast_task {
    void FT_API_LOCAL validate_pool_policies(scheduler::queue_policy queue, scheduler::idle_policy idle);
    worker_pool_storage* FT_API_LOCAL construct_pool_storage(void* buffer, scheduler::queue_policy queue, scheduler::idle_policy idle, scheduler::worker_balancer balancer, bool single_worker);
    worker_pool_storage* FT_API_LOCAL construct_global_pool_storage(void* buffer, scheduler::queue_policy queue, scheduler::idle_policy idle, scheduler::worker_balancer balancer, bool single_worker);
}

#endif /* FAST_TASK_CORE_POOL_STORAGE */
