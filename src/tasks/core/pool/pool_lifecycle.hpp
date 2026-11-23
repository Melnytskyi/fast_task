// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_CORE_POOL_LIFECYCLE
#define FAST_TASK_CORE_POOL_LIFECYCLE

#include <cstdint>

#include <fast_task/shared.hpp>
#include <tasks/core/pool/pool.hpp>

namespace fast_task {
    void FT_API_LOCAL spawn_pool_worker(worker_pool_storage& storage, uint16_t count);
    void FT_API_LOCAL ensure_pool_worker(worker_pool_storage& storage) noexcept;
    void FT_API_LOCAL shrink_pool_workers(worker_pool_storage& pool, uint16_t count) noexcept;
    void FT_API_LOCAL shutdown_pool(worker_pool_storage& storage, bool abort_tasks);
}

#endif /* FAST_TASK_CORE_POOL_LIFECYCLE */
