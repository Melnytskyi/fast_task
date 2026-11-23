// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_CORE_POOL_TABLE
#define FAST_TASK_CORE_POOL_TABLE

#include <cstdint>

#include <fast_task/shared.hpp>
#include <tasks/core/pool/pool.hpp>

namespace fast_task {
    uint8_t allocate_pool_slot(worker_pool_storage* storage);
    worker_pool_storage* release_pool_slot(uint8_t index) noexcept;
    void FT_API_LOCAL refresh_implicit_pool();
    bool FT_API_LOCAL pool_pristine(const worker_pool_storage& pool) noexcept;
    void FT_API_LOCAL retarget_task(task_object& t, worker_pool_storage& to) noexcept;
}

#endif /* FAST_TASK_CORE_POOL_TABLE */
