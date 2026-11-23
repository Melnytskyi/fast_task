// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_CORE_POOL_DORMANT
#define FAST_TASK_CORE_POOL_DORMANT

#include <fast_task/shared.hpp>
#include <tasks/core/pool/pool.hpp>

namespace fast_task {
    void FT_API_LOCAL refresh_dormant_sharing() noexcept;
    bool FT_API_LOCAL claim_dormant_slot(worker_pool_storage& pool, bool spawned) noexcept;
    bool FT_API_LOCAL try_borrow_dormant(worker_pool_storage& borrower) noexcept;
    worker_pool_storage* FT_API_LOCAL take_dormant_lease(worker_pool_storage& home) noexcept;
    void FT_API_LOCAL return_dormant_lease(worker_pool_storage& home, worker_pool_storage& borrower) noexcept;
    void FT_API_LOCAL drop_dormant_grants(worker_pool_storage& pool) noexcept;
    void FT_API_LOCAL close_dormant_broker() noexcept;
}

#endif /* FAST_TASK_CORE_POOL_DORMANT */
