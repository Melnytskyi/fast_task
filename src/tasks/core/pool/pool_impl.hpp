// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_CORE_POOL_IMPL
#define FAST_TASK_CORE_POOL_IMPL

#include <cstddef>

#include <fast_task/shared.hpp>
#include <fast_task/task/scheduler.hpp>
#include <tasks/core/pool/pool.hpp>

namespace fast_task::scheduler {
    struct FT_API_LOCAL worker_pool_impl {
        static constexpr size_t layer_offset = 64;

        worker_pool_storage* base = nullptr;

        static worker_pool_impl& of(worker_pool& pool) noexcept;

        bool is_global() const noexcept {
            return base == nullptr;
        }
    };

    worker_pool_storage& storage_of(worker_pool& pool) noexcept;
    worker_pool_storage& storage_of(const worker_pool& pool) noexcept;
}

#endif /* FAST_TASK_CORE_POOL_IMPL */
