// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <new>

#include <tasks/_internal.hpp>

namespace fast_task::scheduler {
    worker_pool_impl& worker_pool_impl::of(worker_pool& pool) noexcept {
        static_assert(sizeof(worker_pool_impl) <= worker_pool_impl::layer_offset, "worker_pool_impl must fit into the worker_pool reserve");
        static_assert(worker_pool::storage_size >= worker_pool_impl::layer_offset + worker_pool_storage_size, "worker_pool must reserve one impl layer before the pool storage");
        return *std::launder(reinterpret_cast<worker_pool_impl*>(pool.storage));
    }

    worker_pool_storage& storage_of(worker_pool& pool) noexcept {
        auto& impl = worker_pool_impl::of(pool);
        return impl.base ? *impl.base : global_storage();
    }

    worker_pool_storage& storage_of(const worker_pool& pool) noexcept {
        return storage_of(const_cast<worker_pool&>(pool));
    }
}
