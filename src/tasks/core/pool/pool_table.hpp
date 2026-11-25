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
    struct FT_API_LOCAL pool_ref {
        worker_pool_storage* ptr = nullptr;

        pool_ref() noexcept = default;
        explicit pool_ref(worker_pool_storage* p) noexcept : ptr(p) {}
        pool_ref(const pool_ref&) = delete;
        pool_ref& operator=(const pool_ref&) = delete;
        pool_ref(pool_ref&& other) noexcept : ptr(other.ptr) {
            other.ptr = nullptr;
        }
        pool_ref& operator=(pool_ref&& other) noexcept {
            if (this != &other) {
                reset();
                ptr = other.ptr;
                other.ptr = nullptr;
            }
            return *this;
        }
        ~pool_ref() {
            reset();
        }

        void reset() noexcept {
            if (ptr) {
                ptr->active_refs.fetch_sub(1, std::memory_order_release);
                ptr = nullptr;
            }
        }

        worker_pool_storage* get() const noexcept {
            return ptr;
        }
        worker_pool_storage* operator->() const noexcept {
            return ptr;
        }
        worker_pool_storage& operator*() const noexcept {
            return *ptr;
        }
        explicit operator bool() const noexcept {
            return ptr != nullptr;
        }
    };

    pool_ref FT_API_LOCAL acquire_pool_ref(uint8_t index) noexcept;
    pool_ref FT_API_LOCAL acquire_implicit_pool_ref() noexcept;
    uint8_t allocate_pool_slot(worker_pool_storage* storage);
    worker_pool_storage* release_pool_slot(uint8_t index) noexcept;
    void FT_API_LOCAL refresh_implicit_pool();
    bool FT_API_LOCAL pool_pristine(const worker_pool_storage& pool) noexcept;
    void FT_API_LOCAL retarget_task(task_object& t, worker_pool_storage& to) noexcept;
}

#endif /* FAST_TASK_CORE_POOL_TABLE */
