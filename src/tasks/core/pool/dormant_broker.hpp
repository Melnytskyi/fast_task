// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_CORE_DORMANT_BROKER
#define FAST_TASK_CORE_DORMANT_BROKER

#include <array>
#include <cstddef>

#include <fast_task/native/spin_lock.hpp>
#include <fast_task/shared.hpp>

namespace fast_task {
    struct worker_pool_storage;

    struct FT_API_LOCAL dormant_lease_grant {
        worker_pool_storage* lender = nullptr;
        worker_pool_storage* borrower = nullptr;
    };

    struct FT_API_LOCAL dormant_broker_state {
        fast_task::native::spin_lock lock;
        std::array<dormant_lease_grant, 64> grants{};
        size_t grant_count = 0;
        size_t outstanding = 0;
        bool open = true;

        bool try_push(worker_pool_storage* lender, worker_pool_storage* borrower) noexcept {
            if (grant_count == grants.size())
                return false;
            grants[grant_count++] = dormant_lease_grant{lender, borrower};
            return true;
        }

        dormant_lease_grant take(worker_pool_storage* lender) noexcept {
            for (size_t i = 0; i < grant_count; ++i) {
                if (grants[i].lender != lender)
                    continue;
                dormant_lease_grant grant = grants[i];
                grants[i] = grants[--grant_count];
                return grant;
            }
            return {};
        }
    };
}

#endif /* FAST_TASK_CORE_DORMANT_BROKER */
