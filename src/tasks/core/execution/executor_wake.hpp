// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_CORE_EXECUTOR_WAKE
#define FAST_TASK_CORE_EXECUTOR_WAKE

#include <tasks/core/execution/executors_local.hpp>
#include <tasks/core/runtime/runtime.hpp>

namespace fast_task {
    inline scheduler_event& work_event_of(const executors_local& loc) noexcept {
        return loc.owner_pool ? loc.owner_pool->work_event : global_storage().work_event;
    }

    inline bool driver_claimable(const executors_local* loc) noexcept {
        return loc->options.allow_driver_polling &&
               glob.driver.claim_handoff.load(std::memory_order_seq_cst) &&
               !glob.driver.driver_lock.is_locked();
    }
}

#endif /* FAST_TASK_CORE_EXECUTOR_WAKE */
