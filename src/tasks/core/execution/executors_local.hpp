// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_CORE_EXECUTORS_LOCAL
#define FAST_TASK_CORE_EXECUTORS_LOCAL

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <exception>

#include <fast_task/shared.hpp>
#include <fast_task/task.hpp>
#include <tasks/core/execution/task_access.hpp>
#include <tasks/core/pool/executor_registry.hpp>
#include <tasks/core/pool/pool.hpp>
#include <tasks/util/pcg32.hpp>
#include <tasks/util/work_stealing_deque.hpp>

namespace fast_task {
    struct FT_API_LOCAL executors_local {
        work_stealing_deque<task_object*> local_tasks{1024};
        task_object* run_next = nullptr;

        worker_pool_storage* owner_pool = nullptr;

        uint8_t pool_index = global_pool_index;

        struct {
            uint32_t completed = 0;
            uint32_t executing = 0;
        } batch;

        std::exception_ptr ex_ptr;
        task curr_task = nullptr;
        pcg32 rand;
        scheduler::worker_context_options options{};
        uint32_t registry_slot = UINT32_MAX;

        uint8_t llc_id = 0;
        uint8_t slot_flags = 0;
        scheduler::worker_context* host_context = nullptr;

        bool is_task_thread : 1 = false;
        bool context_in_swap : 1 = false;
        bool yield_request : 1 = false;

        struct {
            uint32_t last_slot = UINT32_MAX;
        } steal_cache;

        struct {
            task pending;
#if FT_TASK_TRANSFERS_LIMIT > 0
            std::atomic_size_t transfers{(size_t)0};
#endif
        } transfer_state;

        fast_task::time_point pending_timer = fast_task::time_point::min();

        scheduler::preemption_policy& policy = options.policy;

        void reset();

        ~executors_local();
    };

    static_assert(sizeof(executors_local) <= 1024, "executors_local must fit into scheduler::worker_context::data[1024]");
    static_assert(alignof(executors_local) <= 64, "executors_local alignment must fit into scheduler::worker_context::data");

    inline void publish_slot_flags(executors_local* loc, worker_pool_storage& base) noexcept {
        if (loc->registry_slot == UINT32_MAX)
            return;
        base.ops.executors.store_flags(base, loc->registry_slot, loc->slot_flags);
    }

    inline void mark_local_nonempty(executors_local* loc, worker_pool_storage& base) noexcept {
        if ((loc->slot_flags & slot_flag_nonempty) != 0)
            return;
        loc->slot_flags |= slot_flag_nonempty;
        publish_slot_flags(loc, base);
    }

    inline void clear_local_nonempty(executors_local* loc, worker_pool_storage& base) noexcept {
        if ((loc->slot_flags & slot_flag_nonempty) == 0)
            return;
        loc->slot_flags &= static_cast<uint8_t>(~slot_flag_nonempty);
        publish_slot_flags(loc, base);
    }
}

#endif /* FAST_TASK_CORE_EXECUTORS_LOCAL */
