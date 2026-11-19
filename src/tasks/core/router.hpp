// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)
//
// Router layer: decides which queue a runnable task is published to. Split out
// of tasks/_internal.hpp by S0b (plans/pool-architecture.md §4) without
// behaviour changes; `transfer_task` keeps its implementation. S2a replaces it
// with `route_task` (explicit pool index, lazy global init, inheritance).

#ifndef FAST_TASK_CORE_ROUTER
#define FAST_TASK_CORE_ROUTER

#include <fast_task/shared.hpp>
#include <fast_task/task/task.hpp>

namespace fast_task {
    class enter_state;

    // Publish a runnable task (plans/pool-architecture.md §2.10): resolve the
    // destination pool, account it on that pool, then enqueue into the worker's
    // inline deque or the pool queues.
    void FT_API_LOCAL route_task(task&&, enter_state* stat = nullptr);

    // Source-compatible alias used by every existing caller.
    void FT_API_LOCAL transfer_task(task&&, enter_state* stat = nullptr);

    // Whether a new task may enter the hot queue, given
    // task::max_running_tasks and the per-pool in_run_tasks counters.
    bool FT_API_LOCAL can_be_scheduled_task_to_hot();
}

#endif /* FAST_TASK_CORE_ROUTER */
