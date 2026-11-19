// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)
//
// Router implementation. `transfer_task` was moved verbatim out of
// tasks/scheduler.cpp and `can_be_scheduled_task_to_hot` out of
// tasks/_internal.cpp by S0b (plans/pool-architecture.md §4). S1 replaced the
// condition-variable wakes with the per-pool eventcounts (§2.8).
//
// S2a implements §2.10: an unassigned task inherits the spawning task's pool
// when that pool opted in with `inherit_pool_on_spawn`, else the current
// worker's pool when it opted in, else the global pool. The legacy
// `set_auto_bind_worker` behaviour survives as "first pool with
// allow_implicit_start".

#include <cstdlib>

#include <tasks/_internal.hpp>

namespace fast_task {
    bool can_be_scheduled_task_to_hot() {
        // Counting across pools would put a table walk on the hot path, so it
        // is only done when the limit is actually configured (rare).
        if (task::max_running_tasks) {
            size_t running = 0;
            for (auto& slot : glob.pools) {
                auto* pool = slot.load(std::memory_order_relaxed);
                if (pool)
                    running += pool->runtime.in_run_tasks.load(std::memory_order_relaxed);
            }
            if (task::max_running_tasks <= running)
                return false;
        }
        return true;
    }

    namespace {
        // §2.10: resolve the pool an unassigned task must go to. `loc` is
        // passed in because the caller already read it: get_loc() is an
        // out-of-line TLS access, and route_task() is on the publish path.
        worker_pool_storage* resolve_pool_for(executors_local* loc, task_object& raw_task) noexcept {
            worker_pool_storage* inherit = nullptr;
            if (loc && loc->is_task_thread && loc->curr_task) {
                auto& parent = get_data(loc->curr_task);
                if (parent.get_pool_assigned())
                    inherit = pool_for_index(parent.pool_index);
            }

            // Legacy auto-bind: `task::set_auto_bind_worker(true)` used to pick
            // the first bound worker that allows implicit start. It is now a
            // property of the pool, not of the task, and the first such pool is
            // cached by refresh_implicit_pool(), so the publish path stays a
            // single load instead of a 255-slot table scan.
            if (!inherit) {
                inherit = glob.implicit_pool.load(std::memory_order_acquire);
                if (inherit && inherit->closing)
                    inherit = nullptr;
            }

            if (!inherit && loc && loc->owner_pool)
                inherit = loc->owner_pool;

            if (inherit && (inherit->config.inherit_pool_on_spawn || inherit->config.allow_implicit_start)) {
                raw_task.pool_index = inherit->pool_index;
            } else {
                raw_task.pool_index = global_pool_index;
            }
            raw_task.set_pool_assigned(true);
            return pool_for_index(raw_task.pool_index);
        }
    }

    void route_task(task&& task, enter_state* stat) {
        if (!task) {
            // Null is the retire signal: it still has to wake a worker.
            auto& global = global_storage();
            global.ops.enqueue(global, nullptr, task.release());
            return;
        }

        if (get_data(task).get_is_on_scheduler() && get_data(task).get_relock() && stat) {
            auto mut = get_data(task).get_relock();

            get_data(task).set_relock(nullptr);

            if (!mut.enter_wait(task, *stat))
                return;
        }

        task_object* raw_task = task.release();
        const bool created = raw_task->is_created();
        raw_task->set_status(task_object::status_e::scheduled);

        // One TLS read for the whole publish. On a native publisher it is
        // null; on a worker it is this worker's context.
        auto* loc = get_loc();
        worker_pool_storage* pool = nullptr;
        if (raw_task->get_pool_assigned())
            pool = pool_for_index(raw_task->pool_index);
        else
            pool = resolve_pool_for(loc, *raw_task);
        if (!pool) {
            // A null table slot is a lifetime violation (§2.10).
            std::abort();
        }

        // Account on the *destination* pool, before the task can be dequeued.
        if (created)
            pool->runtime.executing_tasks.fetch_add(1, std::memory_order_acq_rel);

        // Publish through the pool's policy table (§2.5): the local-deque fast
        // path, the self-publish rule for this_task::yield() and the hot/cold
        // split all live in the policy implementation, so the router carries no
        // queue branch and a second queue policy does not touch it.
        pool->ops.enqueue(*pool, loc, raw_task);
    }

    void transfer_task(task&& task, enter_state* stat) {
        route_task(std::move(task), stat);
    }
}
