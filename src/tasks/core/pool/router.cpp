// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <cstdlib>

#include <tasks/_internal.hpp>

namespace fast_task {
    bool can_be_scheduled_task_to_hot() {
        if (task::max_running_tasks) {
            size_t running = 0;
            for (auto& slot : glob.pools.slots) {
                auto* pool = slot.load(std::memory_order_relaxed);
                if (pool)
                    running += pool_in_run_tasks(*pool);
            }
            if (task::max_running_tasks <= running)
                return false;
        }
        return true;
    }

    namespace {
        worker_pool_storage* assign_pool_for(executors_local* loc, task_object& raw_task) noexcept {
            worker_pool_storage* inherit = nullptr;
            if (loc && loc->is_task_thread && loc->curr_task) {
                auto& parent = get_data(loc->curr_task);
                if (parent.get_pool_assigned())
                    inherit = pool_for_index(parent.pool_index);
            }

            if (!inherit) {
                inherit = glob.pools.implicit_pool.load(std::memory_order_acquire);
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

    void route_task(task&& task, enter_state* stat, bool pre_scheduled) {
        if (!task) {
            auto& global = global_storage();
            global.ops.queue.enqueue(global, nullptr, task.release());
            return;
        }

        if (get_data(task).get_is_on_scheduler() && get_data(task).get_relock() && stat) {
            auto mut = get_data(task).get_relock();

            get_data(task).set_relock(nullptr);

            if (!mut.enter_wait(task, *stat))
                return;
        }

        task_object* raw_task = task.release();
        bool created;
        if (pre_scheduled) {
            created = true;
        } else {
            created = raw_task->is_created();
            raw_task->set_status(task_object::status_e::scheduled);
        }

        auto* loc = get_loc();
        worker_pool_storage* pool = nullptr;
        if (raw_task->get_pool_assigned())
            pool = pool_for_index(raw_task->pool_index);
        else
            pool = assign_pool_for(loc, *raw_task);
        if (!pool)
            std::abort();

        if (created)
            task_mark_created(*raw_task);
        pool->ops.queue.enqueue(*pool, loc, raw_task);
    }

    void transfer_task(task&& task, enter_state* stat) {
        route_task(std::move(task), stat);
    }
}
