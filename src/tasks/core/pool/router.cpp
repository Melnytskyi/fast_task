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
            for (uint16_t i = 0; i < pool_table_size; ++i) {
                if (auto pool = acquire_pool_ref(static_cast<uint8_t>(i)))
                    running += pool_in_run_tasks(*pool);
            }
            if (task::max_running_tasks <= running)
                return false;
        }
        return true;
    }

    namespace {
        pool_ref assign_pool_for(executors_local* loc, task_object& raw_task) noexcept {
            pool_ref inherit;
            if (loc && loc->is_task_thread && loc->curr_task) {
                auto& parent = get_data(loc->curr_task);
                if (parent.get_pool_assigned())
                    inherit = acquire_pool_ref(parent.pool_index);
            }

            if (!inherit)
                inherit = acquire_implicit_pool_ref();

            if (!inherit && loc && loc->owner_pool)
                inherit = acquire_pool_ref(loc->owner_pool->pool_index);

            if (inherit && (inherit->config.inherit_pool_on_spawn || inherit->config.allow_implicit_start)) {
                raw_task.pool_index = inherit->pool_index;
                raw_task.set_pool_assigned(true);
                return inherit;
            }
            raw_task.pool_index = global_pool_index;
            raw_task.set_pool_assigned(true);
            return acquire_pool_ref(global_pool_index);
        }
    }

    void route_task(task&& task, enter_state* stat, bool pre_scheduled) {
        if (!task) {
            auto& global = global_storage();
            global.ops.queue.enqueue(global, nullptr, task.release());
            return;
        }

        if (!pre_scheduled) {
            fast_task::lock_guard task_guard(get_data(task));
            if (get_data(task).is_suspending()) {
                get_data(task).set_resume_requested(true);
                return;
            }
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
        pool_ref pool;
        if (pre_scheduled) {
            fast_task::lock_guard task_guard(*raw_task);
            if (raw_task->get_pool_assigned())
                pool = acquire_pool_ref(raw_task->pool_index);
            else
                pool = assign_pool_for(loc, *raw_task);
            if (!pool) {
                raw_task->pool_index = global_pool_index;
                raw_task->set_pool_assigned(true);
                pool = acquire_pool_ref(global_pool_index);
            }
            if (!pool)
                std::abort();
            pool->runtime.executing_tasks.fetch_add(1, std::memory_order_acq_rel);
        } else {
            if (raw_task->get_pool_assigned())
                pool = acquire_pool_ref(raw_task->pool_index);
            else
                pool = assign_pool_for(loc, *raw_task);
            if (!pool) {
                raw_task->pool_index = global_pool_index;
                raw_task->set_pool_assigned(true);
                pool = acquire_pool_ref(global_pool_index);
            }
            if (!pool)
                std::abort();
            if (created)
                pool->runtime.executing_tasks.fetch_add(1, std::memory_order_acq_rel);
        }
        pool->ops.queue.enqueue(*pool, loc, raw_task);
    }

    void transfer_task(task&& task, enter_state* stat) {
        route_task(std::move(task), stat);
    }
}
