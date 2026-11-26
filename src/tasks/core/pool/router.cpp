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
        inline pool_ref resolve_pool_ref(uint8_t index, executors_local* loc) noexcept {
            if (index == global_pool_index)
                return pool_ref(&global_storage(), false);
            if (loc && loc->owner_pool && loc->owner_pool->pool_index == index)
                return pool_ref(loc->owner_pool, false);
            return acquire_pool_ref(index);
        }

        pool_ref assign_pool_for(executors_local* loc, task_object& raw_task) noexcept {
            pool_ref inherit;
            if (loc && loc->is_task_thread && loc->curr_task) {
                auto& parent = get_data(loc->curr_task);
                if (parent.get_pool_assigned())
                    inherit = resolve_pool_ref(parent.pool_index, loc);
            }

            if (!inherit)
                inherit = acquire_implicit_pool_ref();

            if (!inherit && loc && loc->owner_pool)
                inherit = resolve_pool_ref(loc->owner_pool->pool_index, loc);

            if (inherit && (inherit->config.inherit_pool_on_spawn || inherit->config.allow_implicit_start)) {
                raw_task.pool_index = inherit->pool_index;
                raw_task.set_pool_assigned(true);
                return inherit;
            }
            raw_task.pool_index = global_pool_index;
            raw_task.set_pool_assigned(true);
            return pool_ref(&global_storage(), false);
        }
    }

    void route_task(task&& task, enter_state* stat, bool pre_scheduled, bool is_yield) {
        if (!task) {
            auto& global = global_storage();
            global.ops.queue.enqueue(global, nullptr, task.release());
            return;
        }

        if (!pre_scheduled && get_data(task).get_execution_mode() == task_object::execution_mode::as_coroutine) {
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
                pool = resolve_pool_ref(raw_task->pool_index, loc);
            else
                pool = assign_pool_for(loc, *raw_task);
            if (!pool) {
                raw_task->pool_index = global_pool_index;
                raw_task->set_pool_assigned(true);
                pool = pool_ref(&global_storage(), false);
            }
            pool->runtime.executing_tasks.fetch_add(1, std::memory_order_acq_rel);
        } else {
            if (raw_task->get_pool_assigned())
                pool = resolve_pool_ref(raw_task->pool_index, loc);
            else
                pool = assign_pool_for(loc, *raw_task);
            if (!pool) {
                raw_task->pool_index = global_pool_index;
                raw_task->set_pool_assigned(true);
                pool = pool_ref(&global_storage(), false);
            }
            if (created)
                pool->runtime.executing_tasks.fetch_add(1, std::memory_order_acq_rel);
        }

        executors_local* enqueue_loc = loc;
        if (is_yield && loc && loc->owner_pool == pool.get()) {
            if (!loc->local_tasks.empty() || pool->runtime.executing_tasks.load(std::memory_order_relaxed) > 1)
                enqueue_loc = nullptr;
        }
        pool->ops.queue.enqueue(*pool, enqueue_loc, raw_task);
    }

    void transfer_task(task&& task, enter_state* stat) {
        route_task(std::move(task), stat, false, false);
    }

    void yield_task(task&& task) {
        route_task(std::move(task), nullptr, false, true);
    }
}
