// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <fast_task/exceptions.hpp>
#include <fast_task/task.hpp>
#include <tasks/_internal.hpp>

namespace fast_task::this_task {
    size_t get_id() noexcept {
        if (get_loc() && get_loc()->is_task_thread)
            return get_loc()->curr_task.get_id();
        else
            return ((size_t)_thread_id() & native_thread_mask) | native_thread_flag;
    }

    bool is_task() noexcept {
        return get_loc() && get_loc()->is_task_thread;
    }

    void check_cancellation() {
        if (checkCancellation())
            throw task_cancellation();
    }

    bool is_cancellation_requested() noexcept {
        return checkCancellation();
    }

    void self_cancel() {
        auto* loc = get_loc();
        if (loc && loc->is_task_thread) {
            if (loc->curr_task)
                loc->curr_task.notify_cancel();
            throw task_cancellation();
        } else
            throw invalid_context();
    }

    void the_coroutine_ended(const task& task) noexcept {
        if (task) {
            {
                fast_task::lock_guard guard(get_data(task));
                get_data(task).set_is_restartable(false);
            }
            get_data(task).end_of_life_notify();
        }
    }

    bool transfer_to(const task& target) {
        auto* loc = get_loc();
        if (!loc || !loc->is_task_thread)
            return false;
        if (!target || !loc->curr_task)
            return false;
        if (loc->ex_ptr)
            return false;
        if (loc->transfer_state.pending)
            return false;
        if (target == loc->curr_task)
            return false;

        task_object& target_data = get_data(target);
        if (!get_data(loc->curr_task).get_is_on_scheduler())
            return false;
        if (!target_data.get_is_on_scheduler())
            return false;
        if (target_data.get_pool_assigned() && target_data.pool_index != loc->pool_index)
            return false;

#if FT_TASK_TRANSFERS_LIMIT > 0
        if (loc->transfer_state.transfers >= FT_TASK_TRANSFERS_LIMIT)
            return false;
#endif
        {
            fast_task::lock_guard guard(target_data);
            if (!(target_data.is_created() ||
                  (target_data.is_suspended() && target_data.get_is_restartable())))
                return false;
            if (target_data.is_created())
                task_mark_created(target_data);
            target_data.set_status(task_object::status_e::scheduled);
        }
#if FT_TASK_TRANSFERS_LIMIT > 0
        ++loc->transfer_state.transfers;
#endif
        loc->transfer_state.pending = target;
        return true;
    }

    void set_pool(scheduler::worker_pool& target_pool) noexcept {
        auto* loc = get_loc();
        if (!loc || !loc->curr_task)
            return;
        retarget_task(get_data(loc->curr_task), scheduler::storage_of(target_pool));
    }

    void switch_to(scheduler::worker_pool& target_pool) {
        auto* loc = get_loc();
        if (!loc || !loc->curr_task)
            throw invalid_context{};
        auto& target = scheduler::storage_of(target_pool);
        if (loc->pool_index == target.pool_index)
            return;
        if (get_data(loc->curr_task).get_is_on_scheduler())
            throw std::logic_error("this_task::switch_to: a stackless coroutine cannot change pools while it runs");
        retarget_task(get_data(loc->curr_task), target);
        loc->yield_request = true;
        swapCtx();
    }

    scheduler::worker_pool& current_pool() noexcept {
        auto* loc = get_loc();
        worker_pool_storage* pool = (loc && loc->owner_pool) ? loc->owner_pool : &global_storage();
        if (auto* handle = pool->public_handle)
            return *handle;
        return scheduler::worker_pool::global();
    }

    void sleep_until(fast_task::time_point time_point) {
        if (auto* loc = get_loc(); loc && loc->is_task_thread) {
            loc->pending_timer = time_point;
            swapCtx();
            resetTimeWait();
        } else
            native::this_thread::sleep_until(time_point);
    }

    bool FT_API enter_sleep_until(enter_state&, fast_task::time_point time_point) {
        auto* loc = get_loc();
        if (!loc || !loc->is_task_thread)
            return true;
        if (fast_task::clock::now() >= time_point)
            return true;
        loc->pending_timer = time_point;
        return false;
    }

    bool FT_API enter_yield(enter_state&) {
        auto* loc = get_loc();
        if (!loc || !loc->is_task_thread)
            throw invalid_context();
        auto& curr = get_data(loc->curr_task);
        fast_task::lock_guard guard(curr);
        transfer_task(task{loc->curr_task});
        return false;
    }

    void yield() {
        if (auto* loc = get_loc(); loc && loc->is_task_thread) {
            loc->yield_request = true;
            swapCtx();
        } else
            native::this_thread::yield();
    }
}