// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <task.hpp>
#include <tasks/_internal.hpp>

namespace fast_task {
    task_query::task_query(size_t at_execution_max) {
        FT_DEBUG_ONLY(register_object(this));
        handle = new task_query_handle{.tq = this, .at_execution_max = at_execution_max};
    }

    void __TaskQuery_add_task_leave(task_query_handle* tqh) {
        fast_task::lock_guard lock(tqh->no_race);
        if (tqh->destructed) {
            if (tqh->at_execution_max == 0) {
                delete tqh;
                return;
            }
        }

        if (!tqh->tasks.empty() && tqh->is_running) {
            tqh->now_at_execution--;
            while (tqh->now_at_execution < tqh->at_execution_max) {
                tqh->now_at_execution++;
                auto awake_task = tqh->tasks.front();
                tqh->tasks.pop_front();
                scheduler::start(awake_task);
            }
        } else {
            tqh->now_at_execution--;

            if (tqh->now_at_execution == 0 && tqh->tasks.empty())
                tqh->end_of_query.notify_all();
        }
    }

    std::shared_ptr<task> redefine_start_function(std::shared_ptr<task>& task, task_query_handle* tqh) {
        if (!get_data(task).callbacks.on_start)
            throw std::logic_error("task_query::add requires the on_start variable to be set");
        else if (get_data(task).callbacks.on_start_override)
            throw std::logic_error("task_query::add requires the on_start_override variable to be unset");
        else {
            get_data(task).callbacks.on_start_override_data = tqh;
            get_data(task).callbacks.on_start_override = [](auto& cb) {
                auto* tqh = reinterpret_cast<task_query_handle*>(cb.on_start_override_data);
                try {
                    cb.on_start(cb.get_data());
                } catch (...) {
                    __TaskQuery_add_task_leave(tqh);
                    cb.on_start_override = nullptr;
                    throw;
                }
                __TaskQuery_add_task_leave(tqh);
                cb.on_start_override = nullptr;
            };
            return task;
        }
    }

    void task_query::add(std::shared_ptr<task>&& querying_task) {
        if (get_data(querying_task).started)
            throw std::runtime_error("Task already started");
        auto new_task = redefine_start_function(querying_task, handle);
        fast_task::lock_guard lock(handle->no_race);
        if (handle->is_running && handle->now_at_execution < handle->at_execution_max) {
            scheduler::start(std::move(new_task));
            handle->now_at_execution++;
        } else
            handle->tasks.push_back(std::move(new_task));
    }

    void task_query::add(std::shared_ptr<task>& querying_task) {
        if (get_data(querying_task).started)
            throw std::runtime_error("Task already started");
        auto new_task = redefine_start_function(querying_task, handle);
        fast_task::lock_guard lock(handle->no_race);
        if (handle->is_running && handle->now_at_execution < handle->at_execution_max) {
            scheduler::start(new_task);
            handle->now_at_execution++;
        } else
            handle->tasks.push_back(new_task);
    }

    void task_query::enable() {
        fast_task::lock_guard lock(handle->no_race);
        handle->is_running = true;
        while (handle->now_at_execution < handle->at_execution_max && !handle->tasks.empty()) {
            auto awake_task = handle->tasks.front();
            handle->tasks.pop_front();
            scheduler::start(awake_task);
            handle->now_at_execution++;
        }
    }

    void task_query::disable() {
        fast_task::lock_guard lock(handle->no_race);
        handle->is_running = false;
    }

    bool task_query::in_query(const std::shared_ptr<task>& task) {
        if (get_data(task).started)
            return false;
        fast_task::lock_guard lock(handle->no_race);
        return std::find(handle->tasks.begin(), handle->tasks.end(), task) != handle->tasks.end();
    }

    void task_query::set_max_at_execution(size_t val) {
        fast_task::lock_guard lock(handle->no_race);
        handle->at_execution_max = val;
    }

    size_t task_query::get_max_at_execution() {
        fast_task::lock_guard lock(handle->no_race);
        return handle->at_execution_max;
    }

    void task_query::wait() {
        mutex_unify unify(handle->no_race);
        fast_task::unique_lock lock(unify);
        while (handle->now_at_execution != 0 || !handle->tasks.empty())
            // Use timed wait to recover from rare lost-wakeup: end_of_query.notify_all()
            // can fire between the while condition check and wait registration when
            // __TaskQuery_add_task_leave runs on another thread with no waiter present.
            handle->end_of_query.wait_until(lock, std::chrono::high_resolution_clock::now() + std::chrono::milliseconds(1));
    }

    bool task_query::wait_until(std::chrono::high_resolution_clock::time_point time_point) {
        mutex_unify unify(handle->no_race);
        fast_task::unique_lock lock(unify);
        while (handle->now_at_execution != 0 || !handle->tasks.empty()) {
            if (!handle->end_of_query.wait_until(lock, time_point))
                return false;
        }
        return true;
    }

    task_query::~task_query() {
        FT_DEBUG_ONLY(unregister_object(this));
        if (handle) {
            handle->is_running = false;
            handle->destructed = true;
            wait();
            delete handle;
            handle = nullptr;
        }
    }

    bool task_query::enter_wait(const std::shared_ptr<task>& task) {
        if (handle->now_at_execution == 0 && handle->tasks.empty())
            return true;

        task::run([this, parent_coro = task] mutable {
            this->wait();
            transfer_task(std::move(parent_coro));
        });

        return false;
    }

    bool task_query::enter_wait_until(const std::shared_ptr<task>& task, std::chrono::high_resolution_clock::time_point time_point) {
        if (handle->now_at_execution == 0 && handle->tasks.empty())
            return true;

        task::run([this, parent_coro = task, time_point] mutable {
            if (!this->wait_until(time_point))
                get_data(parent_coro).time_end_flag = true;

            transfer_task(std::move(parent_coro));
        });

        return false;
    }
}
