// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <tasks.hpp>

namespace fast_task {
    struct task_query_handle {
        task_query* tq = nullptr;
        size_t at_execution_max = 0;
        size_t now_at_execution = 0;
        task_mutex no_race;
        bool destructed = false;
        task_condition_variable end_of_query;
    };

    task_query::task_query(size_t at_execution_max) {
        is_running = false;
        handle = new task_query_handle{this, at_execution_max};
    }

    void __TaskQuery_add_task_leave(task_query_handle* tqh, task_query* tq) {
        std::lock_guard lock(tqh->no_race);
        if (tqh->destructed) {
            if (tqh->at_execution_max == 0)
                delete tqh;
        } else if (!tq->tasks.empty() && tq->is_running) {
            tq->handle->now_at_execution--;
            while (tq->handle->now_at_execution <= tq->handle->at_execution_max) {
                tq->handle->now_at_execution++;
                auto awake_task = tq->tasks.front();
                tq->tasks.pop_front();
                task::start(awake_task);
            }
        } else {
            tq->handle->now_at_execution--;

            if (tq->handle->now_at_execution == 0 && tq->tasks.empty())
                tq->handle->end_of_query.notify_all();
        }
    }

    void task_query::add(const std::shared_ptr<task>& querying_task) {
        std::lock_guard lock(handle->no_race);
        if (is_running && handle->now_at_execution <= handle->at_execution_max) {
            task::start(querying_task);
            handle->now_at_execution++;
        } else
            tasks.push_back(querying_task);
    }

    void task_query::enable() {
        std::lock_guard lock(handle->no_race);
        is_running = true;
        while (handle->now_at_execution < handle->at_execution_max && !tasks.empty()) {
            auto awake_task = tasks.front();
            tasks.pop_front();
            task::start(awake_task);
            handle->now_at_execution++;
        }
    }

    void task_query::disable() {
        std::lock_guard lock(handle->no_race);
        is_running = false;
    }

    bool task_query::in_query(const std::shared_ptr<task>& task) {
        if (task->started)
            return false; //started task can't be in query
        std::lock_guard lock(handle->no_race);
        return std::find(tasks.begin(), tasks.end(), task) != tasks.end();
    }

    void task_query::set_max_at_execution(size_t val) {
        std::lock_guard lock(handle->no_race);
        handle->at_execution_max = val;
    }

    size_t task_query::get_max_at_execution() {
        std::lock_guard lock(handle->no_race);
        return handle->at_execution_max;
    }

    void task_query::wait() {
        mutex_unify unify(handle->no_race);
        std::unique_lock lock(unify);
        while (handle->now_at_execution != 0 && !tasks.empty())
            handle->end_of_query.wait(lock);
    }

    bool task_query::wait_for(size_t milliseconds) {
        return wait_until(std::chrono::high_resolution_clock::now() + std::chrono::milliseconds(milliseconds));
    }

    bool task_query::wait_until(std::chrono::high_resolution_clock::time_point time_point) {
        mutex_unify unify(handle->no_race);
        std::unique_lock lock(unify);
        while (handle->now_at_execution != 0 && !tasks.empty()) {
            if (!handle->end_of_query.wait_until(lock, time_point))
                return false;
        }
        return true;
    }

    task_query::~task_query() {
        handle->destructed = true;
        wait();
        if (handle->now_at_execution == 0)
            delete handle;
    }
}