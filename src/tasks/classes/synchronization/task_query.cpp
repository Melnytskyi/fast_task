// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <tasks.hpp>

namespace fast_task {
    struct task_query_handle {                  //344 [sizeof]
        task_mutex no_race;                     //188
        bool destructed = false;                //1
        bool is_running = false;                //1
        ;                                       //1 [padding]
        task_condition_variable end_of_query;   //104
        ;                                       //7 [padding]
        std::list<std::shared_ptr<task>> tasks; //24
        task_query* tq = nullptr;               //8
        size_t now_at_execution = 0;            //8
        size_t at_execution_max = 0;            //8
    };

    task_query::task_query(size_t at_execution_max) {
        handle = new task_query_handle{.tq = this, .at_execution_max = at_execution_max};
    }

    void __TaskQuery_add_task_leave(task_query_handle* tqh) {
        std::lock_guard lock(tqh->no_race);
        if (tqh->destructed) {
            if (tqh->at_execution_max == 0)
                delete tqh;
        }

        if (!tqh->tasks.empty() && tqh->is_running) {
            tqh->now_at_execution--;
            while (tqh->now_at_execution <= tqh->at_execution_max) {
                tqh->now_at_execution++;
                auto awake_task = tqh->tasks.front();
                tqh->tasks.pop_front();
                task::start(awake_task);
            }
        } else {
            tqh->now_at_execution--;

            if (tqh->now_at_execution == 0 && tqh->tasks.empty())
                tqh->end_of_query.notify_all();
        }
    }

    void redefine_start_function(std::shared_ptr<task>& task, task_query_handle* tqh) {
        auto old_func = std::move(task->func);
        task->func = [old_func = std::move(old_func), tqh]() {
            try {
                old_func();
            } catch (...) {
                __TaskQuery_add_task_leave(tqh);
                throw;
            }
            __TaskQuery_add_task_leave(tqh);
        };
    }

    void task_query::add(std::shared_ptr<task>&& querying_task) {
        if (querying_task->started)
            throw std::runtime_error("Task already started");
        redefine_start_function(querying_task, handle);
        std::lock_guard lock(handle->no_race);
        if (handle->is_running && handle->now_at_execution <= handle->at_execution_max) {
            task::start(std::move(querying_task));
            handle->now_at_execution++;
        } else
            handle->tasks.push_back(std::move(querying_task));
    }

    void task_query::add(std::shared_ptr<task>& querying_task) {
        if (querying_task->started)
            throw std::runtime_error("Task already started");
        redefine_start_function(querying_task, handle);
        std::lock_guard lock(handle->no_race);
        if (handle->is_running && handle->now_at_execution <= handle->at_execution_max) {
            task::start(querying_task);
            handle->now_at_execution++;
        } else
            handle->tasks.push_back(querying_task);
    }

    void task_query::enable() {
        std::lock_guard lock(handle->no_race);
        handle->is_running = true;
        while (handle->now_at_execution < handle->at_execution_max && !handle->tasks.empty()) {
            auto awake_task = handle->tasks.front();
            handle->tasks.pop_front();
            task::start(awake_task);
            handle->now_at_execution++;
        }
    }

    void task_query::disable() {
        std::lock_guard lock(handle->no_race);
        handle->is_running = false;
    }

    bool task_query::in_query(const std::shared_ptr<task>& task) {
        if (task->started)
            return false;
        std::lock_guard lock(handle->no_race);
        return std::find(handle->tasks.begin(), handle->tasks.end(), task) != handle->tasks.end();
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
        while (handle->now_at_execution != 0 && !handle->tasks.empty())
            handle->end_of_query.wait(lock);
    }

    bool task_query::wait_for(size_t milliseconds) {
        return wait_until(std::chrono::high_resolution_clock::now() + std::chrono::milliseconds(milliseconds));
    }

    bool task_query::wait_until(std::chrono::high_resolution_clock::time_point time_point) {
        mutex_unify unify(handle->no_race);
        std::unique_lock lock(unify);
        while (handle->now_at_execution != 0 && !handle->tasks.empty()) {
            if (!handle->end_of_query.wait_until(lock, time_point))
                return false;
        }
        return true;
    }

    task_query::~task_query() {
        if (handle) {
            handle->is_running = false;
            handle->destructed = true;
            wait();
            delete handle;
            handle = nullptr;
        }
    }
}