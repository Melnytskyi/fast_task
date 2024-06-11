// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <tasks.hpp>
#include <tasks/_internal.hpp>

namespace fast_task {
    task_condition_variable::task_condition_variable() = default;

    task_condition_variable::~task_condition_variable() {
        notify_all();
    }

    void task_condition_variable::wait(std::unique_lock<mutex_unify>& mut) {
        if (loc.is_task_thread) {
            if (mut.mutex()->nmut == &no_race) {
                resume_task.emplace_back(loc.curr_task, loc.curr_task->awake_check);
                swapCtxRelock(no_race);
            } else {
                std::lock_guard guard(no_race);
                resume_task.emplace_back(loc.curr_task, loc.curr_task->awake_check);
                swapCtxRelock(*mut.mutex(), no_race);
            }
        } else {
            std::condition_variable_any cd;
            bool has_res = false;
            std::shared_ptr<task> task = task::cxx_native_bridge(has_res, cd);
            if (mut.mutex()->nmut == &no_race) {
                resume_task.emplace_back(task, task->awake_check);
                while (!has_res)
                    cd.wait(mut);
            } else {
                no_race.lock();
                resume_task.emplace_back(task, task->awake_check);
                no_race.unlock();
                while (!has_res)
                    cd.wait(mut);
            }
        task_not_ended:
            task->no_race.lock();
            if (!task->end_of_life) {
                task->no_race.unlock();
                goto task_not_ended;
            }
            task->no_race.unlock();
        }
    }

    bool task_condition_variable::wait_for(std::unique_lock<mutex_unify>& mut, size_t milliseconds) {
        return wait_until(mut, std::chrono::high_resolution_clock::now() + std::chrono::milliseconds(milliseconds));
    }

    bool task_condition_variable::wait_until(std::unique_lock<mutex_unify>& mut, std::chrono::high_resolution_clock::time_point time_point) {
        if (loc.is_task_thread) {
            std::lock_guard guard(loc.curr_task->no_race);
            makeTimeWait(time_point);
            {
                std::lock_guard guard(no_race);
                resume_task.emplace_back(loc.curr_task, loc.curr_task->awake_check);
            }
            swapCtxRelock(loc.curr_task->no_race);
            if (loc.curr_task->time_end_flag)
                return false;
        } else {
            std::condition_variable_any cd;
            bool has_res = false;
            std::shared_ptr<task> task = task::cxx_native_bridge(has_res, cd);

            if (mut.mutex()->nmut == &no_race) {
                resume_task.emplace_back(task, task->awake_check);
                while (!has_res)
                    cd.wait(mut);
            } else {
                no_race.lock();
                resume_task.emplace_back(task, task->awake_check);
                no_race.unlock();
                while (!has_res)
                    cd.wait(mut);
            }

        task_not_ended:
            task->no_race.lock();
            if (!task->end_of_life) {
                task->no_race.unlock();
                goto task_not_ended;
            }
            task->no_race.unlock();

            return !task->time_end_flag;
        }
        return true;
    }

    void task_condition_variable::notify_all() {
        std::unique_lock no_race_guard(no_race);
        std::list<__::resume_task> revive_tasks(std::move(resume_task));
        no_race_guard.unlock();
        if (revive_tasks.empty())
            return;
        bool to_yield = false;
        {
            std::lock_guard guard(glob.task_thread_safety);
            for (auto& resumer : revive_tasks) {
                auto& it = resumer.task;
                std::lock_guard guard_loc(it->no_race);
                if (resumer.task->awake_check != resumer.awake_check)
                    continue;
                if (!it->time_end_flag) {
                    it->awaked = true;
                    transfer_task(it);
                }
            }
            glob.tasks_notifier.notify_one();
            if (task::max_running_tasks && loc.is_task_thread) {
                if (can_be_scheduled_task_to_hot() && loc.curr_task && !loc.curr_task->end_of_life)
                    to_yield = true;
            }
        }
        if (to_yield)
            task::yield();
    }

    void task_condition_variable::notify_one() {
        std::shared_ptr<task> tsk;
        {
            std::lock_guard guard(no_race);
            while (resume_task.size()) {
                auto& [cur, awake_check] = resume_task.back();
                cur->no_race.lock();
                if (cur->time_end_flag || cur->awake_check != awake_check) {
                    cur->no_race.unlock();
                    resume_task.pop_back();
                } else {
                    tsk = cur;
                    resume_task.pop_back();
                    break;
                }
            }
            if (resume_task.empty() && !tsk)
                return;
        }
        bool to_yield = false;
        std::lock_guard guard_loc(tsk->no_race, std::adopt_lock);
        {
            tsk->awaked = true;
            std::lock_guard guard(glob.task_thread_safety);
            if (task::max_running_tasks && loc.is_task_thread) {
                if (can_be_scheduled_task_to_hot() && loc.curr_task && !loc.curr_task->end_of_life)
                    to_yield = true;
            }
            transfer_task(tsk);
        }
        if (to_yield)
            task::yield();
    }

    bool task_condition_variable::has_waiters() {
        std::lock_guard guard(no_race);
        return !resume_task.empty();
    }

    void task_condition_variable::callback(std::unique_lock<mutex_unify>& mut, const std::shared_ptr<task>& task) {
        if (task->started)
            throw std::logic_error("Task already started");
        if (mut.mutex()->nmut == &no_race) {
            resume_task.emplace_back(task, task->awake_check);
        } else {
            std::lock_guard guard(no_race);
            resume_task.emplace_back(task, task->awake_check);
        }
        task->started = true;
    }
}
