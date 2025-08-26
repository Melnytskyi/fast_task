// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <tasks.hpp>
#include <tasks/_internal.hpp>
#include <variant>

namespace fast_task {
    struct task_condition_variable::resume_task {
        std::shared_ptr<task> task;
        uint16_t awake_check = 0;
        fast_task::condition_variable_any* native_cv = nullptr;
        bool* native_check = nullptr;
    };

    task_condition_variable::task_condition_variable() {}

    task_condition_variable::~task_condition_variable() {
        if (!resume_task.empty()) {
            assert(false && "Condition_variable destroyed while waited");
            std::terminate();
        }
    }

    void task_condition_variable::wait(fast_task::unique_lock<mutex_unify>& mut) {
        if (loc.is_task_thread) {
            if (*mut.mutex() == no_race) {
                resume_task.emplace_back(loc.curr_task, get_data(loc.curr_task).awake_check);
                swapCtxRelock(no_race);
            } else {
                fast_task::lock_guard guard(no_race);
                resume_task.emplace_back(loc.curr_task, get_data(loc.curr_task).awake_check);
                swapCtxRelock(*mut.mutex(), no_race);
            }
        } else {
            fast_task::condition_variable_any cd;
            bool has_res = false;
            if (*mut.mutex() == no_race) {
                resume_task.emplace_back(nullptr, 0, &cd, &has_res);
                while (!has_res) //-V654
                    cd.wait(mut);
            } else {
                fast_task::unique_lock no_race_guard(no_race);
                resume_task.emplace_back(nullptr, 0, &cd, &has_res);
                no_race_guard.unlock();
                while (!has_res) //-V654
                    cd.wait(mut);
            }
        }
    }

    bool task_condition_variable::wait_for(fast_task::unique_lock<mutex_unify>& mut, size_t milliseconds) {
        return wait_until(mut, std::chrono::high_resolution_clock::now() + std::chrono::milliseconds(milliseconds));
    }

    bool task_condition_variable::wait_until(fast_task::unique_lock<mutex_unify>& mut, std::chrono::high_resolution_clock::time_point time_point) {
        if (loc.is_task_thread) {
            fast_task::lock_guard guard(get_data(loc.curr_task).no_race);
            makeTimeWait(time_point);
            {
                fast_task::lock_guard guard(no_race);
                resume_task.emplace_back(loc.curr_task, get_data(loc.curr_task).awake_check);
            }
            swapCtxRelock(get_data(loc.curr_task).no_race);
            if (get_data(loc.curr_task).time_end_flag)
                return false;
        } else {
            fast_task::condition_variable_any cd;
            bool has_res = false;
            if (*mut.mutex() == no_race) {
                auto& rs_task = resume_task.emplace_back(nullptr, 0, &cd, &has_res);
                while (!has_res) { //-V654
                    if (cd.wait_until(mut, time_point) == cv_status::timeout) {
                        rs_task.native_cv = nullptr;
                        return false;
                    }
                }
            } else {
                fast_task::unique_lock no_race_guard(no_race);
                auto& rs_task = resume_task.emplace_back(nullptr, 0, &cd, &has_res);
                no_race_guard.unlock();
                while (!has_res) { //-V654
                    if (cd.wait_until(mut, time_point) == cv_status::timeout) {
                        no_race_guard.lock();
                        rs_task.native_cv = nullptr;
                        return false;
                    }
                }
            }
        }
        return true;
    }

    void task_condition_variable::wait(std::unique_lock<mutex_unify>& mut) {
        if (loc.is_task_thread) {
            if (*mut.mutex() == no_race) {
                resume_task.emplace_back(loc.curr_task, get_data(loc.curr_task).awake_check);
                swapCtxRelock(no_race);
            } else {
                fast_task::lock_guard guard(no_race);
                resume_task.emplace_back(loc.curr_task, get_data(loc.curr_task).awake_check);
                swapCtxRelock(*mut.mutex(), no_race);
            }
        } else {
            fast_task::condition_variable_any cd;
            bool has_res = false;
            if (*mut.mutex() == no_race) {
                resume_task.emplace_back(nullptr, 0, &cd, &has_res);
                while (!has_res) //-V654
                    cd.wait(mut);
            } else {
                fast_task::unique_lock no_race_guard(no_race);
                resume_task.emplace_back(nullptr, 0, &cd, &has_res);
                no_race_guard.unlock();
                while (!has_res) //-V654
                    cd.wait(mut);
            }
        }
    }

    bool task_condition_variable::wait_for(std::unique_lock<mutex_unify>& mut, size_t milliseconds) {
        return wait_until(mut, std::chrono::high_resolution_clock::now() + std::chrono::milliseconds(milliseconds));
    }

    bool task_condition_variable::wait_until(std::unique_lock<mutex_unify>& mut, std::chrono::high_resolution_clock::time_point time_point) {
        if (loc.is_task_thread) {
            fast_task::lock_guard guard(get_data(loc.curr_task).no_race);
            makeTimeWait(time_point);
            {
                fast_task::lock_guard guard(no_race);
                resume_task.emplace_back(loc.curr_task, get_data(loc.curr_task).awake_check);
            }
            swapCtxRelock(get_data(loc.curr_task).no_race);
            if (get_data(loc.curr_task).time_end_flag)
                return false;
        } else {
            fast_task::condition_variable_any cd;
            bool has_res = false;
            if (*mut.mutex() == no_race) {
                auto& rs_task = resume_task.emplace_back(nullptr, 0, &cd, &has_res);
                while (!has_res) { //-V654
                    if (cd.wait_until(mut, time_point) == cv_status::timeout) {
                        rs_task.native_cv = nullptr;
                        return false;
                    }
                }
            } else {
                fast_task::unique_lock no_race_guard(no_race);
                auto& rs_task = resume_task.emplace_back(nullptr, 0, &cd, &has_res);
                no_race_guard.unlock();
                while (!has_res) { //-V654
                    if (cd.wait_until(mut, time_point) == cv_status::timeout) {
                        no_race_guard.lock();
                        rs_task.native_cv = nullptr;
                        return false;
                    }
                }
            }
        }
        return true;
    }

    void task_condition_variable::notify_all() {
        fast_task::unique_lock no_race_guard(no_race);
        std::list<struct resume_task> revive_tasks(std::move(resume_task));
        no_race_guard.unlock();
        if (revive_tasks.empty())
            return;
        bool to_yield = false;
        {
            fast_task::lock_guard guard(glob.task_thread_safety);
            for (auto& [it, awake_check, native_cv, native_flag] : revive_tasks) {
                if (it == nullptr) {
                    if (native_cv != nullptr) {
                        *native_flag = true;
                        native_cv->notify_all();
                    }
                    continue;
                }
                fast_task::lock_guard guard_loc(get_data(it).no_race);
                if (get_data(it).awake_check != awake_check)
                    continue;
                if (!get_data(it).time_end_flag) {
                    get_data(it).awaked = true;
                    transfer_task(it);
                }
            }
            glob.tasks_notifier.notify_one();
            if (task::max_running_tasks && loc.is_task_thread) {
                if (can_be_scheduled_task_to_hot() && loc.curr_task && !get_data(loc.curr_task).end_of_life)
                    to_yield = true;
            }
        }
        if (to_yield)
            this_task::yield();
    }

    void task_condition_variable::notify_one() {
        std::shared_ptr<task> tsk;
        {
            fast_task::lock_guard guard(no_race);
            while (resume_task.size()) {
                auto& [cur, awake_check, native_cv, native_flag] = resume_task.back();
                if (cur == nullptr) {
                    if (native_cv != nullptr) {
                        *native_flag = true;
                        native_cv->notify_all();
                        continue;
                    }
                    continue;
                }
                fast_task::unique_lock ul(get_data(cur).no_race);
                if (get_data(cur).time_end_flag || get_data(cur).awake_check != awake_check) {
                    ul.unlock();
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
        fast_task::lock_guard guard_loc(get_data(tsk).no_race, fast_task::adopt_lock);
        {
            get_data(tsk).awaked = true;
            fast_task::lock_guard guard(glob.task_thread_safety);
            if (task::max_running_tasks && loc.is_task_thread) {
                if (can_be_scheduled_task_to_hot() && loc.curr_task && !get_data(loc.curr_task).end_of_life)
                    to_yield = true;
            }
            transfer_task(tsk);
        }
        if (to_yield)
            this_task::yield();
    }

    bool task_condition_variable::has_waiters() {
        fast_task::lock_guard guard(no_race);
        return !resume_task.empty();
    }

    void task_condition_variable::callback(fast_task::unique_lock<mutex_unify>& mut, const std::shared_ptr<task>& task) {
        if (get_data(task).started)
            throw std::logic_error("Task already started");
        if (*mut.mutex() == no_race) {
            resume_task.emplace_back(task, get_data(task).awake_check);
        } else {
            fast_task::lock_guard guard(no_race);
            resume_task.emplace_back(task, get_data(task).awake_check);
        }
        get_data(task).started = true;
    }

    void task_condition_variable::callback(std::unique_lock<mutex_unify>& mut, const std::shared_ptr<task>& task) {
        if (get_data(task).started)
            throw std::logic_error("Task already started");
        if (*mut.mutex() == no_race) {
            resume_task.emplace_back(task, get_data(task).awake_check);
        } else {
            fast_task::lock_guard guard(no_race);
            resume_task.emplace_back(task, get_data(task).awake_check);
        }
        get_data(task).started = true;
    }
}
