// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <task.hpp>
#include <tasks/_internal.hpp>
#include <variant>

namespace fast_task {

    task_condition_variable::task_condition_variable() {
        FT_DEBUG_ONLY(register_object(this));
    }

    task_condition_variable::~task_condition_variable() {
        FT_DEBUG_ONLY(unregister_object(this));
        if (!values.resume_task.empty()) {
            assert(false && "Condition_variable destroyed while waited");
            std::terminate();
        }
    }

    void task_condition_variable::wait(fast_task::unique_lock<mutex_unify>& mut) {
        if (loc.is_task_thread) {
            if (*mut.mutex() == values.no_race) {
                values.resume_task.emplace_back(loc.curr_task, get_data(loc.curr_task).awake_check);
                swapCtxRelock(values.no_race);
            } else {
                fast_task::lock_guard guard(values.no_race);
                values.resume_task.emplace_back(loc.curr_task, get_data(loc.curr_task).awake_check);
                swapCtxRelock(*mut.mutex(), values.no_race);
            }
        } else {
            fast_task::condition_variable_any cd;
            bool has_res = false;
            if (*mut.mutex() == values.no_race) {
                values.resume_task.emplace_back(nullptr, 0, &cd, &has_res);
                while (!has_res) //-V654
                    cd.wait(mut);
            } else {
                fast_task::unique_lock no_race_guard(values.no_race);
                values.resume_task.emplace_back(nullptr, 0, &cd, &has_res);
                relock_guard relock(mut);
                while (!has_res) //-V654
                    cd.wait(no_race_guard);
                no_race_guard.unlock();
            }
        }
    }

    bool task_condition_variable::wait_until(fast_task::unique_lock<mutex_unify>& mut, std::chrono::high_resolution_clock::time_point time_point) {
        if (loc.is_task_thread) {
            fast_task::lock_guard guard(glob.task_timer_safety);
            makeTimeWait_unsafe(time_point);
            {
                fast_task::lock_guard _guard(values.no_race);
                values.resume_task.emplace_back(loc.curr_task, get_data(loc.curr_task).awake_check);
            }
            swapCtxRelock(glob.task_timer_safety);
            auto time_end_flag = get_data(loc.curr_task).time_end_flag;
            resetTimeWait();
            if (time_end_flag) {
                fast_task::lock_guard _guard(values.no_race);
                auto it = std::find_if(values.resume_task.begin(), values.resume_task.end(), [](const auto& a){ return a.task == loc.curr_task; });
                if (it != values.resume_task.end())
                    values.resume_task.erase(it);
                return false;
            }
        } else {
            fast_task::condition_variable_any cd;
            bool has_res = false;
            if (*mut.mutex() == values.no_race) {
                values.resume_task.emplace_back(nullptr, 0, &cd, &has_res);
                while (!has_res) { //-V654
                    if (cd.wait_until(mut, time_point) == cv_status::timeout) {
                        auto it = std::find_if(values.resume_task.begin(), values.resume_task.end(), [&](const auto& a) { return a.native_cv == &cd; });
                        if (it != values.resume_task.end())
                            values.resume_task.erase(it);
                        return false;
                    }
                }
            } else {
                fast_task::unique_lock no_race_guard(values.no_race);
                values.resume_task.emplace_back(nullptr, 0, &cd, &has_res);
                relock_guard relock(mut);
                while (!has_res) { //-V654
                    if (cd.wait_until(no_race_guard, time_point) == cv_status::timeout) {
                        auto it = std::find_if(values.resume_task.begin(), values.resume_task.end(), [&](const auto& a) { return a.native_cv == &cd; });
                        if (it != values.resume_task.end())
                            values.resume_task.erase(it);
                        // Unlock no_race_guard BEFORE returning so the relock_guard
                        // destructor (which re-acquires mut) doesn't hold no_race
                        // simultaneously — that would create an ABBA deadlock with
                        // any notifier that holds mut and needs no_race.
                        no_race_guard.unlock();
                        return false;
                    }
                }
                no_race_guard.unlock();
            }
        }
        return true;
    }

    void task_condition_variable::wait(std::unique_lock<mutex_unify>& mut) {
        if (loc.is_task_thread) {
            if (*mut.mutex() == values.no_race) {
                values.resume_task.emplace_back(loc.curr_task, get_data(loc.curr_task).awake_check);
                swapCtxRelock(values.no_race);
            } else {
                fast_task::lock_guard guard(values.no_race);
                values.resume_task.emplace_back(loc.curr_task, get_data(loc.curr_task).awake_check);
                swapCtxRelock(*mut.mutex(), values.no_race);
            }
        } else {
            fast_task::condition_variable_any cd;
            bool has_res = false;
            if (*mut.mutex() == values.no_race) {
                values.resume_task.emplace_back(nullptr, 0, &cd, &has_res);
                while (!has_res) //-V654
                    cd.wait(mut);
            } else {
                fast_task::unique_lock no_race_guard(values.no_race);
                values.resume_task.emplace_back(nullptr, 0, &cd, &has_res);
                relock_guard relock(mut);
                while (!has_res) //-V654
                    cd.wait(no_race_guard);
                no_race_guard.unlock();
            }
        }
    }

    bool task_condition_variable::wait_until(std::unique_lock<mutex_unify>& mut, std::chrono::high_resolution_clock::time_point time_point) {
        if (loc.is_task_thread) {
            fast_task::lock_guard guard(glob.task_timer_safety);
            makeTimeWait_unsafe(time_point);
            {
                fast_task::lock_guard _guard(values.no_race);
                values.resume_task.emplace_back(loc.curr_task, get_data(loc.curr_task).awake_check);
            }
            swapCtxRelock(glob.task_timer_safety);
            auto time_end_flag = get_data(loc.curr_task).time_end_flag;
            resetTimeWait();
            if (time_end_flag) {
                fast_task::lock_guard _guard(values.no_race);
                auto it = std::find_if(values.resume_task.begin(), values.resume_task.end(), [](const auto& a){ return a.task == loc.curr_task; });
                if (it != values.resume_task.end())
                    values.resume_task.erase(it);
                return false;
            }
        } else {
            fast_task::condition_variable_any cd;
            bool has_res = false;
            if (*mut.mutex() == values.no_race) {
                values.resume_task.emplace_back(nullptr, 0, &cd, &has_res);
                while (!has_res) { //-V654
                    if (cd.wait_until(mut, time_point) == cv_status::timeout) {
                        auto it = std::find_if(values.resume_task.begin(), values.resume_task.end(), [&](const auto& a) { return a.native_cv == &cd; });
                        if (it != values.resume_task.end())
                            values.resume_task.erase(it);
                        return false;
                    }
                }
            } else {
                fast_task::unique_lock no_race_guard(values.no_race);
                values.resume_task.emplace_back(nullptr, 0, &cd, &has_res);
                relock_guard relock(mut);
                while (!has_res) { //-V654
                    if (cd.wait_until(no_race_guard, time_point) == cv_status::timeout) {
                        auto it = std::find_if(values.resume_task.begin(), values.resume_task.end(), [&](const auto& a) { return a.native_cv == &cd; });
                        if (it != values.resume_task.end())
                            values.resume_task.erase(it);
                        no_race_guard.unlock();
                        return false;
                    }
                }
                no_race_guard.unlock();
            }
        }
        return true;
    }

    void task_condition_variable::notify_all() {
        fast_task::unique_lock no_race_guard(values.no_race);
        std::list<struct resume_task> revive_tasks(std::move(values.resume_task));
        no_race_guard.unlock();
        if (revive_tasks.empty())
            return;
        bool to_yield = false;
        {
            fast_task::shared_lock guard(glob.task_thread_safety);
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
                    fast_task::relock_guard guard_relock(guard);
                    transfer_task(std::move(it));
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

    void task_condition_variable::notify_all_guarded() {
        std::list<struct resume_task> revive_tasks;
        {
            fast_task::unique_lock no_race_guard(values.no_race);
            revive_tasks = std::move(values.resume_task);
        }
        if (revive_tasks.empty())
            return;
        bool to_yield = false;
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
                transfer_task(std::move(it));
            }
        }
        glob.tasks_notifier.notify_one();
        if (task::max_running_tasks && loc.is_task_thread) {
            if (can_be_scheduled_task_to_hot() && loc.curr_task && !get_data(loc.curr_task).end_of_life)
                to_yield = true;
        }
        if (to_yield)
            this_task::yield();
    }

    void task_condition_variable::notify_one() {
        std::shared_ptr<task> tsk;
        {
            fast_task::lock_guard guard(values.no_race);
            while (values.resume_task.size()) {
                auto& [cur, awake_check, native_cv, native_flag] = values.resume_task.back();
                if (cur == nullptr) {
                    if (native_cv != nullptr) {
                        *native_flag = true;
                        native_cv->notify_all();
                        values.resume_task.pop_back();
                        return;
                    }
                    values.resume_task.pop_back();
                    continue;
                }
                fast_task::unique_lock ul(get_data(cur).no_race);
                if (get_data(cur).time_end_flag || get_data(cur).awake_check != awake_check) {
                    ul.unlock();
                    values.resume_task.pop_back();
                } else {
                    tsk = cur;
                    values.resume_task.pop_back();
                    break;
                }
            }
            if (!tsk)
                return;
        }
        bool to_yield = false;
        fast_task::lock_guard guard_loc(get_data(tsk).no_race, fast_task::adopt_lock);
        {
            get_data(tsk).awaked = true;
            fast_task::shared_lock guard(glob.task_thread_safety);
            if (task::max_running_tasks && loc.is_task_thread) {
                if (can_be_scheduled_task_to_hot() && loc.curr_task && !get_data(loc.curr_task).end_of_life)
                    to_yield = true;
            }
            guard.unlock();
            transfer_task(std::move(tsk));
        }
        if (to_yield)
            this_task::yield();
    }

    bool task_condition_variable::has_waiters() {
        fast_task::lock_guard guard(values.no_race);
        return !values.resume_task.empty();
    }

    void task_condition_variable::callback(fast_task::unique_lock<mutex_unify>& mut, const std::shared_ptr<task>& task) {
        if (get_data(task).started)
            throw std::logic_error("Task already started");
        if (*mut.mutex() == values.no_race) {
            values.resume_task.emplace_back(task, get_data(task).awake_check);
        } else {
            fast_task::lock_guard guard(values.no_race);
            values.resume_task.emplace_back(task, get_data(task).awake_check);
        }
        get_data(task).started = true;
        ++glob.executing_tasks;
    }

    void task_condition_variable::callback(std::unique_lock<mutex_unify>& mut, const std::shared_ptr<task>& task) {
        if (get_data(task).started)
            throw std::logic_error("Task already started");
        if (*mut.mutex() == values.no_race) {
            values.resume_task.emplace_back(task, get_data(task).awake_check);
        } else {
            fast_task::lock_guard guard(values.no_race);
            values.resume_task.emplace_back(task, get_data(task).awake_check);
        }
        get_data(task).started = true;
        ++glob.executing_tasks;
    }

    bool task_condition_variable::enter_wait(mutex_unify& mut, const std::shared_ptr<task>& task) {
        fast_task::lock_guard l(values.no_race);
        get_data(loc.curr_task).relock_0 = mut;
        values.resume_task.push_back({task, get_data(task).awake_check, nullptr, nullptr});
        return false;
    }

    bool task_condition_variable::enter_wait_until(mutex_unify& mut, const std::shared_ptr<task>& task, std::chrono::high_resolution_clock::time_point time_point) {
        if (std::chrono::high_resolution_clock::now() >= time_point)
            return true;
        fast_task::lock_guard l(values.no_race);
        get_data(loc.curr_task).relock_0 = mut;
        values.resume_task.push_back({task, get_data(task).awake_check, nullptr, nullptr});
        fast_task::makeTimeWait_extern(task, time_point);
        return false;
    }
}
