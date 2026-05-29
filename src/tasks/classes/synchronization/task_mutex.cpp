// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <task.hpp>
#include <tasks/_internal.hpp>

namespace fast_task {
    task_mutex::task_mutex() {
        FT_DEBUG_ONLY(register_object(this));
    }

    task_mutex::~task_mutex() {
        FT_DEBUG_ONLY(unregister_object(this));
        if (!values.resume_task.empty()) {
            assert(false && "Tried to destroy locked mutex");
            std::terminate();
        }
    }

    void task_mutex::lock() {
        if (get_loc().is_task_thread) {
            get_data(get_loc().curr_task).awaked = false;
            get_data(get_loc().curr_task).time_end_flag = false;

            fast_task::lock_guard lg(values.no_race);
            if (values.current_task == &*get_loc().curr_task)
                throw std::logic_error("Tried lock mutex twice");
            while (values.current_task) {
                values.resume_task.emplace_back(get_loc().curr_task, get_data(get_loc().curr_task).awake_check);
                swapCtxRelock(values.no_race);
            }
            values.current_task = &*get_loc().curr_task;
        } else {
            fast_task::unique_lock ul(values.no_race);
            std::shared_ptr<task> task;

            if (values.current_task == reinterpret_cast<fast_task::task*>((size_t)_thread_id() | native_thread_flag))
                throw std::logic_error("Tried lock mutex twice");
            while (values.current_task) {
                fast_task::condition_variable_any cd;
                bool has_res = false;
                values.resume_task.emplace_back(nullptr, (uint16_t)0, &cd, &has_res);
                while (!has_res) //-V654
                    cd.wait(ul);
            }
            values.current_task = reinterpret_cast<fast_task::task*>((size_t)_thread_id() | native_thread_flag);
        }
    }

    bool task_mutex::try_lock() {
        if (!values.no_race.try_lock())
            return false;
        fast_task::unique_lock ul(values.no_race, fast_task::adopt_lock);

        if (values.current_task)
            return false;
        else if (get_loc().is_task_thread || get_loc().context_in_swap) {
            if (values.current_task == &*get_loc().curr_task)
                return false;
            values.current_task = &*get_loc().curr_task;
        } else {
            if (values.current_task == reinterpret_cast<task*>((size_t)_thread_id() | native_thread_flag))
                return false;
            values.current_task = reinterpret_cast<task*>((size_t)_thread_id() | native_thread_flag);
        }
        return true;
    }

    bool task_mutex::try_lock_until(std::chrono::high_resolution_clock::time_point time_point) {
        fast_task::unique_lock ul(values.no_race);

        if (get_loc().is_task_thread && !get_loc().context_in_swap) {
            if (values.current_task == &*get_loc().curr_task)
                return false;
            while (values.current_task) {
                fast_task::lock_guard guard(glob.task_timer_safety);
                makeTimeWait_unsafe(time_point);
                values.resume_task.emplace_back(get_loc().curr_task, get_data(get_loc().curr_task).awake_check);
                swapCtxRelock(glob.task_timer_safety, values.no_race);
                auto awaked = get_data(get_loc().curr_task).awaked;
                resetTimeWait();
                if (!awaked) {
                    auto it = std::find_if(values.resume_task.begin(), values.resume_task.end(), [](const auto& a) { return a.task == get_loc().curr_task; });
                    if (it != values.resume_task.end())
                        values.resume_task.erase(it);
                    return false;
                }
            }
            values.current_task = &*get_loc().curr_task;
            return true;
        } else {
            if (values.current_task == reinterpret_cast<task*>((size_t)_thread_id() | native_thread_flag))
                return false;
            bool has_res;
            fast_task::condition_variable_any cd;
            while (values.current_task) {
                has_res = false;
                auto& rs_task = values.resume_task.emplace_back(nullptr, (uint16_t)0, &cd, &has_res);
                while (!has_res) { //-V654
                    if (cd.wait_until(ul, time_point) == cv_status::timeout) {
                        rs_task.native_cv = nullptr;
                        return false;
                    }
                }
            }
            if (!get_loc().context_in_swap)
                values.current_task = reinterpret_cast<task*>((size_t)_thread_id() | native_thread_flag);
            else
                values.current_task = &*get_loc().curr_task;
            return true;
        }
    }

    void task_mutex::unlock() {
        fast_task::lock_guard lg0(values.no_race);
        if (get_loc().is_task_thread) {
            if (values.current_task != &*get_loc().curr_task)
                throw std::logic_error("Tried unlock non owned mutex");
        } else if (values.current_task != reinterpret_cast<task*>((size_t)_thread_id() | native_thread_flag))
            throw std::logic_error("Tried unlock non owned mutex");

        values.current_task = nullptr;
        while (values.resume_task.size()) {
            auto [it, awake_check, native_cv, native_flag] = values.resume_task.front();
            values.resume_task.pop_front();
            if (it == nullptr) {
                if (native_cv != nullptr) {
                    *native_flag = true;
                    native_cv->notify_all();
                    return;
                }
                continue;
            }
            fast_task::lock_guard lg1(get_data(it).no_race);
            if (get_data(it).awake_check != awake_check)
                continue;
            if (!get_data(it).time_end_flag) {
                get_data(it).awaked = true;
                if (get_data(it).is_on_scheduler)
                    values.current_task = it.get();
                transfer_task(std::move(it));
                return;
            }
        }
    }

    bool task_mutex::is_locked() {
        if (try_lock()) {
            unlock();
            return false;
        }
        return true;
    }

    bool task_mutex::is_own() {
        fast_task::lock_guard lg0(values.no_race);
        if (get_loc().is_task_thread) {
            if (values.current_task != &*get_loc().curr_task)
                return false;
        } else if (values.current_task != reinterpret_cast<task*>((size_t)_thread_id() | native_thread_flag))
            return false;
        return true;
    }

    void task_mutex::lifecycle_lock(std::shared_ptr<task>&& lock_task) {
        {
            fast_task::lock_guard guard(get_data(lock_task).no_race);
            if (get_data(lock_task).running || get_data(lock_task).end_of_life)
                throw std::runtime_error("Task is running or completed and cannot be registered");
            if (get_data(lock_task).started && (!get_data(lock_task).suspended && get_data(lock_task).is_on_scheduler))
                throw std::runtime_error("Task is already in the scheduler queue");
            if (!get_data(lock_task).callbacks.on_start)
                throw std::logic_error("task_mutex::lifecycle_lock requires the on_start callback to be set");
        }
        task::run([lock_task, this]() {
            fast_task::lock_guard guard(*this);
            task::await_task(lock_task, true);
        });
    }

    bool task_mutex::enter_wait(const std::shared_ptr<task>& task) {
        fast_task::lock_guard l(values.no_race);
        if (values.current_task == nullptr) {
            values.current_task = task.get();
            return true;
        } else {
            values.resume_task.push_back({task, get_data(task).awake_check, nullptr, nullptr});
            return false;
        }
    }

    bool task_mutex::enter_wait_until(const std::shared_ptr<task>& task, std::chrono::high_resolution_clock::time_point time_point) {
        fast_task::lock_guard l(values.no_race);
        if (values.current_task == nullptr) {
            values.current_task = task.get();
            return true;
        } else {
            values.resume_task.push_back({task, get_data(task).awake_check, nullptr, nullptr});
            fast_task::makeTimeWait_extern(task, time_point);
            return false;
        }
    }
}
