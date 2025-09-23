// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <algorithm>
#include <task.hpp>
#include <tasks/_internal.hpp>

namespace fast_task {
    struct task_rw_mutex::resume_task {
        std::shared_ptr<task> task;
        uint16_t awake_check = 0;
        fast_task::condition_variable_any* native_cv = nullptr;
        bool* native_check = nullptr;
    };

    task_rw_mutex::task_rw_mutex() {}

    task_rw_mutex::~task_rw_mutex() {
        if (values.current_writer_task || !values.readers.empty()) {
            assert(false && "Mutex destroyed while locked");
            std::terminate();
        }
    }

#pragma optimize("", off)

    void task_rw_mutex::read_lock() {
        if (loc.is_task_thread) {
            get_data(loc.curr_task).awaked = false;
            get_data(loc.curr_task).time_end_flag = false;

            fast_task::lock_guard lg(values.no_race);
            if (std::find(values.readers.begin(), values.readers.end(), &*loc.curr_task) != values.readers.end())
                throw std::logic_error("Tried lock mutex twice");
            if (values.current_writer_task == &*loc.curr_task)
                throw std::logic_error("Tried lock write and then read mode");
            while (values.current_writer_task) {
                values.resume_task.emplace_back(loc.curr_task, get_data(loc.curr_task).awake_check);
                swapCtxRelock(values.no_race);
            }
            values.readers.push_back(&*loc.curr_task);
        } else {
            fast_task::unique_lock ul(values.no_race);
            fast_task::task* self_mask = reinterpret_cast<fast_task::task*>((size_t)_thread_id() | native_thread_flag);
            if (std::find(values.readers.begin(), values.readers.end(), self_mask) != values.readers.end())
                throw std::logic_error("Tried lock mutex twice");
            while (values.current_writer_task) {
                fast_task::condition_variable_any cd;
                bool has_res = false;
                values.resume_task.emplace_back(nullptr, 0, &cd, &has_res);
                while (!has_res) //-V654
                    cd.wait(ul);
            }
            values.readers.push_back(self_mask);
        }
    }

    bool task_rw_mutex::try_read_lock() {
        if (!values.no_race.try_lock())
            return false;
        fast_task::unique_lock ul(values.no_race, fast_task::adopt_lock);

        if (values.current_writer_task)
            return false;
        else {
            task* self_mask;
            if (loc.is_task_thread || loc.context_in_swap)
                self_mask = &*loc.curr_task;
            else
                self_mask = reinterpret_cast<task*>((size_t)_thread_id() | native_thread_flag);
            if (std::find(values.readers.begin(), values.readers.end(), self_mask) != values.readers.end())
                return false;
            if (values.current_writer_task == &*loc.curr_task)
                return false;
            values.readers.push_back(self_mask);
            return true;
        }
    }

    bool task_rw_mutex::try_read_lock_for(size_t milliseconds) {
        return try_read_lock_until(std::chrono::high_resolution_clock::now() + std::chrono::milliseconds(milliseconds));
    }

    bool task_rw_mutex::try_read_lock_until(std::chrono::high_resolution_clock::time_point time_point) {
        fast_task::unique_lock ul(values.no_race);
        if (loc.is_task_thread) {
            while (values.current_writer_task) {
                get_data(loc.curr_task).awaked = false;
                get_data(loc.curr_task).time_end_flag = false;
                values.resume_task.emplace_back(loc.curr_task, get_data(loc.curr_task).awake_check);
                makeTimeWait(time_point);
                swapCtxRelock(get_data(loc.curr_task).no_race, values.no_race);
                if (!get_data(loc.curr_task).awaked)
                    return false;
            }
        } else {
            while (values.current_writer_task) {
                fast_task::condition_variable_any cd;
                bool has_res = false;
                auto& rs_task = values.resume_task.emplace_back(nullptr, 0, &cd, &has_res);
                while (!has_res) { //-V654
                    if (cd.wait_until(ul, time_point) == cv_status::timeout) {
                        rs_task.native_cv = nullptr;
                        return false;
                    }
                }
            }
        }
        {
            task* self_mask;
            if (loc.is_task_thread || loc.context_in_swap)
                self_mask = &*loc.curr_task;
            else
                self_mask = reinterpret_cast<task*>((size_t)_thread_id() | native_thread_flag);
            if (std::find(values.readers.begin(), values.readers.end(), self_mask) != values.readers.end())
                return false;
            if (values.current_writer_task == &*loc.curr_task)
                return false;
            values.readers.push_back(self_mask);
            return true;
        }
    }

    void task_rw_mutex::read_unlock() {
        fast_task::lock_guard lg0(values.no_race);
        if (values.readers.empty())
            throw std::logic_error("Tried unlock non owned mutex");
        else {
            task* self_mask;
            if (loc.is_task_thread || loc.context_in_swap)
                self_mask = &*loc.curr_task;
            else
                self_mask = reinterpret_cast<task*>((size_t)_thread_id() | native_thread_flag);
            auto it = std::find(values.readers.begin(), values.readers.end(), self_mask);
            if (it == values.readers.end())
                throw std::logic_error("Tried unlock non owned mutex");
            values.readers.erase(it);

            while (values.resume_task.size() && values.readers.empty()) {
                auto [item, awake_check, native_cv, native_flag] = values.resume_task.front();
                values.resume_task.pop_front();
                if (item == nullptr) {
                    if (native_cv != nullptr) {
                        *native_flag = true;
                        native_cv->notify_all();
                        break;
                    }
                    continue;
                }
                fast_task::lock_guard lg1(get_data(item).no_race);
                if (get_data(item).awake_check != awake_check)
                    return;
                if (!get_data(item).time_end_flag) {
                    get_data(item).awaked = true;
                    transfer_task(item);
                }
                break;
            }
        }
    }

    bool task_rw_mutex::is_read_locked() {
        task* self_mask;
        if (loc.is_task_thread || loc.context_in_swap)
            self_mask = &*loc.curr_task;
        else
            self_mask = reinterpret_cast<task*>((size_t)_thread_id() | native_thread_flag);
        auto it = std::find(values.readers.begin(), values.readers.end(), self_mask);
        return it != values.readers.end();
    }

    void task_rw_mutex::lifecycle_read_lock(std::shared_ptr<task>& lock_task) {
        if (get_data(lock_task).started)
            throw std::logic_error("Task already started");
        if (get_data(lock_task).callbacks.is_extended_mode) {
            if (!get_data(lock_task).callbacks.extended_mode.on_start)
                throw std::logic_error("lifecycle_lock requires in extended mode the on_start variable to be set");
            else if (!get_data(lock_task).callbacks.extended_mode.is_coroutine)
                throw std::logic_error("lifecycle_lock requires in extended mode the coroutine mode to be disabled");
            else {
                task::run([lock_task, this]() {
                    fast_task::read_lock guard(*this);
                    task::await_task(lock_task, true);
                });
            }
        } else {
            auto old_func = std::move(get_data(lock_task).callbacks.normal_mode.func);
            get_data(lock_task).callbacks.normal_mode.func = [old_func = std::move(old_func), this]() {
                fast_task::read_lock guard(*this);
                old_func();
            };
            scheduler::start(lock_task);
        }
    }

    void task_rw_mutex::write_lock() {
        if (loc.is_task_thread) {
            get_data(loc.curr_task).awaked = false;
            get_data(loc.curr_task).time_end_flag = false;

            fast_task::lock_guard lg(values.no_race);
            if (values.current_writer_task == &*loc.curr_task)
                throw std::logic_error("Tried lock mutex twice");
            if (std::find(values.readers.begin(), values.readers.end(), &*loc.curr_task) != values.readers.end())
                throw std::logic_error("Tried lock read and then write mode");
            while (values.current_writer_task) {
                values.resume_task.emplace_back(loc.curr_task, get_data(loc.curr_task).awake_check);
                swapCtxRelock(values.no_race);
            }
            values.current_writer_task = &*loc.curr_task;
            while (!values.readers.empty()) {
                values.resume_task.emplace_back(loc.curr_task, get_data(loc.curr_task).awake_check);
                swapCtxRelock(values.no_race);
            }
        } else {
            fast_task::unique_lock ul(values.no_race);
            auto self_mask = reinterpret_cast<task*>((size_t)_thread_id() | native_thread_flag);
            if (values.current_writer_task == self_mask)
                throw std::logic_error("Tried lock mutex twice");
            fast_task::condition_variable_any cd;
            bool has_res = false;
            while (values.current_writer_task) {
                values.resume_task.emplace_back(nullptr, 0, &cd, &has_res);
                while (!has_res) //-V654
                    cd.wait(ul);
            }
            values.current_writer_task = self_mask;
            has_res = false;
            while (!values.readers.empty()) {
                values.resume_task.emplace_back(nullptr, 0, &cd, &has_res);
                while (!has_res) //-V654
                    cd.wait(ul);
            }
        }
    }

    bool task_rw_mutex::try_write_lock() {
        if (!values.no_race.try_lock())
            return false;
        fast_task::unique_lock ul(values.no_race, fast_task::adopt_lock);

        if (values.current_writer_task || !values.readers.empty())
            return false;
        else if (loc.is_task_thread || loc.context_in_swap)
            values.current_writer_task = &*loc.curr_task;
        else
            values.current_writer_task = reinterpret_cast<task*>((size_t)_thread_id() | native_thread_flag);
        return true;
    }

    bool task_rw_mutex::try_write_lock_for(size_t milliseconds) {
        return try_write_lock_until(std::chrono::high_resolution_clock::now() + std::chrono::milliseconds(milliseconds));
    }

    bool task_rw_mutex::try_write_lock_until(std::chrono::high_resolution_clock::time_point time_point) {
        fast_task::unique_lock ul(values.no_race);

        if (loc.is_task_thread && !loc.context_in_swap) {
            get_data(loc.curr_task).awaked = false;
            get_data(loc.curr_task).time_end_flag = false;
            while (values.current_writer_task) {
                fast_task::lock_guard guard(get_data(loc.curr_task).no_race);
                makeTimeWait(time_point);
                values.resume_task.emplace_back(loc.curr_task, get_data(loc.curr_task).awake_check);
                swapCtxRelock(get_data(loc.curr_task).no_race, values.no_race);
                if (!get_data(loc.curr_task).awaked)
                    return false;
            }
            values.current_writer_task = &*loc.curr_task;

            while (!values.readers.empty()) {
                fast_task::lock_guard guard(get_data(loc.curr_task).no_race);
                makeTimeWait(time_point);
                values.resume_task.emplace_back(loc.curr_task, get_data(loc.curr_task).awake_check);
                swapCtxRelock(get_data(loc.curr_task).no_race, values.no_race);
                if (!get_data(loc.curr_task).awaked) {
                    values.current_writer_task = nullptr;
                    return false;
                }
            }
            return true;
        } else {
            bool has_res;
            fast_task::condition_variable_any cd;
            while (values.current_writer_task) {
                has_res = false;
                auto& rs_task = values.resume_task.emplace_back(nullptr, 0, &cd, &has_res);
                while (!has_res) { //-V654
                    if (cd.wait_until(ul, time_point) == cv_status::timeout) {
                        rs_task.native_cv = nullptr;
                        return false;
                    }
                }
            }
            if (!loc.context_in_swap)
                values.current_writer_task = reinterpret_cast<task*>((size_t)_thread_id() | native_thread_flag);
            else
                values.current_writer_task = &*loc.curr_task;

            while (!values.readers.empty()) {
                has_res = false;
                auto& rs_task = values.resume_task.emplace_back(nullptr, 0, &cd, &has_res);
                while (!has_res) { //-V654
                    if (cd.wait_until(ul, time_point) == cv_status::timeout) {
                        rs_task.native_cv = nullptr;
                        values.current_writer_task = nullptr;
                        return false;
                    }
                }
            }
            return true;
        }
    }

    void task_rw_mutex::write_unlock() {
        fast_task::unique_lock ul(values.no_race);
        task* self_mask;
        if (loc.is_task_thread || loc.context_in_swap)
            self_mask = &*loc.curr_task;
        else
            self_mask = reinterpret_cast<task*>((size_t)_thread_id() | native_thread_flag);

        if (values.current_writer_task != self_mask)
            throw std::logic_error("Tried unlock non owned mutex");
        values.current_writer_task = nullptr;
        while (values.resume_task.size()) {
            auto [it, awake_check, native_cv, native_flag] = values.resume_task.front();
            values.resume_task.pop_front();
            if (it == nullptr) {
                if (native_cv != nullptr) {
                    *native_flag = true;
                    native_cv->notify_all();
                }
                continue;
            }
            fast_task::lock_guard lg1(get_data(it).no_race);
            if (get_data(it).awake_check != awake_check)
                continue;
            if (!get_data(it).time_end_flag) {
                get_data(it).awaked = true;
                transfer_task(it);
            }
        }
    }

#pragma optimize("", on)

    bool task_rw_mutex::is_write_locked() {
        task* self_mask;
        if (loc.is_task_thread || loc.context_in_swap)
            self_mask = &*loc.curr_task;
        else
            self_mask = reinterpret_cast<task*>((size_t)_thread_id() | native_thread_flag);
        return values.current_writer_task == self_mask;
    }

    void task_rw_mutex::lifecycle_write_lock(std::shared_ptr<task>& lock_task) {
        if (get_data(lock_task).started)
            throw std::logic_error("Task already started");
        if (get_data(lock_task).callbacks.is_extended_mode) {
            if (!get_data(lock_task).callbacks.extended_mode.on_start)
                throw std::logic_error("lifecycle_lock requires in extended mode the on_start variable to be set");
            else if (!get_data(lock_task).callbacks.extended_mode.is_coroutine)
                throw std::logic_error("lifecycle_lock requires in extended mode the coroutine mode be to disabled");
            else {
                task::run([lock_task, this]() {
                    fast_task::write_lock guard(*this);
                    task::await_task(lock_task, true);
                });
            }
        } else {
            auto old_func = std::move(get_data(lock_task).callbacks.normal_mode.func);
            get_data(lock_task).callbacks.normal_mode.func = [old_func = std::move(old_func), this]() {
                fast_task::write_lock guard(*this);
                old_func();
            };
            scheduler::start(lock_task);
        }
    }

    bool task_rw_mutex::is_own() {
        if (is_write_locked())
            return true;
        else
            return is_read_locked();
    }
}
