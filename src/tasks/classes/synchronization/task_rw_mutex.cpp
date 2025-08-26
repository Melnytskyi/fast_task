// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <algorithm>
#include <tasks.hpp>
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
        if (current_writer_task || !readers.empty()) {
            assert(false && "Mutex destroyed while locked");
            std::terminate();
        }
    }

#pragma optimize("", off)

    void task_rw_mutex::read_lock() {
        if (loc.is_task_thread) {
            get_data(loc.curr_task).awaked = false;
            get_data(loc.curr_task).time_end_flag = false;

            fast_task::lock_guard lg(no_race);
            if (std::find(readers.begin(), readers.end(), &*loc.curr_task) != readers.end())
                throw std::logic_error("Tried lock mutex twice");
            if (current_writer_task == &*loc.curr_task)
                throw std::logic_error("Tried lock write and then read mode");
            while (current_writer_task) {
                resume_task.emplace_back(loc.curr_task, get_data(loc.curr_task).awake_check);
                swapCtxRelock(no_race);
            }
            readers.push_back(&*loc.curr_task);
        } else {
            fast_task::unique_lock ul(no_race);
            fast_task::task* self_mask = reinterpret_cast<fast_task::task*>((size_t)_thread_id() | native_thread_flag);
            if (std::find(readers.begin(), readers.end(), self_mask) != readers.end())
                throw std::logic_error("Tried lock mutex twice");
            while (current_writer_task) {
                fast_task::condition_variable_any cd;
                bool has_res = false;
                resume_task.emplace_back(nullptr, 0, &cd, &has_res);
                while (!has_res) //-V654
                    cd.wait(ul);
            }
            readers.push_back(self_mask);
        }
    }

    bool task_rw_mutex::try_read_lock() {
        if (!no_race.try_lock())
            return false;
        fast_task::unique_lock ul(no_race, fast_task::adopt_lock);

        if (current_writer_task)
            return false;
        else {
            task* self_mask;
            if (loc.is_task_thread || loc.context_in_swap)
                self_mask = &*loc.curr_task;
            else
                self_mask = reinterpret_cast<task*>((size_t)_thread_id() | native_thread_flag);
            if (std::find(readers.begin(), readers.end(), self_mask) != readers.end())
                return false;
            if (current_writer_task == &*loc.curr_task)
                return false;
            readers.push_back(self_mask);
            return true;
        }
    }

    bool task_rw_mutex::try_read_lock_for(size_t milliseconds) {
        return try_read_lock_until(std::chrono::high_resolution_clock::now() + std::chrono::milliseconds(milliseconds));
    }

    bool task_rw_mutex::try_read_lock_until(std::chrono::high_resolution_clock::time_point time_point) {
        if (!no_race.try_lock_until(time_point))
            return false;
        fast_task::unique_lock ul(no_race, fast_task::adopt_lock);
        if (loc.is_task_thread) {
            while (current_writer_task) {
                get_data(loc.curr_task).awaked = false;
                get_data(loc.curr_task).time_end_flag = false;
                resume_task.emplace_back(loc.curr_task, get_data(loc.curr_task).awake_check);
                makeTimeWait(time_point);
                swapCtxRelock(get_data(loc.curr_task).no_race, no_race);
                if (!get_data(loc.curr_task).awaked)
                    return false;
            }
        } else {
            while (current_writer_task) {
                fast_task::condition_variable_any cd;
                bool has_res = false;
                auto& rs_task = resume_task.emplace_back(nullptr, 0, &cd, &has_res);
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
            if (std::find(readers.begin(), readers.end(), self_mask) != readers.end())
                return false;
            if (current_writer_task == &*loc.curr_task)
                return false;
            readers.push_back(self_mask);
            return true;
        }
    }

    void task_rw_mutex::read_unlock() {
        fast_task::lock_guard lg0(no_race);
        if (readers.empty())
            throw std::logic_error("Tried unlock non owned mutex");
        else {
            task* self_mask;
            if (loc.is_task_thread || loc.context_in_swap)
                self_mask = &*loc.curr_task;
            else
                self_mask = reinterpret_cast<task*>((size_t)_thread_id() | native_thread_flag);
            auto it = std::find(readers.begin(), readers.end(), self_mask);
            if (it == readers.end())
                throw std::logic_error("Tried unlock non owned mutex");
            readers.erase(it);

            while (resume_task.size() && readers.empty()) {
                auto [it, awake_check, native_cv, native_flag] = resume_task.front();
                resume_task.pop_front();
                if (it == nullptr) {
                    if (native_cv != nullptr) {
                        *native_flag = true;
                        native_cv->notify_all();
                        break;
                    }
                    continue;
                }
                fast_task::lock_guard lg1(get_data(it).no_race);
                if (get_data(it).awake_check != awake_check)
                    return;
                if (!get_data(it).time_end_flag) {
                    get_data(it).awaked = true;
                    transfer_task(it);
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
        auto it = std::find(readers.begin(), readers.end(), self_mask);
        return it != readers.end();
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

            fast_task::lock_guard lg(no_race);
            if (current_writer_task == &*loc.curr_task)
                throw std::logic_error("Tried lock mutex twice");
            if (std::find(readers.begin(), readers.end(), &*loc.curr_task) != readers.end())
                throw std::logic_error("Tried lock read and then write mode");
            while (current_writer_task) {
                resume_task.emplace_back(loc.curr_task, get_data(loc.curr_task).awake_check);
                swapCtxRelock(no_race);
            }
            current_writer_task = &*loc.curr_task;
            while (!readers.empty()) {
                resume_task.emplace_back(loc.curr_task, get_data(loc.curr_task).awake_check);
                swapCtxRelock(no_race);
            }
        } else {
            fast_task::unique_lock ul(no_race);
            auto self_mask = reinterpret_cast<task*>((size_t)_thread_id() | native_thread_flag);
            if (current_writer_task == self_mask)
                throw std::logic_error("Tried lock mutex twice");
            fast_task::condition_variable_any cd;
            bool has_res = false;
            while (current_writer_task) {
                resume_task.emplace_back(nullptr, 0, &cd, &has_res);
                while (!has_res) //-V654
                    cd.wait(ul);
            }
            current_writer_task = self_mask;
            has_res = false;
            while (!readers.empty()) {
                resume_task.emplace_back(nullptr, 0, &cd, &has_res);
                while (!has_res) //-V654
                    cd.wait(ul);
            }
        }
    }

    bool task_rw_mutex::try_write_lock() {
        if (!no_race.try_lock())
            return false;
        fast_task::unique_lock ul(no_race, fast_task::adopt_lock);

        if (current_writer_task || !readers.empty())
            return false;
        else if (loc.is_task_thread || loc.context_in_swap)
            current_writer_task = &*loc.curr_task;
        else
            current_writer_task = reinterpret_cast<task*>((size_t)_thread_id() | native_thread_flag);
        return true;
    }

    bool task_rw_mutex::try_write_lock_for(size_t milliseconds) {
        return try_write_lock_until(std::chrono::high_resolution_clock::now() + std::chrono::milliseconds(milliseconds));
    }

    bool task_rw_mutex::try_write_lock_until(std::chrono::high_resolution_clock::time_point time_point) {
        if (!no_race.try_lock_until(time_point))
            return false;
        fast_task::unique_lock ul(no_race, fast_task::adopt_lock);

        if (loc.is_task_thread && !loc.context_in_swap) {
            get_data(loc.curr_task).awaked = false;
            get_data(loc.curr_task).time_end_flag = false;
            while (current_writer_task) {
                fast_task::lock_guard guard(get_data(loc.curr_task).no_race);
                makeTimeWait(time_point);
                resume_task.emplace_back(loc.curr_task, get_data(loc.curr_task).awake_check);
                swapCtxRelock(get_data(loc.curr_task).no_race, no_race);
                if (!get_data(loc.curr_task).awaked)
                    return false;
            }
            current_writer_task = &*loc.curr_task;

            while (!readers.empty()) {
                fast_task::lock_guard guard(get_data(loc.curr_task).no_race);
                makeTimeWait(time_point);
                resume_task.emplace_back(loc.curr_task, get_data(loc.curr_task).awake_check);
                swapCtxRelock(get_data(loc.curr_task).no_race, no_race);
                if (!get_data(loc.curr_task).awaked) {
                    current_writer_task = nullptr;
                    return false;
                }
            }
            return true;
        } else {
            bool has_res;
            fast_task::condition_variable_any cd;
            while (current_writer_task) {
                has_res = false;
                auto& rs_task = resume_task.emplace_back(nullptr, 0, &cd, &has_res);
                while (!has_res) { //-V654
                    if (cd.wait_until(ul, time_point) == cv_status::timeout) {
                        rs_task.native_cv = nullptr;
                        return false;
                    }
                }
            }
            if (!loc.context_in_swap)
                current_writer_task = reinterpret_cast<task*>((size_t)_thread_id() | native_thread_flag);
            else
                current_writer_task = &*loc.curr_task;

            while (!readers.empty()) {
                has_res = false;
                auto& rs_task = resume_task.emplace_back(nullptr, 0, &cd, &has_res);
                while (!has_res) { //-V654
                    if (cd.wait_until(ul, time_point) == cv_status::timeout) {
                        rs_task.native_cv = nullptr;
                        current_writer_task = nullptr;
                        return false;
                    }
                }
            }
            return true;
        }
    }

    void task_rw_mutex::write_unlock() {
        fast_task::unique_lock ul(no_race);
        task* self_mask;
        if (loc.is_task_thread || loc.context_in_swap)
            self_mask = &*loc.curr_task;
        else
            self_mask = reinterpret_cast<task*>((size_t)_thread_id() | native_thread_flag);

        if (current_writer_task != self_mask)
            throw std::logic_error("Tried unlock non owned mutex");
        current_writer_task = nullptr;
        while (resume_task.size()) {
            auto [it, awake_check, native_cv, native_flag] = resume_task.front();
            resume_task.pop_front();
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
        return current_writer_task == self_mask;
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
