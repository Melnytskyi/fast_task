// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <algorithm>
#include <tasks.hpp>
#include <tasks/_internal.hpp>

namespace fast_task {


    task_rw_mutex::~task_rw_mutex() {
        std::lock_guard lg(no_race);
        if (current_writer_task || !readers.empty()) {
            assert(false && "Mutex destroyed while locked");
            std::terminate();
        }
    }

#pragma optimize("", off)
    void task_rw_mutex::read_lock() {
        if (loc.is_task_thread) {
            loc.curr_task->awaked = false;
            loc.curr_task->time_end_flag = false;

            std::lock_guard lg(no_race);
            if (std::find(readers.begin(), readers.end(), &*loc.curr_task) != readers.end())
                throw std::logic_error("Tried lock mutex twice");
            if (current_writer_task == &*loc.curr_task)
                throw std::logic_error("Tried lock write and then read mode");
            while (current_writer_task) {
                resume_task.emplace_back(loc.curr_task, loc.curr_task->awake_check);
                swapCtxRelock(no_race);
            }
            readers.push_back(&*loc.curr_task);
        } else {
            std::unique_lock ul(no_race);
            std::shared_ptr<task> task;
            fast_task::task* self_mask = reinterpret_cast<fast_task::task*>((size_t)_thread_id() | native_thread_flag);
            if (std::find(readers.begin(), readers.end(), self_mask) != readers.end())
                throw std::logic_error("Tried lock mutex twice");
            while (current_writer_task) {
                std::condition_variable_any cd;
                bool has_res = false;
                task = task::cxx_native_bridge(has_res, cd);
                resume_task.emplace_back(task, task->awake_check);
                while (!has_res)
                    cd.wait(ul);
                ul.unlock();
            task_not_ended:
                task->no_race.lock();
                if (!task->end_of_life) {
                    task->no_race.unlock();
                    goto task_not_ended;
                }
                task->no_race.unlock();
                ul.lock();
            }
            readers.push_back(self_mask);
        }
    }

    bool task_rw_mutex::try_read_lock() {
        if (!no_race.try_lock())
            return false;
        std::unique_lock ul(no_race, std::adopt_lock);

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
        std::unique_lock ul(no_race, std::adopt_lock);

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

    void task_rw_mutex::read_unlock() {
        std::lock_guard lg0(no_race);
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

            if (resume_task.size() && readers.empty() && !current_writer_task) {
                std::shared_ptr<task> it = resume_task.front().task;
                uint16_t awake_check = resume_task.front().awake_check;
                resume_task.pop_front();
                std::lock_guard lg1(it->no_race);
                if (it->awake_check != awake_check)
                    return;
                if (!it->time_end_flag) {
                    it->awaked = true;
                    transfer_task(it);
                }
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
        if (lock_task->started)
            throw std::logic_error("Task already started");

        auto old_func = std::move(lock_task->func);
        lock_task->func = [old_func = std::move(old_func), this]() {
            fast_task::read_lock guard(*this);
            old_func();
        };
        task::start(lock_task);
    }

    void task_rw_mutex::write_lock() {
        if (loc.is_task_thread) {
            loc.curr_task->awaked = false;
            loc.curr_task->time_end_flag = false;

            std::lock_guard lg(no_race);
            if (current_writer_task == &*loc.curr_task)
                throw std::logic_error("Tried lock mutex twice");
            if (std::find(readers.begin(), readers.end(), &*loc.curr_task) != readers.end())
                throw std::logic_error("Tried lock read and then write mode");
            while (current_writer_task) {
                resume_task.emplace_back(loc.curr_task, loc.curr_task->awake_check);
                swapCtxRelock(no_race);
            }
            current_writer_task = &*loc.curr_task;
            while (!readers.empty()) {
                resume_task.emplace_back(loc.curr_task, loc.curr_task->awake_check);
                swapCtxRelock(no_race);
            }
        } else {
            std::unique_lock ul(no_race);
            std::shared_ptr<task> task;

            if (current_writer_task == reinterpret_cast<fast_task::task*>((size_t)_thread_id() | native_thread_flag))
                throw std::logic_error("Tried lock mutex twice");
            while (current_writer_task) {
                std::condition_variable_any cd;
                bool has_res = false;
                task = task::cxx_native_bridge(has_res, cd);
                resume_task.emplace_back(task, task->awake_check);
                while (!has_res)
                    cd.wait(ul);
            task_not_ended:
                //prevent destruct cd, because it is used in task
                task->no_race.lock();
                if (!task->end_of_life) {
                    task->no_race.unlock();
                    goto task_not_ended;
                }
                task->no_race.unlock();
            }
            current_writer_task = reinterpret_cast<fast_task::task*>((size_t)_thread_id() | native_thread_flag);
            while (!readers.empty()) {
                std::condition_variable_any cd;
                bool has_res = false;
                task = task::cxx_native_bridge(has_res, cd);
                resume_task.emplace_back(task, task->awake_check);
                while (!has_res)
                    cd.wait(ul);
            task_not_ended2:
                //prevent destruct cd, because it is used in task
                task->no_race.lock();
                if (!task->end_of_life) {
                    task->no_race.unlock();
                    goto task_not_ended2;
                }
                task->no_race.unlock();
            }
        }
    }

    bool task_rw_mutex::try_write_lock() {
        if (!no_race.try_lock())
            return false;
        std::unique_lock ul(no_race, std::adopt_lock);

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
        std::unique_lock ul(no_race, std::adopt_lock);

        if (loc.is_task_thread && !loc.context_in_swap) {
            while (current_writer_task) {
                std::lock_guard guard(loc.curr_task->no_race);
                makeTimeWait(time_point);
                resume_task.emplace_back(loc.curr_task, loc.curr_task->awake_check);
                swapCtxRelock(loc.curr_task->no_race, no_race);
                if (!loc.curr_task->awaked)
                    return false;
            }
            current_writer_task = &*loc.curr_task;

            while (!readers.empty()) {
                std::lock_guard guard(loc.curr_task->no_race);
                makeTimeWait(time_point);
                resume_task.emplace_back(loc.curr_task, loc.curr_task->awake_check);
                swapCtxRelock(loc.curr_task->no_race, no_race);
                if (!loc.curr_task->awaked) {
                    current_writer_task = nullptr;
                    return false;
                }
            }
            return true;
        } else {
            bool has_res;
            std::condition_variable_any cd;
            while (current_writer_task) {
                has_res = false;
                std::shared_ptr<task> task = task::cxx_native_bridge(has_res, cd);
                resume_task.emplace_back(task, task->awake_check);
                while (has_res)
                    cd.wait_until(ul, time_point);
                if (!task->awaked)
                    return false;
            }
            if (!loc.context_in_swap)
                current_writer_task = reinterpret_cast<task*>((size_t)_thread_id() | native_thread_flag);
            else
                current_writer_task = &*loc.curr_task;

            while (!readers.empty()) {
                has_res = false;
                std::shared_ptr<task> task = task::cxx_native_bridge(has_res, cd);
                resume_task.emplace_back(task, task->awake_check);
                while (has_res)
                    cd.wait_until(ul, time_point);
                if (!task->awaked) {
                    current_writer_task = nullptr;
                    return false;
                }
            }
            return true;
        }
    }

    void task_rw_mutex::write_unlock() {
        std::unique_lock ul(no_race);
        task* self_mask;
        if (loc.is_task_thread || loc.context_in_swap)
            self_mask = &*loc.curr_task;
        else
            self_mask = reinterpret_cast<task*>((size_t)_thread_id() | native_thread_flag);

        if (current_writer_task != self_mask)
            throw std::logic_error("Tried unlock non owned mutex");
        current_writer_task = nullptr;
        while (resume_task.size()) {
            std::shared_ptr<task> it = resume_task.front().task;
            uint16_t awake_check = resume_task.front().awake_check;
            resume_task.pop_front();
            std::lock_guard lg1(it->no_race);
            if (it->awake_check != awake_check)
                continue;
            if (!it->time_end_flag) {
                it->awaked = true;
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
        if (lock_task->started)
            throw std::logic_error("Task already started");

        auto old_func = std::move(lock_task->func);
        lock_task->func = [old_func = std::move(old_func), this]() {
            fast_task::write_lock guard(*this);
            old_func();
        };
        task::start(lock_task);
    }

    bool task_rw_mutex::is_own() {
        if (is_write_locked())
            return true;
        else
            return is_read_locked();
    }
}
