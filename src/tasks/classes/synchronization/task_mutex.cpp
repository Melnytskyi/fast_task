// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <tasks.hpp>
#include <tasks/_internal.hpp>

namespace fast_task {
    task_mutex::~task_mutex() {
        std::lock_guard lg(no_race);
        while (!resume_task.empty()) {
            auto& tsk = resume_task.back();
            task::notify_cancel(tsk.task);
            current_task = nullptr;
            task::await_task(tsk.task);
            resume_task.pop_back();
        }
    }
#if defined(__GNUC__) && !defined(__clang__)
    #pragma GCC push_options
    #pragma GCC optimize("O0")
#endif
#pragma optimize("", off)

    void task_mutex::lock() {
        if (loc.is_task_thread) {
            loc.curr_task->awaked = false;
            loc.curr_task->time_end_flag = false;

            std::lock_guard lg(no_race);
            if (current_task == &*loc.curr_task)
                throw std::logic_error("Tried lock mutex twice");
            while (current_task) {
                resume_task.emplace_back(loc.curr_task, loc.curr_task->awake_check);
                swapCtxRelock(no_race);
            }
            current_task = &*loc.curr_task;
        } else {
            std::unique_lock ul(no_race);
            std::shared_ptr<task> task;

            if (current_task == reinterpret_cast<fast_task::task*>((size_t)_thread_id() | native_thread_flag))
                throw std::logic_error("Tried lock mutex twice");
            while (current_task) {
                std::condition_variable_any cd;
                bool has_res = false;
                task = task::cxx_native_bridge(has_res, cd);
                resume_task.emplace_back(task, task->awake_check);
                while (!has_res)
                    cd.wait(ul);
                ul.unlock();
            task_not_ended:
                //prevent destruct cd, because it is used in task
                task->no_race.lock();
                if (!task->end_of_life) {
                    task->no_race.unlock();
                    goto task_not_ended;
                }
                task->no_race.unlock();
            }
            current_task = reinterpret_cast<fast_task::task*>((size_t)_thread_id() | native_thread_flag);
        }
    }

    bool task_mutex::try_lock() {
        if (!no_race.try_lock())
            return false;
        std::unique_lock ul(no_race, std::adopt_lock);

        if (current_task)
            return false;
        else if (loc.is_task_thread || loc.context_in_swap)
            current_task = &*loc.curr_task;
        else
            current_task = reinterpret_cast<task*>((size_t)_thread_id() | native_thread_flag);
        return true;
    }

    bool task_mutex::try_lock_for(size_t milliseconds) {
        return try_lock_until(std::chrono::high_resolution_clock::now() + std::chrono::milliseconds(milliseconds));
    }

    bool task_mutex::try_lock_until(std::chrono::high_resolution_clock::time_point time_point) {
        if (!no_race.try_lock_until(time_point))
            return false;
        std::unique_lock ul(no_race, std::adopt_lock);

        if (loc.is_task_thread && !loc.context_in_swap) {
            while (current_task) {
                std::lock_guard guard(loc.curr_task->no_race);
                makeTimeWait(time_point);
                resume_task.emplace_back(loc.curr_task, loc.curr_task->awake_check);
                swapCtxRelock(loc.curr_task->no_race, no_race);
                if (!loc.curr_task->awaked)
                    return false;
            }
            current_task = &*loc.curr_task;
            return true;
        } else {
            bool has_res;
            std::condition_variable_any cd;
            while (current_task) {
                has_res = false;
                std::shared_ptr<task> task = task::cxx_native_bridge(has_res, cd);
                resume_task.emplace_back(task, task->awake_check);
                while (has_res)
                    cd.wait_until(ul, time_point);
                if (!task->awaked)
                    return false;
            }
            if (!loc.context_in_swap)
                current_task = reinterpret_cast<task*>((size_t)_thread_id() | native_thread_flag);
            else
                current_task = &*loc.curr_task;
            return true;
        }
    }

#pragma optimize("", on)
#if defined(__GNUC__) && !defined(__clang__)
    #pragma GCC pop_options
#endif

    void task_mutex::unlock() {
        std::lock_guard lg0(no_race);
        if (loc.is_task_thread) {
            if (current_task != &*loc.curr_task)
                throw std::logic_error("Tried unlock non owned mutex");
        } else if (current_task != reinterpret_cast<task*>((size_t)_thread_id() | native_thread_flag))
            throw std::logic_error("Tried unlock non owned mutex");

        current_task = nullptr;
        if (resume_task.size()) {
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

    bool task_mutex::is_locked() {
        if (try_lock()) {
            unlock();
            return false;
        }
        return true;
    }

    bool task_mutex::is_own() {
        std::lock_guard lg0(no_race);
        if (loc.is_task_thread) {
            if (current_task != &*loc.curr_task)
                return false;
        } else if (current_task != reinterpret_cast<task*>((size_t)_thread_id() | native_thread_flag))
            return false;
        return true;
    }

    void task_mutex::lifecycle_lock(const std::shared_ptr<task>& lock_task) {
        task::start(std::make_shared<task>([&] {
            std::unique_lock guard(*this, std::defer_lock);
            while (!lock_task->end_of_life) {
                guard.lock();
                task::await_task(lock_task);
                guard.unlock();
            }
        }));
    }
}
