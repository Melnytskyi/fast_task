// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <tasks.hpp>
#include <tasks/_internal.hpp>

namespace fast_task {
    struct task_mutex::resume_task {
        std::shared_ptr<task> task;
        uint16_t awake_check = 0;
        fast_task::condition_variable_any* native_cv = nullptr;
        bool* native_check = nullptr;
    };

    task_mutex::task_mutex() {}

    task_mutex::~task_mutex() {
        if (!resume_task.empty()) {
            assert(false && "Tried to destroy locked mutex");
            std::terminate();
        }
    }
#if defined(__GNUC__) && !defined(__clang__)
    #pragma GCC push_options
    #pragma GCC optimize("O0")
#endif
#pragma optimize("", off)

    void task_mutex::lock() {
        if (loc.is_task_thread) {
            get_data(loc.curr_task).awaked = false;
            get_data(loc.curr_task).time_end_flag = false;

            fast_task::lock_guard lg(no_race);
            if (current_task == &*loc.curr_task)
                throw std::logic_error("Tried lock mutex twice");
            while (current_task) {
                resume_task.emplace_back(loc.curr_task, get_data(loc.curr_task).awake_check);
                swapCtxRelock(no_race);
            }
            current_task = &*loc.curr_task;
        } else {
            fast_task::unique_lock ul(no_race);
            std::shared_ptr<task> task;

            if (current_task == reinterpret_cast<fast_task::task*>((size_t)_thread_id() | native_thread_flag))
                throw std::logic_error("Tried lock mutex twice");
            while (current_task) {
                fast_task::condition_variable_any cd;
                bool has_res = false;
                resume_task.emplace_back(nullptr, 0, &cd, &has_res);
                while (!has_res) //-V654
                    cd.wait(ul);
            }
            current_task = reinterpret_cast<fast_task::task*>((size_t)_thread_id() | native_thread_flag);
        }
    }

    bool task_mutex::try_lock() {
        if (!no_race.try_lock())
            return false;
        fast_task::unique_lock ul(no_race, fast_task::adopt_lock);

        if (current_task)
            return false;
        else if (loc.is_task_thread || loc.context_in_swap) {
            if (current_task == &*loc.curr_task)
                return false;
            current_task = &*loc.curr_task;
        } else {
            if (current_task == reinterpret_cast<task*>((size_t)_thread_id() | native_thread_flag))
                return false;
            current_task = reinterpret_cast<task*>((size_t)_thread_id() | native_thread_flag);
        }
        return true;
    }

    bool task_mutex::try_lock_for(size_t milliseconds) {
        return try_lock_until(std::chrono::high_resolution_clock::now() + std::chrono::milliseconds(milliseconds));
    }

    bool task_mutex::try_lock_until(std::chrono::high_resolution_clock::time_point time_point) {
        if (!no_race.try_lock_until(time_point))
            return false;
        fast_task::unique_lock ul(no_race, fast_task::adopt_lock);

        if (loc.is_task_thread && !loc.context_in_swap) {
            if (current_task == &*loc.curr_task)
                return false;
            while (current_task) {
                fast_task::lock_guard guard(get_data(loc.curr_task).no_race);
                makeTimeWait(time_point);
                resume_task.emplace_back(loc.curr_task, get_data(loc.curr_task).awake_check);
                swapCtxRelock(get_data(loc.curr_task).no_race, no_race);
                if (!get_data(loc.curr_task).awaked)
                    return false;
            }
            current_task = &*loc.curr_task;
            return true;
        } else {
            if (current_task == reinterpret_cast<task*>((size_t)_thread_id() | native_thread_flag))
                return false;
            bool has_res;
            fast_task::condition_variable_any cd;
            while (current_task) {
                has_res = false;
                auto rs_task = resume_task.emplace_back(nullptr, 0, &cd, &has_res);
                while (!has_res) { //-V654
                    if (cd.wait_until(ul, time_point) == cv_status::timeout) {
                        rs_task.native_cv = nullptr;
                        return false;
                    }
                }
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
        fast_task::lock_guard lg0(no_race);
        if (loc.is_task_thread) {
            if (current_task != &*loc.curr_task)
                throw std::logic_error("Tried unlock non owned mutex");
        } else if (current_task != reinterpret_cast<task*>((size_t)_thread_id() | native_thread_flag))
            throw std::logic_error("Tried unlock non owned mutex");

        current_task = nullptr;
        while (resume_task.size()) {
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

    bool task_mutex::is_locked() {
        if (try_lock()) {
            unlock();
            return false;
        }
        return true;
    }

    bool task_mutex::is_own() {
        fast_task::lock_guard lg0(no_race);
        if (loc.is_task_thread) {
            if (current_task != &*loc.curr_task)
                return false;
        } else if (current_task != reinterpret_cast<task*>((size_t)_thread_id() | native_thread_flag))
            return false;
        return true;
    }

    void task_mutex::lifecycle_lock(std::shared_ptr<task>& lock_task) {
        if (get_data(lock_task).started)
            throw std::logic_error("Task already started");
        if (get_data(lock_task).callbacks.is_extended_mode) {
            if (!get_data(lock_task).callbacks.extended_mode.on_start)
                throw std::logic_error("lifecycle_lock requires in extended mode the on_start variable to be set");
            else if (!get_data(lock_task).callbacks.extended_mode.is_coroutine)
                throw std::logic_error("lifecycle_lock requires in extended mode the coroutine mode to be disabled");
            else {
                task::run([lock_task, this]() {
                    fast_task::lock_guard guard(*this);
                    task::await_task(lock_task, true);
                });
            }
        } else {
            auto old_func = std::move(get_data(lock_task).callbacks.normal_mode.func);
            get_data(lock_task).callbacks.normal_mode.func = [old_func = std::move(old_func), this]() {
                fast_task::lock_guard guard(*this);
                old_func();
            };
            scheduler::start(lock_task);
        }
    }
}
