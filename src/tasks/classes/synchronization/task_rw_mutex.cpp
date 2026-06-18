// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <algorithm>
#include <task.hpp>
#include <tasks/_internal.hpp>

namespace fast_task {
    task_rw_mutex::task_rw_mutex() {
        FT_DEBUG_ONLY(register_object(this));
    }

    task_rw_mutex::~task_rw_mutex() {
        FT_DEBUG_ONLY(unregister_object(this));
        if (values.current_writer_task || !values.readers.empty()) {
            assert(false && "Mutex destroyed while locked");
            std::terminate();
        }
    }

    void task_rw_mutex::push_back(private_values& values, resume_task* node) {
        node->next = nullptr;
        node->prev = values.end;
        if (values.end) {
            values.end->next = node;
        } else
            values.begin = node;

        values.end = node;
    }

    void task_rw_mutex::erase(private_values& values, resume_task* node) {
        if (node->prev) {
            node->prev->next = node->next;
        } else
            values.begin = node->next;

        if (node->next) {
            node->next->prev = node->prev;
        } else
            values.end = node->prev;

        node->next = nullptr;
        node->prev = nullptr;
    }

    void task_rw_mutex::read_lock() {
        resume_task node;
        if (get_loc().is_task_thread) {
            get_data(get_loc().curr_task).set_awaked(false);
            get_data(get_loc().curr_task).set_time_end(false);
            node.task = get_loc().curr_task;

            fast_task::lock_guard lg(values.no_race);
            if (std::find(values.readers.begin(), values.readers.end(), get_loc().curr_task.get_id()) != values.readers.end())
                throw std::logic_error("Tried lock mutex twice");
            if (values.current_writer_task == get_loc().curr_task.get_id())
                throw std::logic_error("Tried lock write and then read mode");
            while (values.current_writer_task) {
                node.awake_check = get_data(node.task).awake_check;
                push_back(values, &node);
                swapCtxRelock(values.no_race);
            }
            values.readers.push_back(get_loc().curr_task.get_id());
        } else {
            fast_task::condition_variable_any cd;
            bool has_res = false;
            node.task = nullptr;
            node.awake_check = 0;
            node.native_cv = &cd;
            node.native_check = &has_res;
            fast_task::unique_lock ul(values.no_race);
            size_t self_mask = (size_t)_thread_id() | native_thread_flag;
            if (std::find(values.readers.begin(), values.readers.end(), self_mask) != values.readers.end())
                throw std::logic_error("Tried lock mutex twice");
            while (values.current_writer_task) {
                push_back(values, &node);
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
            size_t self_mask;
            if (get_loc().is_task_thread || get_loc().context_in_swap)
                self_mask = get_loc().curr_task.get_id();
            else
                self_mask = (size_t)_thread_id() | native_thread_flag;
            if (std::find(values.readers.begin(), values.readers.end(), self_mask) != values.readers.end())
                return false;
            if (values.current_writer_task == get_loc().curr_task.get_id())
                return false;
            values.readers.push_back(self_mask);
            return true;
        }
    }

    bool task_rw_mutex::try_read_lock_until(std::chrono::high_resolution_clock::time_point time_point) {
        resume_task node;
        fast_task::unique_lock ul(values.no_race);
        if (get_loc().is_task_thread) {
            node.task = get_loc().curr_task;
            while (values.current_writer_task) {
                get_data(get_loc().curr_task).set_awaked(false);
                get_data(get_loc().curr_task).set_time_end(false);
                node.awake_check = get_data(node.task).awake_check;
                push_back(values, &node);
                makeTimeWait(time_point);
                swapCtxRelock(values.no_race);
                auto awaked = get_data(get_loc().curr_task).get_awaked();
                resetTimeWait();
                if (!awaked) {
                    erase(values, &node);
                    return false;
                }
            }
        } else {
            fast_task::condition_variable_any cd;
            bool has_res = false;
            node.task = nullptr;
            node.awake_check = 0;
            node.native_cv = &cd;
            node.native_check = &has_res;
            while (values.current_writer_task) {
                push_back(values, &node);
                while (!has_res) { //-V654
                    if (cd.wait_until(ul, time_point) == cv_status::timeout) {
                        erase(values, &node);
                        return false;
                    }
                }
            }
        }
        {
            size_t self_mask;
            if (get_loc().is_task_thread || get_loc().context_in_swap)
                self_mask = get_loc().curr_task.get_id();
            else
                self_mask = (size_t)_thread_id() | native_thread_flag;
            if (std::find(values.readers.begin(), values.readers.end(), self_mask) != values.readers.end())
                return false;
            if (values.current_writer_task == get_loc().curr_task.get_id())
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
            size_t self_mask;
            if (get_loc().is_task_thread || get_loc().context_in_swap)
                self_mask = get_loc().curr_task.get_id();
            else
                self_mask = (size_t)_thread_id() | native_thread_flag;
            auto it = std::find(values.readers.begin(), values.readers.end(), self_mask);
            if (it == values.readers.end())
                throw std::logic_error("Tried unlock non owned mutex");
            values.readers.erase(it);

            while (values.begin && values.readers.empty()) {
                auto [item, native_cv, native_flag, n, p, awake_check, lock_read] = *values.begin;
                erase(values, values.begin);
                if (item == nullptr) {
                    if (native_cv != nullptr) {
                        *native_flag = true;
                        native_cv->notify_all();
                        break;
                    }
                    continue;
                }
                fast_task::lock_guard lg1(get_data(item));
                if (get_data(item).awake_check != awake_check)
                    continue;
                if (!get_data(item).get_time_end()) {
                    get_data(item).set_awaked(true);
                    bool make_break = false;
                    if (lock_read) {
                        if (*lock_read) {
                            values.readers.push_back(item.get_id());
                        } else {
                            values.current_writer_task = item.get_id();
                            make_break = true;
                        }
                    }
                    transfer_task(std::move(item));
                    if (make_break)
                        break;
                }
            }
        }
    }

    bool task_rw_mutex::is_read_locked() {
        size_t self_mask;
        if (get_loc().is_task_thread || get_loc().context_in_swap)
            self_mask = get_loc().curr_task.get_id();
        else
            self_mask = (size_t)_thread_id() | native_thread_flag;
        auto it = std::find(values.readers.begin(), values.readers.end(), self_mask);
        return it != values.readers.end();
    }

    void task_rw_mutex::lifecycle_read_lock(task&& lock_task) {
        {
            fast_task::lock_guard guard(get_data(lock_task));
            if (get_data(lock_task).is_running() || get_data(lock_task).is_ended())
                throw std::runtime_error("Task is running or completed and cannot be registered");
            if (get_data(lock_task).is_scheduled() && (!get_data(lock_task).is_suspended() && get_data(lock_task).get_is_on_scheduler()))
                throw std::runtime_error("Task is already in the scheduler queue");
            if (!get_data(lock_task).vtable || !get_data(lock_task).vtable->on_start)
                throw std::logic_error("task_rw_mutex::lifecycle_read_lock requires the on_start callback to be set");
        }
        task::run([lock_task, this]() {
            fast_task::read_lock guard(*this);
            task::await_task(lock_task, true);
        });
    }

    void task_rw_mutex::write_lock() {
        resume_task node;
        if (get_loc().is_task_thread) {
            node.task = get_loc().curr_task;
            get_data(get_loc().curr_task).set_awaked(false);
            get_data(get_loc().curr_task).set_time_end(false);

            fast_task::lock_guard lg(values.no_race);
            if (values.current_writer_task == get_loc().curr_task.get_id())
                throw std::logic_error("Tried lock mutex twice");
            if (std::find(values.readers.begin(), values.readers.end(), get_loc().curr_task.get_id()) != values.readers.end())
                throw std::logic_error("Tried lock read and then write mode");
            while (values.current_writer_task) {
                node.awake_check = get_data(node.task).awake_check;
                push_back(values, &node);
                swapCtxRelock(values.no_race);
            }
            values.current_writer_task = get_loc().curr_task.get_id();
            while (!values.readers.empty()) {
                node.awake_check = get_data(node.task).awake_check;
                push_back(values, &node);
                swapCtxRelock(values.no_race);
            }
        } else {
            auto self_mask = (size_t)_thread_id() | native_thread_flag;
            fast_task::condition_variable_any cd;
            bool has_res = false;
            node.task = nullptr;
            node.awake_check = 0;
            node.native_cv = &cd;
            node.native_check = &has_res;
            fast_task::unique_lock ul(values.no_race);
            if (values.current_writer_task == self_mask)
                throw std::logic_error("Tried lock mutex twice");
            while (values.current_writer_task) {
                push_back(values, &node);
                while (!has_res) //-V654
                    cd.wait(ul);
            }
            values.current_writer_task = self_mask;
            has_res = false;
            while (!values.readers.empty()) {
                push_back(values, &node);
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
        else if (get_loc().is_task_thread || get_loc().context_in_swap)
            values.current_writer_task = get_loc().curr_task.get_id();
        else
            values.current_writer_task = (size_t)_thread_id() | native_thread_flag;
        return true;
    }

    bool task_rw_mutex::try_write_lock_until(std::chrono::high_resolution_clock::time_point time_point) {
        resume_task node;
        fast_task::unique_lock ul(values.no_race);

        if (get_loc().is_task_thread && !get_loc().context_in_swap) {
            node.task = get_loc().curr_task;
            get_data(get_loc().curr_task).set_awaked(false);
            get_data(get_loc().curr_task).set_time_end(false);
            while (values.current_writer_task) {
                fast_task::lock_guard guard(glob.task_timer_safety);
                makeTimeWait_unsafe(time_point);
                node.awake_check = get_data(node.task).awake_check;
                push_back(values, &node);
                swapCtxRelock(glob.task_timer_safety, values.no_race);
                auto awaked = get_data(get_loc().curr_task).get_awaked();
                resetTimeWait();
                if (!awaked) {
                    erase(values, &node);
                    return false;
                }
            }
            values.current_writer_task = get_loc().curr_task.get_id();

            while (!values.readers.empty()) {
                fast_task::lock_guard guard(glob.task_timer_safety);
                makeTimeWait_unsafe(time_point);
                node.awake_check = get_data(node.task).awake_check;
                push_back(values, &node);
                swapCtxRelock(glob.task_timer_safety, values.no_race);
                auto awaked = get_data(get_loc().curr_task).get_awaked();
                resetTimeWait();
                if (!awaked) {
                    values.current_writer_task = 0;
                    erase(values, &node);
                    return false;
                }
            }
            return true;
        } else {
            fast_task::condition_variable_any cd;
            bool has_res = false;
            node.task = nullptr;
            node.awake_check = 0;
            node.native_cv = &cd;
            node.native_check = &has_res;
            while (values.current_writer_task) {
                has_res = false;
                push_back(values, &node);
                while (!has_res) { //-V654
                    if (cd.wait_until(ul, time_point) == cv_status::timeout) {
                        erase(values, &node);
                        return false;
                    }
                }
            }
            if (!get_loc().context_in_swap)
                values.current_writer_task = (size_t)_thread_id() | native_thread_flag;
            else
                values.current_writer_task = get_loc().curr_task.get_id();

            while (!values.readers.empty()) {
                has_res = false;
                push_back(values, &node);
                while (!has_res) { //-V654
                    if (cd.wait_until(ul, time_point) == cv_status::timeout) {
                        erase(values, &node);
                        values.current_writer_task = 0;
                        return false;
                    }
                }
            }
            return true;
        }
    }

    void task_rw_mutex::write_unlock() {
        fast_task::unique_lock ul(values.no_race);
        size_t self_mask;
        if (get_loc().is_task_thread || get_loc().context_in_swap)
            self_mask = get_loc().curr_task.get_id();
        else
            self_mask = (size_t)_thread_id() | native_thread_flag;

        if (values.current_writer_task != self_mask)
            throw std::logic_error("Tried unlock non owned mutex");
        values.current_writer_task = 0;
        while (values.begin) {
            auto [it, native_cv, native_flag, n, p, awake_check, lock_read] = *values.begin;
            erase(values, values.begin);
            if (it == nullptr) {
                if (native_cv != nullptr) {
                    *native_flag = true;
                    native_cv->notify_all();
                }
                continue;
            }
            fast_task::lock_guard lg1(get_data(it));
            if (get_data(it).awake_check != awake_check)
                continue;
            if (!get_data(it).get_time_end()) {
                get_data(it).set_awaked(true);
                if (lock_read) {
                    if (*lock_read) {
                        values.readers.push_back(it.get_id());
                    } else
                        values.current_writer_task = it.get_id();
                }
                transfer_task(std::move(it));
            }
        }
    }

    bool task_rw_mutex::is_write_locked() {
        size_t self_mask;
        if (get_loc().is_task_thread || get_loc().context_in_swap)
            self_mask = get_loc().curr_task.get_id();
        else
            self_mask = (size_t)_thread_id() | native_thread_flag;
        return values.current_writer_task == self_mask;
    }

    void task_rw_mutex::lifecycle_write_lock(task&& lock_task) {
        {
            fast_task::lock_guard guard(get_data(lock_task));
            if (get_data(lock_task).is_running() || get_data(lock_task).is_ended())
                throw std::runtime_error("Task is running or completed and cannot be registered");
            if (get_data(lock_task).is_scheduled() && (!get_data(lock_task).is_suspended() && get_data(lock_task).get_is_on_scheduler()))
                throw std::runtime_error("Task is already in the scheduler queue");
            if (!get_data(lock_task).vtable || !get_data(lock_task).vtable->on_start)
                throw std::logic_error("task_rw_mutex::lifecycle_write_lock requires the on_start callback to be set");
        }
        task::run([lock_task, this]() {
            fast_task::write_lock guard(*this);
            task::await_task(lock_task, true);
        });
    }

    bool task_rw_mutex::is_own() {
        if (is_write_locked())
            return true;
        else
            return is_read_locked();
    }

    bool task_rw_mutex::enter_read_wait(const task& task, enter_state& state) {
        fast_task::lock_guard l(values.no_race);
        if (values.current_writer_task == 0) {
            values.readers.push_back(task.get_id());
            return true;
        } else if (std::find(values.readers.begin(), values.readers.end(), task.get_id()) != values.readers.end()) {
            values.readers.push_back(task.get_id());
            return true;
        } else {
            auto node = state.template use<resume_task>();
            node->task = task;
            node->awake_check = get_data(task).awake_check;
            node->lock_read = true;
            push_back(values, node);
            return false;
        }
    }

    bool task_rw_mutex::enter_read_wait_until(const task& task, enter_state& state, std::chrono::high_resolution_clock::time_point time_point) {
        fast_task::lock_guard l(values.no_race);
        if (values.current_writer_task == 0) {
            values.readers.push_back(task.get_id());
            return true;
        } else if (std::find(values.readers.begin(), values.readers.end(), task.get_id()) != values.readers.end()) {
            values.readers.push_back(task.get_id());
            return true;
        } else {
            auto node = state.template use<resume_task>();
            node->task = task;
            node->awake_check = get_data(task).awake_check;
            node->lock_read = true;
            get_data(task).set_awaked(false);
            get_data(task).set_time_end(false);
            push_back(values, node);
            fast_task::makeTimeWait_extern(task, time_point);
            return false;
        }
    }

    bool task_rw_mutex::enter_write_wait(const task& task, enter_state& state) {
        fast_task::lock_guard l(values.no_race);
        if (values.current_writer_task == 0 && values.readers.empty()) {
            values.current_writer_task = task.get_id();
            return true;
        } else {
            auto node = state.template use<resume_task>();
            node->task = task;
            node->awake_check = get_data(task).awake_check;
            node->lock_read = false;
            push_back(values, node);
            return false;
        }
    }

    bool task_rw_mutex::enter_write_wait_until(const task& task, enter_state& state, std::chrono::high_resolution_clock::time_point time_point) {
        fast_task::lock_guard l(values.no_race);
        if (values.current_writer_task == 0 && values.readers.empty()) {
            values.current_writer_task = task.get_id();
            return true;
        } else {
            auto node = state.template use<resume_task>();
            node->task = task;
            node->awake_check = get_data(task).awake_check;
            node->lock_read = false;
            get_data(task).set_awaked(false);
            get_data(task).set_time_end(false);
            push_back(values, node);
            fast_task::makeTimeWait_extern(task, time_point);
            return false;
        }
    }
}
