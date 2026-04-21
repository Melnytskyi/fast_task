// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <task.hpp>
#include <tasks/_internal.hpp>

namespace fast_task {
    bool task::enable_task_naming = false;

    task::data::callbacks_data::callbacks_data() : normal_mode() {}

    task::data::callbacks_data::callbacks_data(callbacks_data&& move) noexcept {
        if (move.is_extended_mode) {
            is_extended_mode = true;
            extended_mode.is_restartable = move.extended_mode.is_restartable;
            extended_mode.data = move.extended_mode.data;
            extended_mode.on_start = move.extended_mode.on_start;
            extended_mode.on_await = move.extended_mode.on_await;
            extended_mode.on_cancel = move.extended_mode.on_cancel;
            extended_mode.on_destruct = move.extended_mode.on_destruct;
            move.extended_mode.on_destruct = nullptr;
        } else {
            is_extended_mode = false;
            normal_mode.ex_handle = std::move(move.normal_mode.ex_handle);
            normal_mode.func = std::move(move.normal_mode.func);
        }
    }

    task::data::callbacks_data::~callbacks_data() {
        if (is_extended_mode) {
            if (extended_mode.on_destruct)
                extended_mode.on_destruct(extended_mode.data);
            extended_mode.data = nullptr;
            extended_mode.on_start = nullptr;
            extended_mode.on_await = nullptr;
            extended_mode.on_cancel = nullptr;
            extended_mode.on_destruct = nullptr;
        } else {
            normal_mode.ex_handle = nullptr;
            normal_mode.func = nullptr;
        }
    }

    task::task(void* data, void (*on_start)(void*), void (*on_await)(void*), void (*on_cancel)(void*), void (*on_destruct)(void*), bool is_restartable, bool is_on_scheduler)
        : data_{.timeout = std::chrono::high_resolution_clock::time_point::min().time_since_epoch().count()} {
        data_.is_on_scheduler = is_on_scheduler;
        data_.callbacks.is_extended_mode = true;
        data_.callbacks.extended_mode.is_restartable = is_restartable;
        data_.callbacks.extended_mode.data = data;
        data_.callbacks.extended_mode.on_start = on_start;
        data_.callbacks.extended_mode.on_await = on_await;
        data_.callbacks.extended_mode.on_cancel = on_cancel;
        data_.callbacks.extended_mode.on_destruct = on_destruct;
        FT_DEBUG_ONLY(register_object(this));
    }

    task::task(task&& mov) noexcept
        : data_{.callbacks = std::move(mov.data_.callbacks), .timeout = std::move(mov.data_.timeout)} {
        data_.time_end_flag = mov.data_.time_end_flag;
        data_.awaked = mov.data_.awaked;
        data_.started = mov.data_.started;
        data_.completed = mov.data_.completed;
        FT_DEBUG_ONLY(register_object(this));
    }

    task::task(std::move_only_function<void()>&& func, std::move_only_function<void(const std::exception_ptr&)>&& ex_handle, std::chrono::high_resolution_clock::time_point timeout, task_priority priority, bool is_on_scheduler) : data_{.timeout = timeout.time_since_epoch().count()} {
#ifdef FT_ENABLE_PREEMPTIVE_SCHEDULER
        data_.exdata = new execution_data();
        data_.exdata->priority = priority;
#endif
        data_.is_on_scheduler = is_on_scheduler;
        data_.callbacks.is_extended_mode = false;
        data_.callbacks.normal_mode.func = std::move(func);
        data_.callbacks.normal_mode.ex_handle = std::move(ex_handle);
        FT_DEBUG_ONLY(register_object(this));
    }

    void task::awaitEnd(fast_task::unique_lock<mutex_unify>& l) {
        while (!data_.end_of_life)
            data_.result_notify.wait(l);
    }

    task::~task() {
        FT_DEBUG_ONLY(unregister_object(this));
        if (data_.exdata) {
            delete data_.exdata;
            data_.exdata = nullptr;
        }
        if (!data_.completed && data_.started) {
            --glob.executing_tasks;
            glob.no_tasks_execute_notifier.notify_all();
        }
#ifdef FT_ENABLE_ABORT_IF_NEVER_STARTED
        if (!data_.started && !data_.end_of_life) {
            assert(false && "The task should always be started.");
            std::abort();
        }
#endif
    }

    void task::set_auto_bind_worker(bool enable) noexcept {
        data_.auto_bind_worker = enable;
        if (enable)
            data_.bind_to_worker_id = (uint16_t)-1;
    }

    void task::set_worker_id(uint16_t id) noexcept {
        data_.bind_to_worker_id = id;
        data_.auto_bind_worker = false;
    }

    void task::set_priority(task_priority p) noexcept {
#ifdef FT_ENABLE_PREEMPTIVE_SCHEDULER
        if (!data_.exdata)
            data_.exdata = new execution_data();
        data_.exdata->priority = p;
#endif
    }

    void task::set_timeout(std::chrono::high_resolution_clock::time_point timeout) noexcept {
        data_.timeout = timeout.time_since_epoch().count();
    }

    task_priority task::get_priority() const noexcept {
#ifdef FT_ENABLE_PREEMPTIVE_SCHEDULER
        return data_.exdata ? data_.exdata->priority : task_priority::high;
#else
        return task_priority::semi_realtime;
#endif
    }

    size_t task::get_counter_interrupt() const noexcept {
#ifdef FT_ENABLE_PREEMPTIVE_SCHEDULER
        return data_.data ? data_.data->interrupt_count : 0;
#else
        return 0;
#endif
    }

    size_t task::get_counter_context_switch() const noexcept {
        return data_.exdata ? data_.exdata->context_switch_count : 0;
    }

    std::chrono::high_resolution_clock::time_point task::get_timeout() const noexcept {
        return std::chrono::high_resolution_clock::time_point(std::chrono::high_resolution_clock::duration(data_.timeout));
    }

    bool task::has_wait_timed_out() const noexcept {
        return data_.time_end_flag;
    }

    bool task::is_cancellation_requested() const noexcept {
        return data_.make_cancel;
    }

    bool task::is_ended() const noexcept {
        return data_.end_of_life;
    }

    void task::await_task() {
        if (!scheduler::total_executors())
            scheduler::create_executor(1);

        if (data_.callbacks.is_extended_mode) {
            data_.callbacks.extended_mode.on_await(data_.callbacks.extended_mode.data);
            if (!data_.callbacks.extended_mode.on_start)
                return;
            if (!data_.started) //started could change after `on_await`, better to be safe than oops
                return;
        } else if (!data_.started)
            throw std::runtime_error("Task is not started");
        mutex_unify uni(data_.no_race);
        fast_task::unique_lock l(uni);
        awaitEnd(l);
    }

    void task::callback(const std::shared_ptr<task>& task) {
        mutex_unify unify(data_.no_race);
        fast_task::unique_lock lock(unify);
        if (data_.end_of_life)
            scheduler::start(task);
        else
            data_.result_notify.callback(lock, task);
    }

    void task::notify_cancel() {
        if (data_.callbacks.is_extended_mode)
            data_.callbacks.extended_mode.on_cancel(data_.callbacks.extended_mode.data);
        data_.make_cancel = true;
    }

    void task::await_notify_cancel() {
        if (data_.callbacks.is_extended_mode)
            data_.callbacks.extended_mode.on_cancel(data_.callbacks.extended_mode.data);

        mutex_unify uni(data_.no_race);
        fast_task::unique_lock l(uni);
        data_.make_cancel = true;
        awaitEnd(l);
    }

    std::shared_ptr<task> task::run(std::function<void()>&& func) {
        auto r = std::make_shared<task>(std::move(func));
        scheduler::start(r);
        return r;
    }

    std::shared_ptr<task> task::create(std::function<void()>&& func) {
        return std::make_shared<task>(std::move(func));
    }

    void task::await_task(const std::shared_ptr<task>& lgr_task, bool make_start) {
        if (!scheduler::total_executors())
            scheduler::create_executor(1);

        if (!lgr_task->data_.started && make_start)
            scheduler::start(lgr_task);
        if (lgr_task->data_.callbacks.is_extended_mode) {
            lgr_task->data_.callbacks.extended_mode.on_await(lgr_task->data_.callbacks.extended_mode.data);
            if (!lgr_task->data_.callbacks.extended_mode.on_start)
                return;
            if (!(make_start || lgr_task->data_.started))
                return;
        }

        mutex_unify uni(lgr_task->data_.no_race);
        fast_task::unique_lock l(uni);
        lgr_task->awaitEnd(l);
    }

    void task::await_multiple(std::list<std::shared_ptr<task>>& tasks, bool pre_started, bool release) {
        if (!pre_started) {
            for (auto& it : tasks)
                scheduler::start(it);
        }
        if (release) {
            for (auto& it : tasks) {
                await_task(it, false);
                it = nullptr;
            }
        } else
            for (auto& it : tasks)
                await_task(it, false);
    }

    void task::await_multiple(std::vector<std::shared_ptr<task>>& tasks, bool pre_started, bool release) {
        if (!pre_started) {
            for (auto& it : tasks)
                scheduler::start(it);
        }
        if (release) {
            for (auto& it : tasks) {
                await_task(it, false);
                it = nullptr;
            }
        } else
            for (auto& it : tasks)
                await_task(it, false);
    }

    void task::await_multiple(std::shared_ptr<task>* tasks, size_t len, bool pre_started, bool release) {
        if (!pre_started) {
            std::shared_ptr<task>* iter = tasks;
            size_t count = len;
            while (count--)
                scheduler::start(*iter++);
        }
        if (release) {
            while (len--) {
                await_task(*tasks, false);
                (*tasks++) = nullptr;
            }
        } else
            while (len--)
                await_task(*tasks, false);
    }

    std::shared_ptr<task> task::callback_dummy(void* dummy_data, void (*on_start)(void*), void (*on_await)(void*), void (*on_cancel)(void*), void (*on_destruct)(void*), bool is_restartable, bool is_on_scheduler) {
        return std::make_shared<task>(dummy_data, on_start, on_await, on_cancel, on_destruct, is_restartable, is_on_scheduler);
    }

    std::shared_ptr<task> task::callback_dummy(void* dummy_data, void (*on_await)(void*), void (*on_cancel)(void*), void (*on_destruct)(void*), bool is_restartable, bool is_on_scheduler) {
        return std::make_shared<task>(dummy_data, nullptr, on_await, on_cancel, on_destruct, is_restartable, is_on_scheduler);
    }
}