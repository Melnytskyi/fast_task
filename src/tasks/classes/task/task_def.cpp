// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <task.hpp>
#include <tasks/_internal.hpp>

namespace fast_task {
    bool task::enable_task_naming = false;

    task::data::callbacks_data::callbacks_data() : buf{.dat{.data{nullptr}, .on_await{nullptr}, .on_cancel{nullptr}}} {}

    task::data::callbacks_data::callbacks_data(callbacks_data&& move) noexcept {
        is_sbo = move.is_sbo;
        on_move = move.on_move;
        if (on_move)
            on_move(get_data(), move.get_data());
        else {
            buf.dat.data = move.buf.dat.data;
            buf.dat.on_await = move.buf.dat.on_await;
            buf.dat.on_cancel = move.buf.dat.on_cancel;
        }
        on_start = move.on_start;
        on_destruct = move.on_destruct;
        move.on_destruct = nullptr;
    }

    task::data::callbacks_data::~callbacks_data() {
        if (on_destruct)
            on_destruct(get_data());
        buf.dat.data = nullptr;
        buf.dat.on_await = nullptr;
        buf.dat.on_cancel = nullptr;
        on_start = nullptr;
        on_destruct = nullptr;
        on_move = nullptr;
    }

    task::task(void* data, void (*on_start)(void*), void (*on_await)(void*), void (*on_cancel)(void*), void (*on_destruct)(void*), bool is_restartable, bool is_on_scheduler)
        : data_{
              .callbacks{},
              .result_notify{},
              .no_race{},
              .relock_0{},
              .relock_1{},
              .relock_2{},
              .timeout = std::chrono::high_resolution_clock::time_point::min().time_since_epoch().count()
          } {
        data_.is_on_scheduler = is_on_scheduler;
        data_.is_restartable = is_restartable;
        data_.callbacks.is_sbo = false;
        data_.callbacks.buf.dat.data = data;
        data_.callbacks.buf.dat.on_await = on_await;
        data_.callbacks.buf.dat.on_cancel = on_cancel;
        data_.callbacks.on_start = on_start;
        data_.callbacks.on_destruct = on_destruct;
        FT_DEBUG_ONLY(register_object(this));
    }

    task::task(task&& mov) noexcept
        : data_{
              .callbacks = std::move(mov.data_.callbacks),
              .result_notify{},
              .no_race{},
              .relock_0{},
              .relock_1{},
              .relock_2{},
              .timeout = std::move(mov.data_.timeout)
          } {
        if (mov.data_.started)
            assert(false && "Moving started tasks is not allowed");
        data_.time_end_flag = mov.data_.time_end_flag;
        data_.awaked = mov.data_.awaked;
        data_.started = mov.data_.started;
        data_.completed = mov.data_.completed;
        FT_DEBUG_ONLY(register_object(this));
    }

    void task::awaitEnd(fast_task::unique_lock<mutex_unify>& l) {
        while (!data_.end_of_life)
            data_.result_notify.wait(l);
    }

    bool task::awaitEnd(fast_task::unique_lock<mutex_unify>& l, std::chrono::high_resolution_clock::time_point time_point) {
        while (!data_.end_of_life)
            if (!data_.result_notify.wait_until(l, time_point))
                return false;
        return true;
    }

    task::~task() {
        FT_DEBUG_ONLY(unregister_object(this));
        if (data_.exdata) {
            delete data_.exdata;
            data_.exdata = nullptr;
        }
        if (!data_.completed && data_.started) {
            --glob.executing_tasks;
            fast_task::shared_lock guard(glob.task_thread_safety);
            glob.no_tasks_execute_notifier.notify_all_guarded();
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

    void task::set_priority([[maybe_unused]] task_priority p) noexcept {
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
        fast_task::lock_guard lock(data_.no_race);
        auto time_end_flag = data_.time_end_flag;
        resetTimeWait();
        return time_end_flag;
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

        if (!data_.started && data_.callbacks.on_start)
            scheduler::start(shared_from_this());
        data_.callbacks.make_await();
        if (!data_.callbacks.on_start)
            return;

        mutex_unify uni(data_.no_race);
        fast_task::unique_lock l(uni);
        if (!data_.started)
            return;
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
        data_.callbacks.make_cancel();
        fast_task::lock_guard l(data_.no_race);
        data_.make_cancel = true;

        if (data_.suspended && !data_.end_of_life && !data_.time_end_flag) {
            data_.time_end_flag = true;
            data_.awaked = true;
            fast_task::transfer_task(shared_from_this());
        }
    }

    void task::await_notify_cancel() {
        notify_cancel();

        mutex_unify uni(data_.no_race);
        fast_task::unique_lock l(uni);
        data_.make_cancel = true;
        awaitEnd(l);
    }

    void task::reset_awake() {
        data_.time_end_flag = false;
        data_.awaked = false;
    }

    bool task::enter_wait(const std::shared_ptr<task>& t) {
        struct enter_data {
            std::shared_ptr<task> wake;
            std::weak_ptr<task> bridge;
            std::shared_ptr<task> self;
        };

        mutex_unify unify(data_.no_race);
        fast_task::unique_lock lock(unify);
        if (!data_.started && data_.callbacks.on_start)
            scheduler::start(shared_from_this());
        if (data_.end_of_life)
            return true;

        auto ew_data = std::unique_ptr<enter_data>(new enter_data(t, {}, shared_from_this()));
        auto bridge = std::make_shared<task>(
            nullptr,
            [](void* ptr) {
                auto& data = *static_cast<enter_data*>(ptr);
                mutex_unify unify(data.self->data_.no_race);
                fast_task::unique_lock lock(unify, fast_task::adopt_lock);
                while (true) {
                    if (data.self->data_.end_of_life) {
                        if (!fast_task::this_task::transfer_to(data.wake))
                            fast_task::transfer_task(std::shared_ptr<fast_task::task>(data.wake));
                        this_task::the_coroutine_ended(data.bridge.lock());
                        break;
                    } else if (!data.self->data_.result_notify.enter_wait(unify, data.bridge.lock())) {
                        lock.release();
                        break;
                    }
                }
            },
            [](void*) {},
            [](void*) {},
            [](void* ptr) { if(ptr) delete static_cast<enter_data*>(ptr); },
            true,
            true
        );
        bridge->data_.started = true;
        ++glob.executing_tasks;

        ew_data->bridge = bridge;
        bridge->data_.callbacks.buf.dat.data = ew_data.release();
        return data_.result_notify.enter_wait(unify, bridge);
    }

    bool task::enter_wait_until(const std::shared_ptr<task>& t, std::chrono::high_resolution_clock::time_point time_point) {
        struct enter_data {
            std::shared_ptr<task> wake;
            std::weak_ptr<task> bridge;
            std::shared_ptr<task> self;
            std::chrono::high_resolution_clock::time_point time_point;
        };

        mutex_unify unify(data_.no_race);
        fast_task::unique_lock lock(unify);
        if (time_point <= std::chrono::high_resolution_clock::now()) {
            t->data_.time_end_flag = true;
            return true;
        }
        if (!data_.started && data_.callbacks.on_start)
            scheduler::start(shared_from_this());
        if (data_.end_of_life)
            return true;

        auto ew_data = std::unique_ptr<enter_data>(new enter_data(t, {}, shared_from_this(), time_point));
        auto bridge = std::make_shared<task>(
            nullptr,
            [](void* ptr) {
                auto& data = *static_cast<enter_data*>(ptr);
                auto bridge = data.bridge.lock();
                mutex_unify unify(data.self->data_.no_race);
                fast_task::unique_lock lock(unify, fast_task::adopt_lock);
                while (true) {
                    if (bridge->data_.time_end_flag) {
                        data.wake->data_.time_end_flag = true;
                        if (!fast_task::this_task::transfer_to(data.wake))
                            fast_task::transfer_task(std::shared_ptr<fast_task::task>(data.wake));
                        this_task::the_coroutine_ended(bridge);
                        break;
                    } else if (data.self->data_.end_of_life) {
                        if (!fast_task::this_task::transfer_to(data.wake))
                            fast_task::transfer_task(std::shared_ptr<fast_task::task>(data.wake));
                        this_task::the_coroutine_ended(bridge);
                        break;
                    } else {
                        bridge->data_.time_end_flag = false;
                        bridge->data_.awaked = false;
                        if (!data.self->data_.result_notify.enter_wait_until(unify, bridge, data.time_point)) {
                            lock.release();
                            break;
                        }
                    }
                }
            },
            [](void*) {},
            [](void*) {},
            [](void* ptr) { if(ptr) delete static_cast<enter_data*>(ptr); },
            true,
            true
        );
        bridge->data_.started = true;
        ++glob.executing_tasks;

        ew_data->bridge = bridge;
        bridge->data_.callbacks.buf.dat.data = ew_data.release();
        if (data_.result_notify.enter_wait_until(unify, bridge, time_point)) {
            t->data_.time_end_flag = true;
            return true;
        } else
            return false;
    }

    bool task::enter_cancel(const std::shared_ptr<task>& t) {
        notify_cancel();
        return enter_wait(t);
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
        lgr_task->data_.callbacks.make_await();
        if (!lgr_task->data_.callbacks.on_start)
            return;

        mutex_unify uni(lgr_task->data_.no_race);
        fast_task::unique_lock l(uni);
        if (!(make_start || lgr_task->data_.started || lgr_task->data_.is_restartable))
            return;
        lgr_task->awaitEnd(l);
    }

    bool task::await_task_until(std::chrono::high_resolution_clock::time_point time_point) {
        if (!scheduler::total_executors())
            scheduler::create_executor(1);

        data_.callbacks.make_await();
        if (!data_.callbacks.on_start)
            return true;

        mutex_unify uni(data_.no_race);
        fast_task::unique_lock l(uni);
        if (!data_.started && !data_.is_restartable)
            return true;
        return awaitEnd(l, time_point);
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