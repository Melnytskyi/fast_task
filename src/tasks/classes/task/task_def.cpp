// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <task.hpp>
#include <tasks/_internal.hpp>

namespace fast_task {
    bool task::enable_task_naming = false;

    void task::init_pointer(void* heap_state, task_vtable* vtable, bool is_restartable, bool is_on_scheduler) {
        obj = task_object::alloc();
        obj->vtable = vtable;
        obj->status.store(task_object::status_e::created, std::memory_order_relaxed);
        obj->bind_to_worker_id = (uint16_t)-1;
        obj->set_is_restartable(is_restartable);
        obj->set_is_on_scheduler(is_on_scheduler);
        obj->set_is_sbo(false);
        *reinterpret_cast<void**>(obj->sbo_buffer) = heap_state;
    }

    void* task::init_inplace(task_vtable* vtable, bool is_restartable, bool is_on_scheduler) {
        obj = task_object::alloc();
        obj->vtable = vtable;
        obj->status.store(task_object::status_e::created, std::memory_order_relaxed);
        obj->bind_to_worker_id = (uint16_t)-1;
        obj->set_is_restartable(is_restartable);
        obj->set_is_on_scheduler(is_on_scheduler);
        obj->set_is_sbo(true);
        return obj->sbo_buffer;
    }

    void* task::user_data() const noexcept {
        return obj ? obj->user_data() : nullptr;
    }

    void task::end_of_life_notify() const {
        if (obj)
            obj->end_of_life_notify();
    }

    task::task(void* data, task_vtable* vtable, bool is_restartable, bool is_on_scheduler) {
        init_pointer(data, vtable, is_restartable, is_on_scheduler);
    }

    task::task() noexcept {
        obj = nullptr;
    }

    task::task(std::nullptr_t) noexcept {
        obj = nullptr;
    }

    task::task(task&& mov) noexcept
        : obj(mov.obj) {
        mov.obj = nullptr;
    }

    task::task(const task& copy) noexcept : obj(task_object::use(copy.obj)) {
    }

    task::~task() {
        if (obj)
            task_object::free(obj);
    }

    task& task::operator=(task&& mov) noexcept {
        if (this != &mov) {
            if (obj)
                task_object::free(obj);
            obj = mov.obj;
            mov.obj = nullptr;
        }
        return *this;
    }

    task& task::operator=(const task& copy) noexcept {
        if (this != &copy) {
            if (obj)
                task_object::free(obj);
            obj = task_object::use(copy.obj);
        }
        return *this;
    }

    void task::reset() noexcept {
        *this = task();
    }

    task_object* task::release() noexcept {
        task_object* temp = obj;
        obj = nullptr;
        return temp;
    }

    task task::adopt(task_object* raw) noexcept {
        task t(nullptr);
        t.obj = raw;
        return t;
    }

    void task::set_auto_bind_worker(bool enable) const noexcept {
        if (!obj)
            return;
        obj->set_auto_bind(enable);
        if (enable)
            obj->bind_to_worker_id = (uint16_t)-1;
    }

    void task::set_worker_id(uint16_t id) const noexcept {
        if (!obj)
            return;
        obj->bind_to_worker_id = id;
        obj->set_auto_bind(false);
    }

    void task::set_priority([[maybe_unused]] task_priority p) const noexcept {
        if (!obj)
            return;
#ifdef FT_ENABLE_PREEMPTIVE_SCHEDULER
        if (!get_data(*this).exdata && p == task_priority::semi_realtime)
            return;
        get_execution_data(*this).priority = p;
#endif
    }

    void task::set_timeout(std::chrono::high_resolution_clock::time_point timeout) const noexcept {
        if (!obj)
            return;
        if (!get_data(*this).exdata && timeout == std::chrono::high_resolution_clock::time_point::min())
            return;
        get_execution_data(*this).timeout = timeout.time_since_epoch().count();
    }

    task_priority task::get_priority() const noexcept {
        if (!obj)
            return task_priority::semi_realtime;
#ifdef FT_ENABLE_PREEMPTIVE_SCHEDULER
        auto* ex = obj->exdata.load(std::memory_order_acquire);
        return ex ? ex->priority : task_priority::semi_realtime;
#else
        return task_priority::semi_realtime;
#endif
    }

    size_t task::get_counter_interrupt() const noexcept {
        if (!obj)
            return 0;
#ifdef FT_ENABLE_PREEMPTIVE_SCHEDULER
        auto* ex = obj->exdata.load(std::memory_order_acquire);
        return ex ? ex->interrupt_count : 0;
#else
        return 0;
#endif
    }

    size_t task::get_counter_context_switch() const noexcept {
        if (!obj)
            return 0;
        auto* ex = obj->exdata.load(std::memory_order_acquire);
        return ex ? ex->context_switch_count : 0;
    }

    std::chrono::high_resolution_clock::time_point task::get_timeout() const noexcept {
        if (!obj)
            return std::chrono::high_resolution_clock::time_point::min();
        auto* ex = obj->exdata.load(std::memory_order_acquire);
        auto rep = ex ? ex->timeout : std::chrono::high_resolution_clock::time_point::min().time_since_epoch().count();
        return std::chrono::high_resolution_clock::time_point(std::chrono::high_resolution_clock::duration(rep));
    }

    bool task::has_wait_timed_out() const noexcept {
        if (!obj)
            return false;
        obj->lock();
        bool time_end_flag = obj->get_time_end();
        resetTimeWait();
        obj->unlock();
        return time_end_flag;
    }

    bool task::is_cancellation_requested() const noexcept {
        if (!obj)
            return false;
        return obj->get_cancellation_requested();
    }

    bool task::is_ended() const noexcept {
        if (!obj)
            return false;
        return obj->is_ended();
    }

    void task::await_task() const {
        if (!obj)
            return;
        if (!scheduler::total_executors())
            scheduler::create_executor(1);

        if (!obj->is_scheduled() && obj->vtable && obj->vtable->on_start)
            scheduler::start(*this);
        if (obj->vtable && obj->vtable->on_await)
            obj->vtable->on_await(obj->user_data());
        if (!obj->vtable || !obj->vtable->on_start)
            return;
        if (!obj->is_scheduled())
            return;
        obj->wait();
    }

    void task::callback(const task& cbtask) const {
        if (!obj)
            return;
        obj->lock();
        if (obj->is_ended()) {
            obj->unlock();
            scheduler::start(cbtask);
            return;
        }

        auto& cd = get_data(cbtask);
        {
            fast_task::lock_guard guard(cd);
            if (cd.is_running() || cd.is_ended()) {
                obj->unlock();
                throw std::runtime_error("Task is running or completed and cannot be registered");
            }
            if (cd.is_scheduled() && (!cd.is_suspended() && cd.get_is_on_scheduler())) {
                obj->unlock();
                throw std::runtime_error("Task is already in the scheduler queue");
            }
            if (!cd.vtable || !cd.vtable->on_start) {
                obj->unlock();
                throw std::logic_error("task::callback requires the on_start callback to be set");
            }
        }

        auto* node = new task_object::wait_item();
        node->waiter = cbtask;
        node->awake_check = cd.awake_check;
        node->heap_allocated = true;
        node->next = obj->on_wait.load(std::memory_order_relaxed);
        obj->on_wait.store(node, std::memory_order_relaxed);

        if (!cd.is_scheduled()) {
            ++glob.executing_tasks;
            cd.set_status(task_object::status_e::scheduled);
        }
        obj->unlock();
    }

    void task::notify_cancel() const {
        if (!obj)
            return;
        if (obj->vtable && obj->vtable->on_cancel)
            obj->vtable->on_cancel(obj->user_data());

        fast_task::lock_guard guard(*obj);
        obj->set_cancellation_requested(true);
        if (obj->is_suspended() && !obj->is_scheduled() && !obj->get_time_end()) {
            obj->set_time_end(true);
            obj->set_awaked(true);
            fast_task::transfer_task(task(*this));
        }
    }

    void task::await_notify_cancel() const {
        if (!obj)
            return;
        notify_cancel();
        obj->wait();
    }

    void task::reset_awake() const {
        if (!obj)
            return;
        obj->set_time_end(false);
        obj->set_awaked(false);
    }

    void task::start() const {
        if (!obj)
            return;
        if (!scheduler::total_executors())
            scheduler::create_executor(1);
        if (!obj->is_scheduled())
            scheduler::start(*this);
    }

    bool task::enter_wait(const task& waiter, enter_state& st) const {
        if (!obj)
            return true;
        if (!obj->is_scheduled() && obj->vtable && obj->vtable->on_start)
            scheduler::start(*this);
        return obj->enter_wait(waiter, st);
    }

    bool task::enter_wait_until(const task& waiter, enter_state& st, std::chrono::high_resolution_clock::time_point time_point) const {
        if (!obj)
            return true;
        if (!obj->is_scheduled() && obj->vtable && obj->vtable->on_start)
            scheduler::start(*this);
        return obj->enter_wait_until(waiter, st, time_point);
    }

    bool task::enter_cancel(const task& waiter, enter_state& st) const {
        if (!obj)
            return true;
        notify_cancel();
        return enter_wait(waiter, st);
    }

    void task::await_task(const task& lgr_task, bool make_start) {
        if (!scheduler::total_executors())
            scheduler::create_executor(1);

        auto& d = get_data(lgr_task);
        if (!d.is_scheduled() && make_start)
            scheduler::start(lgr_task);
        if (d.vtable && d.vtable->on_await)
            d.vtable->on_await(lgr_task.obj->user_data());
        if (!d.vtable || !d.vtable->on_start)
            return;
        if (!(make_start || d.is_scheduled() || d.get_is_restartable()))
            return;
        d.wait();
    }

    bool task::await_task_until(std::chrono::high_resolution_clock::time_point time_point) const {
        if (!obj)
            return true;
        if (!scheduler::total_executors())
            scheduler::create_executor(1);

        if (obj->vtable && obj->vtable->on_await)
            obj->vtable->on_await(obj->user_data());
        if (!obj->vtable || !obj->vtable->on_start)
            return true;
        if (!obj->is_scheduled() && !obj->get_is_restartable())
            return true;
        obj->wait_until(time_point);
        return obj->is_ended();
    }

    task task::callback_dummy(void* dummy_data, void (*on_start)(void*), void (*on_await)(void*), void (*on_cancel)(void*), void (*on_destruct)(void*), bool is_restartable, bool is_on_scheduler) {
        auto* vtable = new task_vtable{};
        vtable->on_await = on_await;
        vtable->on_cancel = on_cancel;
        vtable->on_start = on_start;
        vtable->on_destruct = on_destruct;
        vtable->heap_allocated = true;
        return task(dummy_data, vtable, is_restartable, is_on_scheduler);
    }

    task task::callback_dummy(void* dummy_data, void (*on_await)(void*), void (*on_cancel)(void*), void (*on_destruct)(void*), bool is_restartable, bool is_on_scheduler) {
        return callback_dummy(dummy_data, nullptr, on_await, on_cancel, on_destruct, is_restartable, is_on_scheduler);
    }

    size_t task::get_id() const noexcept {
        return reinterpret_cast<size_t>(obj) & ~native_thread_flag;
    }
}
