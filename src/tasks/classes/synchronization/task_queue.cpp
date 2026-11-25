// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <algorithm>
#include <list>

#include <fast_task/internal/futex.hpp>
#include <fast_task/task.hpp>
#include <tasks/_internal.hpp>

namespace fast_task {
    struct queue_handle {
        std::list<task> tasks;
        condition_variable end_of_queue;
        fast_task::mutex no_race;
        std::atomic_uint8_t wait_futex{0};
        queue* tq = nullptr;
        size_t now_at_execution = 0;
        size_t at_execution_max = 0;
        bool destructed = false;
        bool is_running = false;
    };

    void __TaskQueue_add_task_leave(queue_handle* tqh);

    namespace {
        class redefine_start_queue : public to_start_override {
        public:
            queue_handle* tqh;
            bool started = false;

            redefine_start_queue(queue_handle* tqh) : tqh(tqh) {}

            virtual void callback(task_object* cb) override {
                auto* handle = tqh;
                tqh = nullptr;
                cb->on_start_override = nullptr;
                auto* on_start = cb->vtable->on_start;
                void* user_data = cb->user_data();
                delete this;
                try {
                    on_start(user_data);
                } catch (...) {
                    if (handle)
                        __TaskQueue_add_task_leave(handle);
                    throw;
                }
                if (handle)
                    __TaskQueue_add_task_leave(handle);
            }

            virtual void on_destruct(to_start_override* self) override {
                auto* me = static_cast<redefine_start_queue*>(self);
                auto* handle = me->tqh;
                bool was_started = me->started;
                me->tqh = nullptr;
                delete me;
                if (handle && was_started)
                    __TaskQueue_add_task_leave(handle);
            }

            virtual ~redefine_start_queue() = default;
        };

        bool queue_wait_check_callback(void* addr) {
            return reinterpret_cast<std::atomic_uint8_t*>(addr)->load(std::memory_order_acquire) == 0;
        }
    }

    queue::queue(size_t at_execution_max) {
        FT_DEBUG_ONLY(register_object(this));
        handle = new queue_handle{.tasks{}, .end_of_queue{}, .no_race{}, .wait_futex{0}, .tq = this, .at_execution_max = at_execution_max};
    }

    void __TaskQueue_add_task_leave(queue_handle* tqh) {
        fast_task::lock_guard lock(tqh->no_race);
        tqh->now_at_execution--;

        if (!tqh->destructed && tqh->is_running && !tqh->tasks.empty()) {
            while (tqh->now_at_execution < tqh->at_execution_max && !tqh->tasks.empty()) {
                auto awake_task = std::move(tqh->tasks.front());
                tqh->tasks.pop_front();
                if (auto* ov = static_cast<redefine_start_queue*>(get_data(awake_task).on_start_override))
                    ov->started = true;
                tqh->now_at_execution++;
                scheduler::start(std::move(awake_task));
            }
        }

        if (tqh->now_at_execution == 0 && (tqh->tasks.empty() || tqh->destructed)) {
            tqh->wait_futex.store(0, std::memory_order_release);
            tqh->end_of_queue.notify_all();
            futex::wake_on_address(&tqh->wait_futex, SIZE_MAX);
        }
    }

    redefine_start_queue* redefine_start_function(task& task, queue_handle* tqh) {
        if (!get_data(task).vtable || !get_data(task).vtable->on_start)
            throw std::logic_error("queue::add requires the on_start variable to be set");
        else if (get_data(task).on_start_override)
            throw std::logic_error("queue::add requires the on_start_override variable to be unset");
        else {
            auto* ov = new redefine_start_queue(tqh);
            get_data(task).on_start_override = ov;
            return ov;
        }
    }

    void queue::add(task&& queueing_task) {
        {
            fast_task::lock_guard guard(get_data(queueing_task));
            if (get_data(queueing_task).is_running() || get_data(queueing_task).is_ended())
                throw std::runtime_error("Task is running or completed and cannot be added");
            if (get_data(queueing_task).is_scheduled() && (!get_data(queueing_task).is_suspended() && get_data(queueing_task).get_is_on_scheduler()))
                throw std::runtime_error("Task is already in the scheduler queue");
            if (!get_data(queueing_task).vtable || !get_data(queueing_task).vtable->on_start)
                throw std::logic_error("queue::add requires the on_start callback to be set");
        }

        auto* ov = redefine_start_function(queueing_task, handle);
        fast_task::lock_guard lock(handle->no_race);
        handle->wait_futex.store(1, std::memory_order_release);

        if (handle->is_running && handle->now_at_execution < handle->at_execution_max) {
            ov->started = true;
            handle->now_at_execution++;
            scheduler::start(std::move(queueing_task));
        } else {
            handle->tasks.push_back(std::move(queueing_task));
        }
    }

    void queue::add(task& queueing_task) {
        {
            fast_task::lock_guard guard(get_data(queueing_task));
            if (get_data(queueing_task).is_running() || get_data(queueing_task).is_ended())
                throw std::runtime_error("Task is running or completed and cannot be added");
            if (get_data(queueing_task).is_scheduled() && (!get_data(queueing_task).is_suspended() && get_data(queueing_task).get_is_on_scheduler()))
                throw std::runtime_error("Task is already in the scheduler queue");
            if (!get_data(queueing_task).vtable || !get_data(queueing_task).vtable->on_start)
                throw std::logic_error("queue::add requires the on_start callback to be set");
        }

        auto* ov = redefine_start_function(queueing_task, handle);
        fast_task::lock_guard lock(handle->no_race);
        handle->wait_futex.store(1, std::memory_order_release);

        if (handle->is_running && handle->now_at_execution < handle->at_execution_max) {
            ov->started = true;
            handle->now_at_execution++;
            scheduler::start(queueing_task);
        } else {
            handle->tasks.push_back(queueing_task);
        }
    }

    void queue::enable() {
        fast_task::lock_guard lock(handle->no_race);
        handle->is_running = true;
        while (handle->now_at_execution < handle->at_execution_max && !handle->tasks.empty()) {
            auto awake_task = std::move(handle->tasks.front());
            handle->tasks.pop_front();
            if (auto* ov = static_cast<redefine_start_queue*>(get_data(awake_task).on_start_override))
                ov->started = true;
            handle->now_at_execution++;
            scheduler::start(std::move(awake_task));
        }
    }

    void queue::disable() {
        fast_task::lock_guard lock(handle->no_race);
        handle->is_running = false;
    }

    bool queue::in_queue(const task& task) {
        {
            fast_task::lock_guard guard(get_data(task));
            if (get_data(task).is_running() || get_data(task).is_ended())
                return false;
            if (get_data(task).is_scheduled() && (!get_data(task).is_suspended() && get_data(task).get_is_on_scheduler()))
                return false;
        }
        fast_task::lock_guard lock(handle->no_race);
        return std::find(handle->tasks.begin(), handle->tasks.end(), task) != handle->tasks.end();
    }

    void queue::set_max_at_execution(size_t val) {
        fast_task::lock_guard lock(handle->no_race);
        handle->at_execution_max = val;
    }

    size_t queue::get_max_at_execution() {
        fast_task::lock_guard lock(handle->no_race);
        return handle->at_execution_max;
    }

    void queue::wait() {
        fast_task::unique_lock lock(handle->no_race);
        while (handle->now_at_execution != 0 || !handle->tasks.empty())
            handle->end_of_queue.wait(lock);
    }

    bool queue::wait_until(fast_task::time_point time_point) {
        fast_task::unique_lock lock(handle->no_race);
        while (handle->now_at_execution != 0 || !handle->tasks.empty()) {
            if (!handle->end_of_queue.wait_until(lock, time_point))
                return false;
        }
        return true;
    }

    queue::~queue() {
        FT_DEBUG_ONLY(unregister_object(this));
        if (handle) {
            std::list<task> unstarted;
            {
                fast_task::unique_lock lock(handle->no_race);
                handle->is_running = false;
                handle->destructed = true;
                unstarted.swap(handle->tasks);
                for (auto& t : unstarted) {
                    auto& td = get_data(t);
                    fast_task::lock_guard tguard(td);
                    if (td.on_start_override) {
                        auto* ov = static_cast<redefine_start_queue*>(td.on_start_override);
                        ov->tqh = nullptr;
                        td.on_start_override = nullptr;
                        delete ov;
                    }
                }
                while (handle->now_at_execution != 0)
                    handle->end_of_queue.wait(lock);
                handle->wait_futex.store(0, std::memory_order_release);
                handle->end_of_queue.notify_all();
                futex::wake_on_address(&handle->wait_futex, SIZE_MAX);
            }
            unstarted.clear();
            delete handle;
            handle = nullptr;
        }
    }

    bool queue::enter_wait(const task& task, enter_state& st) {
        {
            fast_task::lock_guard lock(handle->no_race);
            if (handle->now_at_execution == 0 && handle->tasks.empty())
                return true;
        }
        return futex::enter_wait_on_address(task, &handle->wait_futex, &queue_wait_check_callback, st);
    }

    bool queue::enter_wait_until(const task& task, enter_state& st, fast_task::time_point time_point) {
        get_data(task).set_time_end(false);
        {
            fast_task::lock_guard lock(handle->no_race);
            if (handle->now_at_execution == 0 && handle->tasks.empty())
                return true;
        }
        return futex::enter_wait_on_address_until(task, &handle->wait_futex, &queue_wait_check_callback, st, time_point);
    }
}
