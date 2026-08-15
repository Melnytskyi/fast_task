// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <experimental/futex.hpp>
#include <task.hpp>
#include <tasks/_internal.hpp>

namespace fast_task {
    constexpr uint8_t HAS_WAITERS = 0xFF;
    constexpr uint8_t NO_WAITERS = 0x00;

    condition_variable::condition_variable() : address(NO_WAITERS) {
        FT_DEBUG_ONLY(register_object(this));
    }

    condition_variable::~condition_variable() {
        FT_DEBUG_ONLY(unregister_object(this));
        if (address.load(std::memory_order_relaxed)) {
            if (futex::has_waiters(&address)) {
                assert(false && "Condition_variable destroyed while waited");
                std::terminate();
            }
        }
    }

    void condition_variable::wait(fast_task::unique_lock<mutex>& guard) {
        auto* mut = guard.release();
        futex::unlock_and_wait(
            &address,
            [](void* address) { reinterpret_cast<std::atomic_uint8_t*>(address)->store(HAS_WAITERS, std::memory_order_release); return false; },
            mut,
            [](void* mut_) { reinterpret_cast<fast_task::mutex*>(mut_)->unlock(); },
            [](void* mut_, bool mark_request) {
                if (mark_request) {
                    reinterpret_cast<fast_task::mutex*>(mut_)->mark_has_wait();
                    return true;
                } else
                    return !reinterpret_cast<fast_task::mutex*>(mut_)->is_locked();
            }
        );
        guard = fast_task::unique_lock<mutex>{*mut}; //locks
    }

    bool condition_variable::wait_until(fast_task::unique_lock<mutex>& guard, std::chrono::high_resolution_clock::time_point time_point) {
        auto* mut = guard.release();
        auto res = futex::unlock_and_wait_until(
            &address,
            [](void* address) { reinterpret_cast<std::atomic_uint8_t*>(address)->store(HAS_WAITERS, std::memory_order_release); return false; },
            mut,
            [](void* mut_) { reinterpret_cast<fast_task::mutex*>(mut_)->unlock(); },
            [](void* mut_, bool mark_request) {
                if (mark_request) {
                    reinterpret_cast<fast_task::mutex*>(mut_)->mark_has_wait();
                    return true;
                } else
                    return !reinterpret_cast<fast_task::mutex*>(mut_)->is_locked();
            },
            time_point
        );
        guard = fast_task::unique_lock<mutex>{*mut}; //locks
        return res;
    }

    void condition_variable::wait(std::unique_lock<mutex>& guard) {
        auto* mut = guard.release();
        futex::unlock_and_wait(
            &address,
            [](void* address) { reinterpret_cast<std::atomic_uint8_t*>(address)->store(HAS_WAITERS, std::memory_order_release); return false; },
            mut,
            [](void* mut_) { reinterpret_cast<fast_task::mutex*>(mut_)->unlock(); },
            [](void* mut_, bool mark_request) {
                if (mark_request) {
                    reinterpret_cast<fast_task::mutex*>(mut_)->mark_has_wait();
                    return true;
                } else
                    return !reinterpret_cast<fast_task::mutex*>(mut_)->is_locked();
            }
        );
        guard = std::unique_lock<mutex>{*mut}; //locks
    }

    bool condition_variable::wait_until(std::unique_lock<mutex>& guard, std::chrono::high_resolution_clock::time_point time_point) {
        auto* mut = guard.release();
        auto res = futex::unlock_and_wait_until(
            &address,
            [](void* address) { reinterpret_cast<std::atomic_uint8_t*>(address)->store(HAS_WAITERS, std::memory_order_release); return false; },
            mut,
            [](void* mut_) { reinterpret_cast<fast_task::mutex*>(mut_)->unlock(); },
            [](void* mut_, bool mark_request) {
                if (mark_request) {
                    reinterpret_cast<fast_task::mutex*>(mut_)->mark_has_wait();
                    return true;
                } else
                    return !reinterpret_cast<fast_task::mutex*>(mut_)->is_locked();
            },
            time_point
        );
        guard = std::unique_lock<mutex>{*mut}; //locks
        return res;
    }

    void condition_variable::notify_all() {
        if (address.load(std::memory_order_acquire) == HAS_WAITERS)
            futex::wake_and_requeue_on_address(&address, [](void* address, size_t to_process) {
                if (to_process == 0)
                    reinterpret_cast<std::atomic_uint8_t*>(address)->store(NO_WAITERS, std::memory_order_release);
            });
    }

    void condition_variable::notify_one() {
        if (address.load(std::memory_order_acquire) == HAS_WAITERS)
            futex::wake_on_address(&address, [](void* address, size_t to_process) {
                if (to_process == 0)
                    reinterpret_cast<std::atomic_uint8_t*>(address)->store(NO_WAITERS, std::memory_order_release);
            });
    }

    bool condition_variable::has_waiters() {
        if (address.load(std::memory_order_relaxed))
            return futex::has_waiters_callback(
                &address,
                [](void* address, void*, bool result) {
                    if (result == false)
                        reinterpret_cast<std::atomic_uint8_t*>(address)->store(NO_WAITERS, std::memory_order_release);
                },
                nullptr
            );
        return false;
    }

    void condition_variable::callback([[maybe_unused]] fast_task::unique_lock<mutex>&, const task& task) {
        {
            fast_task::lock_guard guard(get_data(task));
            if (get_data(task).is_running() || get_data(task).is_ended())
                throw std::runtime_error("Task is running or completed and cannot be registered");
            if (get_data(task).is_scheduled() && (!get_data(task).is_suspended() && get_data(task).get_is_on_scheduler()))
                throw std::runtime_error("Task is already in the scheduler queue");
            if (!get_data(task).vtable || !get_data(task).vtable->on_start)
                throw std::logic_error("condition_variable::callback requires the on_start callback to be set");
            if (get_data(task).on_start_override)
                throw std::logic_error("queue::add requires the on_start_override variable to be unset");
        }

        struct redefine_start_callback : public to_start_override {
            enter_state state;

            redefine_start_callback() {}

            virtual void callback(task_object* cb) {
                cb->on_start_override = nullptr;
                cb->vtable->on_start(cb->user_data());
            }

            virtual void on_destruct(to_start_override* self) {
                delete self;
            }

            virtual ~redefine_start_callback() = default;
        };

        auto res = new redefine_start_callback();
        get_data(task).on_start_override = res;
        if (get_data(task).is_created())
            ++glob.executing_tasks;

        get_data(task).set_status(task_object::status_e::scheduled);
        futex::enter_wait_on_address(
            task,
            &address,
            [](void* address) { reinterpret_cast<std::atomic_uint8_t*>(address)->store(HAS_WAITERS, std::memory_order_release); return false; },
            res->state
        );
    }

    void condition_variable::callback([[maybe_unused]] std::unique_lock<mutex>&, const task& task) {
        {
            fast_task::lock_guard guard(get_data(task));
            if (get_data(task).is_running() || get_data(task).is_ended())
                throw std::runtime_error("Task is running or completed and cannot be registered");
            if (get_data(task).is_scheduled() && (!get_data(task).is_suspended() && get_data(task).get_is_on_scheduler()))
                throw std::runtime_error("Task is already in the scheduler queue");
            if (!get_data(task).vtable || !get_data(task).vtable->on_start)
                throw std::logic_error("condition_variable::callback requires the on_start callback to be set");
            if (get_data(task).on_start_override)
                throw std::logic_error("queue::add requires the on_start_override variable to be unset");
        }

        struct redefine_start_callback : public to_start_override {
            enter_state state;

            redefine_start_callback() {}

            virtual void callback(task_object* cb) {
                cb->on_start_override = nullptr;
                cb->vtable->on_start(cb->user_data());
            }

            virtual void on_destruct(to_start_override* self) {
                delete self;
            }

            virtual ~redefine_start_callback() = default;
        };

        auto res = new redefine_start_callback();
        get_data(task).on_start_override = res;
        if (get_data(task).is_created())
            ++glob.executing_tasks;

        get_data(task).set_status(task_object::status_e::scheduled);
        futex::enter_wait_on_address(
            task,
            &address,
            [](void* address) { reinterpret_cast<std::atomic_uint8_t*>(address)->store(HAS_WAITERS, std::memory_order_release); return false; },
            res->state
        );
    }

    bool condition_variable::enter_wait(mutex& mut, const task& task, enter_state& st) {
        get_data(task).set_relock(mut);
        futex::enter_unlock_and_wait(
            task,
            &address,
            [](void* address) { reinterpret_cast<std::atomic_uint8_t*>(address)->store(HAS_WAITERS, std::memory_order_release); return false; },
            &mut,
            [](void*) {},
            [](void* mut_, bool mark_request) {
                if (mark_request) {
                    reinterpret_cast<fast_task::mutex*>(mut_)->mark_has_wait();
                    return true;
                } else
                    return !reinterpret_cast<fast_task::mutex*>(mut_)->is_locked();
            },
            st
        );
        return false;
    }

    bool condition_variable::enter_wait_until(mutex& mut, const task& task, enter_state& st, std::chrono::high_resolution_clock::time_point time_point) {
        if (std::chrono::high_resolution_clock::now() >= time_point)
            return true;
        auto res = futex::enter_unlock_and_wait_until(
            task,
            &address,
            [](void* address) { reinterpret_cast<std::atomic_uint8_t*>(address)->store(HAS_WAITERS, std::memory_order_release); return false; },
            &mut,
            [](void*) {},
            [](void* mut_, bool mark_request) {
                if (mark_request) {
                    reinterpret_cast<fast_task::mutex*>(mut_)->mark_has_wait();
                    return true;
                } else
                    return !reinterpret_cast<fast_task::mutex*>(mut_)->is_locked();
            },
            st,
            time_point
        );
        if (!res)
            get_data(task).set_relock(mut);
        return res;
    }
}
