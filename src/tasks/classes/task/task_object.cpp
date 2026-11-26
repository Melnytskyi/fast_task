// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <tasks/_internal.hpp>
#include <tasks/classes/misc/mutex_unify_internal.hpp>

#if defined(__x86_64__) || defined(__i386__) || defined(_M_IX86) || defined(_M_X64)
    #define __IS_X86_OR_X64
#endif

namespace fast_task {
    static_assert(sizeof(task_object::sbo_buffer) == task::sbo_size, "task::sbo_size must match task_object::sbo_buffer");

    bool task_object::get_time_end() const noexcept {
        return (state.load(std::memory_order_acquire) & (state_f::time_end)) != 0;
    }

    bool task_object::get_awaked() const noexcept {
        return (state.load(std::memory_order_acquire) & (state_f::awaked)) != 0;
    }

    bool task_object::get_pool_assigned() const noexcept {
        return (state.load(std::memory_order_relaxed) & (state_f::pool_assigned)) != 0;
    }

    bool task_object::get_is_restartable() const noexcept {
        return (state.load(std::memory_order_relaxed) & (state_f::is_restartable)) != 0;
    }

    bool task_object::get_is_on_scheduler() const noexcept {
        return (state.load(std::memory_order_relaxed) & (state_f::is_on_scheduler)) != 0;
    }

    bool task_object::get_is_sbo() const noexcept {
        return (state.load(std::memory_order_relaxed) & (state_f::is_sbo)) != 0;
    }

    bool task_object::get_cancellation_requested() const noexcept {
        return (state.load(std::memory_order_acquire) & (state_f::cancellation_requested)) != 0;
    }

    bool task_object::get_invalid_switch_caught() const noexcept {
        return (state.load(std::memory_order_relaxed) & (state_f::invalid_switch_caught)) != 0;
    }

    bool task_object::get_completed() const noexcept {
        return (state.load(std::memory_order_acquire) & (state_f::completed)) != 0;
    }

    bool task_object::get_resume_requested() const noexcept {
        return (state.load(std::memory_order_acquire) & (state_f::resume_requested)) != 0;
    }

    template <fast_task::task_object::state_f::f flag>
    void set_flag(std::atomic<uint16_t>& state, bool on) noexcept {
        if (on)
            state.fetch_or(static_cast<uint16_t>(flag), std::memory_order_acq_rel);
        else
            state.fetch_and(static_cast<uint16_t>(~static_cast<uint16_t>(flag)), std::memory_order_acq_rel);
    }

    void task_object::set_time_end(bool on) noexcept {
        set_flag<state_f::time_end>(state, on);
    }

    void task_object::set_awaked(bool on) noexcept {
        set_flag<state_f::awaked>(state, on);
    }

    void task_object::reset_wait_flags() noexcept {
        state.fetch_and(
            static_cast<uint16_t>(~(static_cast<uint16_t>(state_f::time_end) | static_cast<uint16_t>(state_f::awaked))),
            std::memory_order_acq_rel
        );
    }

    void task_object::set_pool_assigned(bool on) noexcept {
        set_flag<state_f::pool_assigned>(state, on);
    }

    void task_object::set_is_restartable(bool on) noexcept {
        set_flag<state_f::is_restartable>(state, on);
    }

    void task_object::set_is_on_scheduler(bool on) noexcept {
        set_flag<state_f::is_on_scheduler>(state, on);
    }

    void task_object::set_is_sbo(bool on) noexcept {
        set_flag<state_f::is_sbo>(state, on);
    }

    void task_object::set_cancellation_requested(bool on) noexcept {
        set_flag<state_f::cancellation_requested>(state, on);
    }

    void task_object::set_invalid_switch_caught(bool on) noexcept {
        set_flag<state_f::invalid_switch_caught>(state, on);
    }

    void task_object::set_completed(bool on) noexcept {
        set_flag<state_f::completed>(state, on);
    }

    void task_object::set_resume_requested(bool on) noexcept {
        set_flag<state_f::resume_requested>(state, on);
    }

    task_object::execution_mode task_object::get_execution_mode() const noexcept {
        return static_cast<task_object::execution_mode>(state.load(std::memory_order_relaxed) & 0x03);
    }

    task_priority task_object::get_priority() const noexcept {
        return priority;
    }

    void task_object::set_priority(task_priority p) noexcept {
        priority = p;
    }

    void task_object::lock() noexcept {
        interrupt_unsafe_region::lock();
        uint16_t cur = state.load(std::memory_order_relaxed);
        for (;;) {
            cur = static_cast<uint16_t>(cur & ~static_cast<uint16_t>(state_f::spin_lock_locked));
            if (state.compare_exchange_weak(cur, static_cast<uint16_t>(cur | state_f::spin_lock_locked), std::memory_order_acquire, std::memory_order_relaxed))
                return;
#if defined(PLATFORM_WINDOWS)
    #ifdef __IS_X86_OR_X64
            _mm_pause();
    #endif
#else
    #if (defined(__GNUC__) || defined(__clang__)) && defined(__IS_X86_OR_X64)
            __builtin_ia32_pause();
    #endif
#endif
        }
    }

    void task_object::unlock() noexcept {
        state.fetch_and(static_cast<uint16_t>(~static_cast<uint16_t>(state_f::spin_lock_locked)), std::memory_order_release);
        interrupt_unsafe_region::unlock();
    }

    void task_object::set_status(status_e s) noexcept {
        status.store(s, std::memory_order_release);
    }

    bool task_object::is_scheduled() const noexcept {
        return status.load(std::memory_order_acquire) != status_e::created;
    }

    bool task_object::is_created() const noexcept {
        return status.load(std::memory_order_acquire) == status_e::created;
    }

    bool task_object::is_running() const noexcept {
        return status.load(std::memory_order_acquire) == status_e::running;
    }

    bool task_object::is_suspending() const noexcept {
        return status.load(std::memory_order_acquire) == status_e::suspending;
    }

    bool task_object::is_suspended() const noexcept {
        return status.load(std::memory_order_acquire) == status_e::suspended;
    }

    bool task_object::is_ended() const noexcept {
        return status.load(std::memory_order_acquire) == status_e::ended;
    }

    bool task_object::is_released() const noexcept {
        return status.load(std::memory_order_acquire) == status_e::released;
    }

    void* task_object::user_data() const noexcept {
        if ((state.load(std::memory_order_acquire) & state_f::is_sbo) != 0)
            return const_cast<std::byte*>(sbo_buffer);
        return *reinterpret_cast<void* const*>(sbo_buffer);
    }

    void task_object::end_of_life_notify() {
        lock();
        status.store(task_object::status_e::ended, std::memory_order_release);
        futex::wake_on_address(this, SIZE_MAX);
        unlock();
    }

    void task_object::wait() {
        futex::wait_on_address(
            this,
            [](void* self) {
                return reinterpret_cast<task_object*>(self)->is_ended();
            }
        );
    }

    void task_object::wait_until(fast_task::time_point time_point) {
        futex::wait_on_address_until(
            this,
            [](void* self) {
                return reinterpret_cast<task_object*>(self)->is_ended();
            },
            time_point
        );
    }

    void task_object::cancel() {
        set_cancellation_requested(true);
    }

    bool task_object::enter_wait(const task& waiter, enter_state& st) {
        return futex::enter_wait_on_address(
            waiter,
            this,
            [](void* self) {
                return reinterpret_cast<task_object*>(self)->is_ended();
            },
            st
        );
    }

    bool task_object::enter_wait_until(const task& waiter, enter_state& st, fast_task::time_point time_point) {
        return futex::enter_wait_on_address_until(
            waiter,
            this,
            [](void* self) {
                return reinterpret_cast<task_object*>(self)->is_ended();
            },
            st,
            time_point
        );
    }

    bool task_object::enter_cancel(const task& waiter, enter_state& st) {
        cancel();
        return enter_wait(waiter, st);
    }

    mutex_unify task_object::get_relock() noexcept {
        auto res = mutex_unify_relock_access::from_raw(relock, relock_type);
        if ((state.load(std::memory_order_relaxed) & (state_f::relock_action_as_unlock)) != 0)
            set_relock(mutex_unify{});
        return res;
    }

    void task_object::set_relock(mutex_unify mut) noexcept {
        relock = mutex_unify_relock_access::raw_ptr(mut);
        relock_type = mutex_unify_relock_access::raw_type(mut);
        set_flag<state_f::relock_action_as_unlock>(state, false);
    }

    void task_object::set_unlock(mutex_unify mut) noexcept {
        relock = mutex_unify_relock_access::raw_ptr(mut);
        relock_type = mutex_unify_relock_access::raw_type(mut);
        set_flag<state_f::relock_action_as_unlock>(state, true);
    }

    mutex_unify task_object::get_self_unify() noexcept {
        return mutex_unify_relock_access::from_task_object(*this);
    }

    task_object* task_object::alloc() {
        auto obj = static_cast<task_object*>(get_alloc_loc().task_cache.allocate());

        obj->tls_data.store(nullptr, std::memory_order_relaxed);
        obj->exdata.store(nullptr, std::memory_order_relaxed);
        obj->vtable = nullptr;
        obj->relock = nullptr;
        obj->relock_type = 0;
        obj->status.store(status_e::created, std::memory_order_relaxed);
        obj->state.store(0, std::memory_order_relaxed);
        obj->pool_index = global_pool_index;
        obj->priority = task_priority::high;
        obj->awake_check = 0;
        obj->tls_capacity = 0;
        obj->link_counter.store(1, std::memory_order_relaxed);
        obj->on_start_override = nullptr;
        FT_DEBUG_ONLY(register_object(obj));
        return obj;
    }

    task_object* task_object::use(task_object* obj) noexcept {
        if (obj) {
            uint32_t old_counter = obj->link_counter.fetch_add(1, std::memory_order_relaxed);
            if (old_counter == 0) {
                obj->link_counter.fetch_sub(1, std::memory_order_relaxed);
                return nullptr;
            }
        }
        return obj;
    }

    void task_object::free(task_object* obj) {
        if (!obj)
            return;
        if (obj->link_counter.fetch_sub(1, std::memory_order_acq_rel) == 1) {
            const bool started = obj->is_scheduled();
            const bool ended = obj->is_ended();

            if (obj->on_start_override)
                obj->on_start_override->on_destruct(obj->on_start_override);

            if (obj->vtable && obj->vtable->on_destruct)
                obj->vtable->on_destruct(obj->user_data());

            if (auto* ex = obj->exdata.load(std::memory_order_acquire)) {
                release_execution_data(ex);
                obj->exdata.store(nullptr, std::memory_order_relaxed);
            }

            if (!ended && started)
                task_mark_completed(*obj);

#ifdef FT_ENABLE_ABORT_IF_NEVER_STARTED
            if (!started && !ended) {
                assert(false && "The task should always be started.");
                std::abort();
            }
#endif
            if (obj->vtable && obj->vtable->heap_allocated)
                delete const_cast<task_vtable*>(obj->vtable);

            obj->status.store(task_object::status_e::released, std::memory_order_relaxed);
            get_alloc_loc().task_cache.deallocate(obj);
            FT_DEBUG_ONLY(unregister_object(obj));
        }
    }

    size_t task_object::get_id() const noexcept {
        return reinterpret_cast<size_t>(this) & ~native_thread_flag;
    }
}
