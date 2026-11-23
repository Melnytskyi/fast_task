// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <fast_task/internal/futex.hpp>
#include <fast_task/task.hpp>
#include <tasks/_internal.hpp>

namespace fast_task {
    bool rw_mutex::read_probe(void* state_address) noexcept {
        private_values& values = values_of(state_address);
        uint64_t state = values.state.load(std::memory_order_relaxed);
        if (reader_can_acquire(state))
            return true;
        state = values.state.fetch_or(private_values::HAS_READER_WAITERS, std::memory_order_acq_rel) |
                private_values::HAS_READER_WAITERS;
        return reader_can_acquire(state);
    }

    bool rw_mutex::write_probe(void* state_address) noexcept {
        private_values& values = values_of(state_address);
        uint64_t state = values.state.load(std::memory_order_relaxed);
        if (writer_can_acquire(state))
            return true;
        state = values.state.fetch_or(private_values::HAS_WRITER_WAITERS, std::memory_order_acq_rel) |
                private_values::HAS_WRITER_WAITERS;
        return writer_can_acquire(state);
    }

    size_t rw_mutex::wake_writers(private_values& values, size_t count) {
        return futex::wake_and_requeue_on_address_select(
            &values.state,
            [](void* address, size_t, bool has_remaining) {
                if (has_remaining)
                    return;
                values_of(address).state.fetch_and(~private_values::HAS_WRITER_WAITERS, std::memory_order_release);
            },
            [](void*, futex::node_data node, bool) { return node.data == private_values::WRITER_KEY; },
            count,
            count
        );
    }

    size_t rw_mutex::wake_readers(private_values& values) {
        return futex::wake_and_requeue_on_address_select(
            &values.state,
            [](void* address, size_t, bool has_remaining) {
                if (has_remaining)
                    return;
                values_of(address).state.fetch_and(~private_values::HAS_READER_WAITERS, std::memory_order_release);
            },
            [](void*, futex::node_data node, bool) { return node.data == private_values::READER_KEY; },
            SIZE_MAX,
            SIZE_MAX
        );
    }

    void rw_mutex::reader_left(private_values& values, uint64_t state) noexcept {
        if ((state & private_values::READER_COUNT_MASK) != private_values::READER_ONE)
            return;
        if ((state & private_values::HAS_WRITER_WAITERS) == 0)
            return;
        wake_writers(values, 1);
    }

    rw_mutex::rw_mutex() {
        FT_DEBUG_ONLY(register_object(this));
    }

    rw_mutex::~rw_mutex() {
        FT_DEBUG_ONLY(unregister_object(this));
        if ((values.state.load(std::memory_order_relaxed) & private_values::OWNERSHIP_MASK) != 0) {
            assert(false && "Mutex destroyed while locked");
            std::terminate();
        }
        if (futex::has_waiters(&values.state, futex::node_data{0})) {
            assert(false && "Mutex destroyed while waited");
            std::terminate();
        }
    }

    void rw_mutex::read_lock() {
        interrupt_unsafe_region region;

        while (true) {
            uint64_t previous = values.state.fetch_add(private_values::READER_ONE, std::memory_order_acq_rel);
            if ((previous & (private_values::WRITER_LOCKED | private_values::HAS_WRITER_WAITERS)) == 0)
                return;

            reader_left(values, values.state.fetch_sub(private_values::READER_ONE, std::memory_order_acq_rel));

            futex::wait_on_address(
                &values.state,
                &rw_mutex::read_probe,
                {private_values::READER_KEY}
            );
        }
    }

    bool rw_mutex::try_read_lock() {
        interrupt_unsafe_region region;
        uint64_t previous = values.state.fetch_add(private_values::READER_ONE, std::memory_order_acq_rel);
        if ((previous & (private_values::WRITER_LOCKED | private_values::HAS_WRITER_WAITERS)) == 0)
            return true;

        reader_left(values, values.state.fetch_sub(private_values::READER_ONE, std::memory_order_acq_rel));
        return false;
    }

    bool rw_mutex::try_read_lock_until(fast_task::time_point time_point) {
        interrupt_unsafe_region region;

        while (true) {
            uint64_t previous = values.state.fetch_add(private_values::READER_ONE, std::memory_order_acq_rel);
            if ((previous & (private_values::WRITER_LOCKED | private_values::HAS_WRITER_WAITERS)) == 0)
                return true;

            reader_left(values, values.state.fetch_sub(private_values::READER_ONE, std::memory_order_acq_rel));

            if (!futex::wait_on_address_until(
                    &values.state,
                    &rw_mutex::read_probe,
                    time_point,
                    {private_values::READER_KEY}
                ))
                return false;
        }
    }

    void rw_mutex::read_unlock() {
        interrupt_unsafe_region region;
        uint64_t previous = values.state.fetch_sub(private_values::READER_ONE, std::memory_order_acq_rel);
        if ((previous & private_values::READER_COUNT_MASK) == 0) {
            values.state.fetch_add(private_values::READER_ONE, std::memory_order_relaxed);
            throw std::logic_error("Tried unlock non owned mutex");
        }
        reader_left(values, previous);
    }

    bool rw_mutex::is_read_locked() {
        return (values.state.load(std::memory_order_relaxed) & private_values::READER_COUNT_MASK) != 0;
    }

    void rw_mutex::lifecycle_read_lock(task&& lock_task) {
        {
            fast_task::lock_guard guard(get_data(lock_task));
            if (get_data(lock_task).is_running() || get_data(lock_task).is_ended())
                throw std::runtime_error("Task is running or completed and cannot be registered");
            if (get_data(lock_task).is_scheduled() && (!get_data(lock_task).is_suspended() && get_data(lock_task).get_is_on_scheduler()))
                throw std::runtime_error("Task is already in the scheduler queue");
            if (!get_data(lock_task).vtable || !get_data(lock_task).vtable->on_start)
                throw std::logic_error("rw_mutex::lifecycle_read_lock requires the on_start callback to be set");
        }
        task::run([lock_task, this]() {
            fast_task::read_lock guard(*this);
            task::await_task(lock_task, true);
        });
    }

    void rw_mutex::write_lock() {
        interrupt_unsafe_region region;
        size_t self = this_task::get_id();

        while (true) {
            uint64_t state = values.state.load(std::memory_order_relaxed);
            if (writer_can_acquire(state)) {
                if (values.state.compare_exchange_weak(
                        state,
                        state | private_values::WRITER_LOCKED,
                        std::memory_order_acquire,
                        std::memory_order_relaxed
                    )) {
                    values.writer_owner.store(self, std::memory_order_relaxed);
                    return;
                }
                continue;
            }

            futex::wait_on_address(
                &values.state,
                &rw_mutex::write_probe,
                {private_values::WRITER_KEY}
            );
        }
    }

    bool rw_mutex::try_write_lock() {
        interrupt_unsafe_region region;
        size_t self = this_task::get_id();
        uint64_t state = values.state.load(std::memory_order_relaxed);
        if (!writer_can_acquire(state))
            return false;
        if (!values.state.compare_exchange_strong(
                state,
                state | private_values::WRITER_LOCKED,
                std::memory_order_acquire,
                std::memory_order_relaxed
            ))
            return false;
        values.writer_owner.store(self, std::memory_order_relaxed);
        return true;
    }

    bool rw_mutex::try_write_lock_until(fast_task::time_point time_point) {
        interrupt_unsafe_region region;
        size_t self = this_task::get_id();

        while (true) {
            uint64_t state = values.state.load(std::memory_order_relaxed);
            if (writer_can_acquire(state)) {
                if (values.state.compare_exchange_weak(
                        state,
                        state | private_values::WRITER_LOCKED,
                        std::memory_order_acquire,
                        std::memory_order_relaxed
                    )) {
                    values.writer_owner.store(self, std::memory_order_relaxed);
                    return true;
                }
                continue;
            }

            if (!futex::wait_on_address_until(
                    &values.state,
                    &rw_mutex::write_probe,
                    time_point,
                    {private_values::WRITER_KEY}
                ))
                return false;
        }
    }

    void rw_mutex::write_unlock() {
        interrupt_unsafe_region region;
        size_t self = this_task::get_id();
        uint64_t state = values.state.load(std::memory_order_relaxed);
        if ((state & private_values::WRITER_LOCKED) == 0 || values.writer_owner.load(std::memory_order_relaxed) != self)
            throw std::logic_error("Tried unlock non owned mutex");

        values.writer_owner.store(0, std::memory_order_relaxed);

        uint64_t expected = state;
        while (!values.state.compare_exchange_weak(
            expected,
            expected & ~private_values::WRITER_LOCKED,
            std::memory_order_release,
            std::memory_order_relaxed
        )) {
        }

        if ((expected & private_values::HAS_WRITER_WAITERS) != 0)
            wake_writers(values, 1);
        else if ((expected & private_values::HAS_READER_WAITERS) != 0)
            wake_readers(values);
    }

    bool rw_mutex::is_write_locked() {
        return (values.state.load(std::memory_order_relaxed) & private_values::WRITER_LOCKED) != 0;
    }

    void rw_mutex::lifecycle_write_lock(task&& lock_task) {
        {
            fast_task::lock_guard guard(get_data(lock_task));
            if (get_data(lock_task).is_running() || get_data(lock_task).is_ended())
                throw std::runtime_error("Task is running or completed and cannot be registered");
            if (get_data(lock_task).is_scheduled() && (!get_data(lock_task).is_suspended() && get_data(lock_task).get_is_on_scheduler()))
                throw std::runtime_error("Task is already in the scheduler queue");
            if (!get_data(lock_task).vtable || !get_data(lock_task).vtable->on_start)
                throw std::logic_error("rw_mutex::lifecycle_write_lock requires the on_start callback to be set");
        }
        task::run([lock_task, this]() {
            fast_task::write_lock guard(*this);
            task::await_task(lock_task, true);
        });
    }

    bool rw_mutex::is_own() {
        uint64_t state = values.state.load(std::memory_order_relaxed);
        if ((state & private_values::READER_COUNT_MASK) != 0)
            return true;
        if ((state & private_values::WRITER_LOCKED) == 0)
            return false;
        return values.writer_owner.load(std::memory_order_relaxed) == this_task::get_id();
    }

    bool rw_mutex::enter_read_wait(const task& task_obj, enter_state& state) {
        interrupt_unsafe_region region;
        return futex::enter_wait_on_address_lock(
            task_obj,
            &values.state,
            &rw_mutex::read_probe,
            [](void* address, const task&, futex::node_data) {
                private_values& values = values_of(address);
                uint64_t current = values.state.load(std::memory_order_relaxed);
                while (true) {
                    if (!reader_can_acquire(current)) {
                        current = values.state.load(std::memory_order_relaxed);
                        continue;
                    }
                    if (values.state.compare_exchange_weak(
                            current,
                            current + private_values::READER_ONE,
                            std::memory_order_acquire,
                            std::memory_order_relaxed
                        ))
                        return;
                }
            },
            state,
            {private_values::READER_KEY}
        );
    }

    bool rw_mutex::enter_read_wait_until(const task& task_obj, enter_state& state, fast_task::time_point time_point) {
        interrupt_unsafe_region region;
        return futex::enter_wait_on_address_lock_until(
            task_obj,
            &values.state,
            &rw_mutex::read_probe,
            [](void* address, const task&, futex::node_data) {
                private_values& values = values_of(address);
                uint64_t current = values.state.load(std::memory_order_relaxed);
                while (true) {
                    if (!reader_can_acquire(current)) {
                        current = values.state.load(std::memory_order_relaxed);
                        continue;
                    }
                    if (values.state.compare_exchange_weak(
                            current,
                            current + private_values::READER_ONE,
                            std::memory_order_acquire,
                            std::memory_order_relaxed
                        ))
                        return;
                }
            },
            state,
            time_point,
            {private_values::READER_KEY}
        );
    }

    bool rw_mutex::enter_write_wait(const task& task_obj, enter_state& state) {
        interrupt_unsafe_region region;
        return futex::enter_wait_on_address_lock(
            task_obj,
            &values.state,
            &rw_mutex::write_probe,
            [](void* address, const task& task_obj, futex::node_data) {
                private_values& values = values_of(address);
                uint64_t current = values.state.load(std::memory_order_relaxed);
                while (true) {
                    if (writer_can_acquire(current)) {
                        if (values.state.compare_exchange_weak(
                                current,
                                current | private_values::WRITER_LOCKED,
                                std::memory_order_acquire,
                                std::memory_order_relaxed
                            )) {
                            values.writer_owner.store(task_obj.get_id(), std::memory_order_relaxed);
                            return;
                        }
                        continue;
                    }
                    current = values.state.load(std::memory_order_relaxed);
                }
            },
            state,
            {private_values::WRITER_KEY}
        );
    }

    bool rw_mutex::enter_write_wait_until(const task& task_obj, enter_state& state, fast_task::time_point time_point) {
        interrupt_unsafe_region region;
        return futex::enter_wait_on_address_lock_until(
            task_obj,
            &values.state,
            &rw_mutex::write_probe,
            [](void* address, const task& task_obj, futex::node_data) {
                private_values& values = values_of(address);
                uint64_t current = values.state.load(std::memory_order_relaxed);
                while (true) {
                    if (writer_can_acquire(current)) {
                        if (values.state.compare_exchange_weak(
                                current,
                                current | private_values::WRITER_LOCKED,
                                std::memory_order_acquire,
                                std::memory_order_relaxed
                            )) {
                            values.writer_owner.store(task_obj.get_id(), std::memory_order_relaxed);
                            return;
                        }
                        continue;
                    }
                    current = values.state.load(std::memory_order_relaxed);
                }
            },
            state,
            time_point,
            {private_values::WRITER_KEY}
        );
    }
}
