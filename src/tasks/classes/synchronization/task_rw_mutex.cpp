// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <fast_task/experimental/futex.hpp>
#include <fast_task/task.hpp>
#include <tasks/_internal.hpp>

namespace fast_task {
    inline bool writer_can_acquire(uint64_t writer, uint32_t readers) {
        return writer == 0 && readers == 0;
    }

    template <uint8_t Key, uint8_t Transition>
    size_t rw_mutex::wake_waiters(rw_mutex::private_values& values, size_t count) {
        return futex::wake_and_requeue_on_address_select(
            &values.state,
            [](void* address, size_t, bool has_remaining) {
                auto& v = values_of(address);
                if (Transition == 1)
                    v.state.store(0, std::memory_order_release);
                else if (Transition == 2)
                    v.readers.fetch_sub(1, std::memory_order_release);

                if (!has_remaining) {
                    const uint32_t clear_mask = (Key == private_values::READER_KEY)
                                                    ? private_values::HAS_READER_WAITERS
                                                    : private_values::HAS_WRITER_WAITERS;
                    v.waiters.fetch_and(~clear_mask, std::memory_order_release);
                }
            },
            [](void*, futex::node_data node, bool) {
                return node.data == Key;
            },
            count,
            count
        );
    }

    rw_mutex::rw_mutex() {
        FT_DEBUG_ONLY(register_object(this));
    }

    rw_mutex::~rw_mutex() {
        FT_DEBUG_ONLY(unregister_object(this));
        if (values.state.load(std::memory_order_relaxed) != 0 || values.readers.load(std::memory_order_relaxed) != 0) {
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
            uint64_t writer = values.state.load(std::memory_order_relaxed);
            uint32_t w = values.waiters.load(std::memory_order_relaxed);
            if (reader_can_acquire(writer, w)) {
                values.readers.fetch_add(1, std::memory_order_acquire);

                if ((values.waiters.load(std::memory_order_relaxed) & rw_mutex::private_values::HAS_WRITER_WAITERS) == 0)
                    return;
                if (values.readers.fetch_sub(1, std::memory_order_release) == 1)
                    wake_waiters<rw_mutex::private_values::WRITER_KEY, 0>(values, 1);
            }

            futex::wait_on_address(
                &values.state,
                [](void* address) {
                    auto& v = values_of(address);
                    if (reader_can_acquire(
                            v.state.load(std::memory_order_relaxed),
                            v.waiters.load(std::memory_order_relaxed)
                        ))
                        return true;
                    v.waiters.fetch_or(rw_mutex::private_values::HAS_READER_WAITERS, std::memory_order_release);
                    return false;
                },
                {rw_mutex::private_values::READER_KEY}
            );
        }
    }

    bool rw_mutex::try_read_lock() {
        interrupt_unsafe_region region;
        uint64_t writer = values.state.load(std::memory_order_relaxed);
        uint32_t w = values.waiters.load(std::memory_order_relaxed);
        if (!reader_can_acquire(writer, w))
            return false;
        values.readers.fetch_add(1, std::memory_order_acquire);
        if ((values.waiters.load(std::memory_order_relaxed) & rw_mutex::private_values::HAS_WRITER_WAITERS) != 0) {
            values.readers.fetch_sub(1, std::memory_order_release);
            return false;
        }
        return true;
    }

    bool rw_mutex::try_read_lock_until(std::chrono::high_resolution_clock::time_point time_point) {
        interrupt_unsafe_region region;
        while (true) {
            uint64_t writer = values.state.load(std::memory_order_relaxed);
            uint32_t w = values.waiters.load(std::memory_order_relaxed);
            if (reader_can_acquire(writer, w)) {
                values.readers.fetch_add(1, std::memory_order_acquire);
                if ((values.waiters.load(std::memory_order_relaxed) & rw_mutex::private_values::HAS_WRITER_WAITERS) == 0)
                    return true;
                if (values.readers.fetch_sub(1, std::memory_order_release) == 1)
                    wake_waiters<rw_mutex::private_values::WRITER_KEY, 0>(values, 1);
            }

            if (!futex::wait_on_address_until(
                    &values.state,
                    [](void* address) {
                        auto& v = values_of(address);
                        if (reader_can_acquire(
                                v.state.load(std::memory_order_relaxed),
                                v.waiters.load(std::memory_order_relaxed)
                            ))
                            return true;
                        v.waiters.fetch_or(rw_mutex::private_values::HAS_READER_WAITERS, std::memory_order_release);
                        return false;
                    },
                    time_point,
                    {rw_mutex::private_values::READER_KEY}
                ))
                return false;
        }
    }

    void rw_mutex::read_unlock() {
        interrupt_unsafe_region region;
        uint32_t prev = values.readers.load(std::memory_order_acquire);
        if (prev == 0)
            throw std::logic_error("Tried unlock non owned mutex");

        if (prev == 1) {
            wake_waiters<rw_mutex::private_values::WRITER_KEY, 2>(values, 1);
        } else {
            values.readers.fetch_sub(1, std::memory_order_release);
        }
    }

    bool rw_mutex::is_read_locked() {
        return values.readers.load(std::memory_order_relaxed) != 0;
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
            uint64_t writer = values.state.load(std::memory_order_relaxed);
            uint32_t readers = values.readers.load(std::memory_order_relaxed);
            if (writer_can_acquire(writer, readers)) {
                uint64_t expected = 0;
                if (values.state.compare_exchange_weak(expected, self, std::memory_order_acquire, std::memory_order_relaxed))
                    return;
                continue;
            }

            futex::wait_on_address(
                &values.state,
                [](void* address) {
                    auto& v = values_of(address);
                    if (writer_can_acquire(
                            v.state.load(std::memory_order_relaxed),
                            v.readers.load(std::memory_order_relaxed)
                        ))
                        return true;
                    v.waiters.fetch_or(rw_mutex::private_values::HAS_WRITER_WAITERS, std::memory_order_release);
                    return false;
                },
                {rw_mutex::private_values::WRITER_KEY}
            );
        }
    }

    bool rw_mutex::try_write_lock() {
        interrupt_unsafe_region region;
        size_t self = this_task::get_id();
        uint64_t writer = values.state.load(std::memory_order_relaxed);
        uint32_t readers = values.readers.load(std::memory_order_relaxed);
        if (!writer_can_acquire(writer, readers))
            return false;
        uint64_t expected = 0;
        return values.state.compare_exchange_strong(expected, self, std::memory_order_acquire, std::memory_order_relaxed);
    }

    bool rw_mutex::try_write_lock_until(std::chrono::high_resolution_clock::time_point time_point) {
        interrupt_unsafe_region region;
        size_t self = this_task::get_id();
        while (true) {
            uint64_t writer = values.state.load(std::memory_order_relaxed);
            uint32_t readers = values.readers.load(std::memory_order_relaxed);
            if (writer_can_acquire(writer, readers)) {
                uint64_t expected = 0;
                if (values.state.compare_exchange_weak(expected, self, std::memory_order_acquire, std::memory_order_relaxed))
                    return true;
                continue;
            }

            if (!futex::wait_on_address_until(
                    &values.state,
                    [](void* address) {
                        auto& v = values_of(address);
                        if (writer_can_acquire(
                                v.state.load(std::memory_order_relaxed),
                                v.readers.load(std::memory_order_relaxed)
                            ))
                            return true;
                        v.waiters.fetch_or(rw_mutex::private_values::HAS_WRITER_WAITERS, std::memory_order_release);
                        return false;
                    },
                    time_point,
                    {rw_mutex::private_values::WRITER_KEY}
                ))
                return false;
        }
    }

    void rw_mutex::write_unlock() {
        interrupt_unsafe_region region;
        size_t self = this_task::get_id();
        if (values.state.load(std::memory_order_relaxed) != self)
            throw std::logic_error("Tried unlock non owned mutex");

        if (wake_waiters<rw_mutex::private_values::WRITER_KEY, 1>(values, 1) == 0) {
            wake_waiters<rw_mutex::private_values::READER_KEY, 0>(values, SIZE_MAX);
        }
    }

    bool rw_mutex::is_write_locked() {
        return values.state.load(std::memory_order_relaxed) != 0;
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
        size_t self = this_task::get_id();
        if (values.state.load(std::memory_order_relaxed) == self)
            return true;
        return values.readers.load(std::memory_order_relaxed) != 0;
    }

    bool rw_mutex::enter_read_wait(const task& task_obj, enter_state& state) {
        interrupt_unsafe_region region;
        return futex::enter_wait_on_address_lock(
            task_obj,
            &values.state,
            [](void* address) {
                auto& v = values_of(address);
                return reader_can_acquire(
                    v.state.load(std::memory_order_relaxed),
                    v.waiters.load(std::memory_order_relaxed)
                );
            },
            [](void* address, const task&, futex::node_data) {
                auto& v = values_of(address);
                v.waiters.fetch_or(rw_mutex::private_values::HAS_READER_WAITERS, std::memory_order_release);
                v.readers.fetch_add(1, std::memory_order_acquire);
            },
            state,
            {rw_mutex::private_values::READER_KEY}
        );
    }

    bool rw_mutex::enter_read_wait_until(const task& task_obj, enter_state& state, std::chrono::high_resolution_clock::time_point time_point) {
        interrupt_unsafe_region region;
        return futex::enter_wait_on_address_lock_until(
            task_obj,
            &values.state,
            [](void* address) {
                auto& v = values_of(address);
                return reader_can_acquire(
                    v.state.load(std::memory_order_relaxed),
                    v.waiters.load(std::memory_order_relaxed)
                );
            },
            [](void* address, const task&, futex::node_data) {
                auto& v = values_of(address);
                v.waiters.fetch_or(rw_mutex::private_values::HAS_READER_WAITERS, std::memory_order_release);
                v.readers.fetch_add(1, std::memory_order_acquire);
            },
            state,
            time_point,
            {rw_mutex::private_values::READER_KEY}
        );
    }

    bool rw_mutex::enter_write_wait(const task& task_obj, enter_state& state) {
        interrupt_unsafe_region region;
        return futex::enter_wait_on_address_lock(
            task_obj,
            &values.state,
            [](void* address) {
                auto& v = values_of(address);
                return writer_can_acquire(
                    v.state.load(std::memory_order_relaxed),
                    v.readers.load(std::memory_order_relaxed)
                );
            },
            [](void* address, const task& t, futex::node_data) {
                auto& v = values_of(address);
                v.waiters.fetch_or(rw_mutex::private_values::HAS_WRITER_WAITERS, std::memory_order_release);
                v.state.store(t.get_id(), std::memory_order_acquire);
            },
            state,
            {rw_mutex::private_values::WRITER_KEY}
        );
    }

    bool rw_mutex::enter_write_wait_until(const task& task_obj, enter_state& state, std::chrono::high_resolution_clock::time_point time_point) {
        interrupt_unsafe_region region;
        return futex::enter_wait_on_address_lock_until(
            task_obj,
            &values.state,
            [](void* address) {
                auto& v = values_of(address);
                return writer_can_acquire(
                    v.state.load(std::memory_order_relaxed),
                    v.readers.load(std::memory_order_relaxed)
                );
            },
            [](void* address, const task& t, futex::node_data) {
                auto& v = values_of(address);
                v.waiters.fetch_or(rw_mutex::private_values::HAS_WRITER_WAITERS, std::memory_order_release);
                v.state.store(t.get_id(), std::memory_order_acquire);
            },
            state,
            time_point,
            {rw_mutex::private_values::WRITER_KEY}
        );
    }
}
