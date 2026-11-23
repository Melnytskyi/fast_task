// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_CORE_EVENT
#define FAST_TASK_CORE_EVENT

#include <atomic>
#include <cstdint>
#include <new>

#include <fast_task/clock.hpp>
#include <fast_task/shared.hpp>
#include <fast_task/task.hpp>
#include <tasks/core/notify/notifier.hpp>
#include <tasks/core/runtime/hdi.hpp>

namespace fast_task {
    bool native_futex_wait_until(std::atomic<uint32_t>* address, uint32_t expected_value, fast_task::time_point time_point);
    void native_futex_wake(std::atomic_uint32_t* address, uint32_t count);

    class FT_API_LOCAL scheduler_event {
        pool_park_line park;

    public:
        scheduler_event() = default;
        scheduler_event(const scheduler_event&) = delete;
        scheduler_event& operator=(const scheduler_event&) = delete;

        bool notify_one() noexcept {
            std::atomic_thread_fence(std::memory_order_seq_cst);

            uint64_t state = park.load(std::memory_order_acquire);
            if (pool_park_line::sleepers_in(state) == 0)
                return false;
            if (pool_park_line::spinners_in(state) != 0 || pool_park_line::pending_in(state))
                return true;

            if (!park.begin_wake(state))
                return true;
            park.bump_epoch();
            native_futex_wake(&park.wake_epoch, 1);
            return true;
        }

        bool cascade() noexcept {
            park.clear_pending();
            return notify_one();
        }

        void notify_all() noexcept {
            std::atomic_thread_fence(std::memory_order_seq_cst);
            park.bump_epoch();
            park.clear_pending();
            if (park.load(std::memory_order_seq_cst) & pool_park_line::sleepers_mask)
                native_futex_wake(&park.wake_epoch, UINT32_MAX);
        }

        template <class Pred>
        bool wait(Pred&& pred, fast_task::time_point deadline) noexcept {
            const bool bounded = deadline != fast_task::time_point::max();
            for (;;) {
                const uint32_t token = park.epoch();
                if (pred())
                    return true;
                if (bounded && fast_task::clock::now() >= deadline)
                    return pred();

                park.clear_pending();
                park.add_sleeper();
                if (pred() || park.epoch() != token) {
                    park.remove_sleeper();
                    continue;
                }
                native_futex_wait_until(&park.wake_epoch, token, deadline);
                park.remove_sleeper();
            }
        }

        uint32_t current_epoch() const noexcept {
            return park.epoch();
        }

        bool has_sleepers() const noexcept {
            return park.has_sleepers();
        }

        bool has_pending() const noexcept {
            return park.has_pending();
        }

        bool clear_pending() noexcept {
            return park.clear_pending();
        }

        pool_park_line& line() noexcept {
            return park;
        }
    };

}

#endif /* FAST_TASK_CORE_EVENT */
