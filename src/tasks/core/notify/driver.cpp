// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <tasks/_internal.hpp>
#include <tasks/util/native_workers_singleton.hpp>

namespace fast_task {
    void driver_context::poll(executors_local* loc) {
        constexpr size_t BATCH = 64;
        task wake_ups[BATCH];
        task cold_wakes[BATCH];
        size_t wake_count = 0;
        size_t cold_count = 0;

        auto flush_wake_ups = [&] {
            for (size_t i = 0; i < wake_count; ++i)
                transfer_task(std::move(wake_ups[i]));
            wake_count = 0;
        };
        auto flush_cold = [&] {
            if (cold_count) {
                for (size_t i = 0; i < cold_count; ++i) {
                    task t = std::move(cold_wakes[i]);
                    if (!t)
                        continue;
                    auto& data = get_data(t);
                    pool_ref target = data.get_pool_assigned() ? acquire_pool_ref(data.pool_index) : pool_ref{};
                    worker_pool_storage& pool = target ? *target : global_storage();
                    {
                        fast_task::shared_lock sg(glob.no_tasks.guard);
                        if (pool.is_global)
                            pool.ops.queue.enqueue_cold(pool, t.release());
                        else
                            pool.ops.queue.enqueue(pool, nullptr, t.release());
                    }
                    wake_work_all(pool);
                }
                cold_count = 0;
            }
        };

        auto enqueue_wake = [&](task&& t) {
            wake_ups[wake_count++] = std::move(t);
            if (wake_count == BATCH)
                flush_wake_ups();
        };
        auto enqueue_cold = [&](task&& t) {
            cold_wakes[cold_count++] = std::move(t);
            if (cold_count == BATCH)
                flush_cold();
        };

        auto handle_expired = [&](timing& tmng) {
            auto& data = get_data(tmng.awake_task);
            bool is_cold = false;
            {
                fast_task::lock_guard tg(data);
                if (tmng.check_id != data.awake_check || data.get_awaked())
                    return;
                data.set_time_end(true);
                is_cold = tmng.get_is_cold();
            }
            if (is_cold)
                enqueue_cold(std::move(tmng.awake_task));
            else
                enqueue_wake(std::move(tmng.awake_task));
        };

        auto current_now = fast_task::clock::now();
        if (glob.shutdown.requested.load(std::memory_order_acquire)) {
            glob.timing.wheel.clear([&](timing& tmng) {
                if (tmng.check_id == get_data(tmng.awake_task).awake_check)
                    handle_expired(tmng);
            });
        } else
            glob.timing.wheel.collect_expired(current_now, handle_expired);

        flush_wake_ups();
        flush_cold();

        if (glob.no_tasks.waiters.load(std::memory_order_acquire) != 0) {
            fast_task::shared_lock sg(glob.no_tasks.guard);
            glob.no_tasks.notifier.notify_all();
        }

        util::native_workers_singleton::poll_all(0);

        (void)loc;
    }

    namespace {
        constexpr std::chrono::milliseconds driver_park_slice{50};
    }

    void driver_context::park_until(executors_local* loc, fast_task::time_point max_wait, uint32_t token_before, uint32_t work_epoch_before) {
        using clock = fast_task::clock;

        const bool timers_live = glob.timing.enabled.load(std::memory_order_acquire);
        auto deadline = max_wait;
        armed_deadline_ticks.store(UINT64_MAX, std::memory_order_seq_cst);
        if (timers_live) {
            auto next_deadline = glob.timing.wheel.next_deadline();
            if (next_deadline < deadline)
                deadline = next_deadline;
        }
        const auto slice_deadline = clock::now() + driver_park_slice;
        if (deadline == clock::time_point::max() || slice_deadline < deadline)
            deadline = slice_deadline;

        int timeout_ms = -1;
        if (deadline != clock::time_point::max()) {
            auto now = clock::now();
            if (deadline <= now)
                timeout_ms = 0;
            else {
                auto remain = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
                timeout_ms = static_cast<int>(remain.count()) + 1;
            }
        }

        if (timeout_ms == 0)
            return;

        const uint64_t deadline_ticks = deadline == clock::time_point::max()
                                            ? UINT64_MAX
                                            : glob.timing.wheel.to_ticks(deadline);
        parked_deadline_ticks.store(deadline_ticks, std::memory_order_relaxed);
        parked_pool.store(loc ? loc->pool_index : UINT16_MAX, std::memory_order_seq_cst);
        parked.store(true, std::memory_order_seq_cst);

        const bool woken = wake_token.load(std::memory_order_seq_cst) != token_before;

        const bool stopping = glob.shutdown.executors_down.load(std::memory_order_acquire);

        const bool work_notified = loc &&
                                   (has_runnable_work(loc->owner_pool, loc) ||
                                    work_event_of(*loc).current_epoch() != work_epoch_before);

        if (woken || stopping || work_notified) {
            parked.store(false, std::memory_order_release);
            parked_pool.store(UINT16_MAX, std::memory_order_release);
            parked_deadline_ticks.store(UINT64_MAX, std::memory_order_relaxed);
            return;
        }

        util::native_workers_singleton::poll_all(timeout_ms);
        parked.store(false, std::memory_order_release);
        parked_pool.store(UINT16_MAX, std::memory_order_release);
        parked_deadline_ticks.store(UINT64_MAX, std::memory_order_relaxed);
    }

    void driver_context::wake() {
        wake_token.fetch_add(1, std::memory_order_seq_cst);
        if (parked.load(std::memory_order_seq_cst))
            util::native_workers_singleton::wake_all();
    }

    void driver_context::wake_driver_candidate() {
        if (claim_handoff.load(std::memory_order_relaxed))
            return;
        claim_handoff.store(true, std::memory_order_seq_cst);
        if (global_storage().work_event.notify_one())
            return;
        for (uint8_t i = 0; i < user_pool_count; ++i) {
            if (auto pool = acquire_pool_ref(i)) {
                if (pool->config.allow_driver_polling && !pool->closing && pool->work_event.notify_one())
                    return;
            }
        }
    }

    void driver_context::ensure_driver() {
        wake();
        if (!driver_lock.is_locked())
            wake_driver_candidate();
    }

    void notify_driver_of_timer(uint64_t tick) noexcept {
        if (glob.driver.parked.load(std::memory_order_acquire)) {
            const uint64_t parked_ticks =
                glob.driver.parked_deadline_ticks.load(std::memory_order_relaxed);
            if (parked_ticks != UINT64_MAX && tick >= parked_ticks)
                return;
        }
        uint64_t cur = glob.driver.armed_deadline_ticks.load(std::memory_order_acquire);
        while (tick < cur) {
            if (glob.driver.armed_deadline_ticks.compare_exchange_weak(
                    cur, tick, std::memory_order_acq_rel, std::memory_order_acquire)) {
                glob.driver.ensure_driver();
                return;
            }
        }
    }

    void driver_context::handoff() {
        ensure_driver();
    }

    namespace util {
        void driver_notify_io_submission() noexcept {
            glob.driver.ensure_driver();
        }
    }
}
