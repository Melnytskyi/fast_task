// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)
//
// Driver implementation. Moved verbatim out of tasks/_internal.cpp by S0b
// (plans/pool-architecture.md §4); S1 added the wake token, the parked-pool
// handshake and the handoff described in §2.9.

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
                auto& global = global_storage();
                {
                    fast_task::shared_lock sg(glob.task_thread_safety);
                    for (size_t i = 0; i < cold_count; ++i)
                        global.ops.enqueue_cold(global, cold_wakes[i].release());
                }
                // A batch: one notify_one would wake a single worker and leave
                // the rest of the batch queued behind it.
                wake_work_all(global.work_event, global_pool_index);
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
            if (tmng.check_id != get_data(tmng.awake_task).awake_check)
                return;

            if (tmng.get_is_cold()) {
                enqueue_cold(std::move(tmng.awake_task));
            } else {
                fast_task::lock_guard tg(get_data(tmng.awake_task));
                if (get_data(tmng.awake_task).get_awaked())
                    return;
                get_data(tmng.awake_task).set_time_end(true);
                enqueue_wake(std::move(tmng.awake_task));
            }
        };

        auto current_now = fast_task::clock::now();
        if (glob.shutdown_requested.load(std::memory_order_acquire)) {
            glob.timed_wheel.clear([&](timing& tmng) {
                if (tmng.check_id == get_data(tmng.awake_task).awake_check)
                    handle_expired(tmng);
            });
        } else
            glob.timed_wheel.collect_expired(current_now, handle_expired);

        flush_wake_ups();
        flush_cold();

        {
            fast_task::shared_lock sg(glob.task_thread_safety);
            glob.no_tasks_execute_notifier.notify_all();
        }

        // Drain any I/O completions that are already ready. Never block here:
        // park_until() is the only place the driver is allowed to sleep.
        util::native_workers_singleton::poll_all(0);

        (void)loc;
    }

    void driver_context::park_until(executors_local* loc, fast_task::time_point max_wait, uint32_t token_before, uint32_t work_epoch_before) {
        using clock = fast_task::clock;

        // The wheel only matters when the timer controller is running. When it
        // is not, there is nothing to wake us early, but max_wait is still a
        // hard deadline: a caller that asked to sleep for 50ms must sleep for
        // 50ms even if no timer was ever armed.
        const bool timers_live = glob.time_control_enabled.load(std::memory_order_acquire);
        auto deadline = max_wait;
        if (timers_live) {
            auto next_deadline = glob.timed_wheel.next_deadline();
            if (next_deadline < deadline)
                deadline = next_deadline;
        }

        int timeout_ms = -1;
        if (deadline != clock::time_point::max()) {
            auto now = clock::now();
            if (deadline <= now)
                timeout_ms = 0;
            else {
                auto remain = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
                // Round up so we never wake a hair early and spin.
                timeout_ms = static_cast<int>(remain.count()) + 1;
            }
        }

        // Nothing to wait for and no deadline: do not enter the multiplexer.
        if (timeout_ms == 0)
            return;

        // Publish which pool we are parked on, then "parked", before the final
        // re-check. Any thread that publishes work for this pool afterwards
        // sees the pool id and pokes us; any wake() afterwards changes the
        // token and we bail out below. All of these are seq_cst so the
        // token/parked pair cannot be reordered into a lost wake.
        parked_pool.store(loc ? loc->pool_index : UINT16_MAX, std::memory_order_seq_cst);
        parked.store(true, std::memory_order_seq_cst);

        const bool woken = wake_token.load(std::memory_order_seq_cst) != token_before;

        // Only the final shutdown phase skips the park. shutdown_requested is
        // the drain phase (the wheel was just flushed by poll()), and workers
        // must stay in this bounded park rather than hot-spin until
        // executor_shutting_down is raised.
        const bool stopping = glob.executor_shutting_down.load(std::memory_order_acquire);

        // Re-check everything a producer may have published while we were
        // between poll() and the store above. Two independent witnesses:
        //   * the queue itself -- a publisher that read parked_pool before we
        //     stored it did not poke us, so this is the witness that closes the
        //     enqueue-versus-park race (it is a Dekker pair: the publisher's
        //     seq_cst fence precedes its parked_pool read, our parked store
        //     precedes this probe);
        //   * the pool's work_event epoch, for the wakes that do bump it.
        // At least one of them observes any publish.
        const bool work_notified = loc &&
                                   (has_runnable_work(loc, loc->owner_pool) ||
                                    work_event_of(*loc).current_epoch() != work_epoch_before);

        if (woken || stopping || work_notified) {
            parked.store(false, std::memory_order_release);
            parked_pool.store(UINT16_MAX, std::memory_order_release);
            return;
        }

        util::native_workers_singleton::poll_all(timeout_ms);
        parked.store(false, std::memory_order_release);
        parked_pool.store(UINT16_MAX, std::memory_order_release);
    }

    void driver_context::wake() {
        // The token bump is unconditional: it is what makes the post-publish
        // re-check in park_until() able to catch a wake that raced with the
        // "parked" store. The syscall stays conditional.
        wake_token.fetch_add(1, std::memory_order_seq_cst);
        if (parked.load(std::memory_order_seq_cst))
            util::native_workers_singleton::wake_all();
    }

    void driver_context::wake_driver_candidate() {
        // Publish the claim *before* the notify: a candidate whose wake-up is
        // not lost (its predicate sees the claim) must not then find the flag
        // unset and go back to sleep.
        claim_handoff.store(true, std::memory_order_seq_cst);
        // Every idle worker's work_event predicate accepts a claimable driver,
        // so this single notify is enough to make one of them take it instead
        // of going straight back to sleep. Preferring the global pool costs
        // nothing here: its workers always allow driver polling and it is where
        // every unbound task lands.
        global_storage().work_event.notify_one();
    }

    void driver_context::ensure_driver() {
        wake();
        // Only when nobody is parked: a parked driver already holds the lock,
        // and waking a candidate would just add a redundant wake-up.
        if (!driver_lock.is_locked())
            wake_driver_candidate();
    }

    void driver_context::handoff() {
        // Must be called with driver_lock released: a candidate can only claim
        // the driver while the lock is genuinely free.
        ensure_driver();
    }
}
