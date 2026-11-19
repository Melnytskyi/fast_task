// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)
//
// Policy implementations (plans/pool-architecture.md §2.5–§2.7).
//
// S2b ships one (queue, idle) combination: work_stealing_lifo + wait. The
// functions below are the only place that knows the concrete queue layout;
// `make_ops<Q, I>()` is the runtime selection point, and it is a compile-time
// constant per storage type, so no hot path branches on a policy.

#include <tasks/_internal.hpp>

namespace fast_task {
    namespace {
        using ws_wait = configured_worker_pool_storage<scheduler::queue_policy::work_stealing_lifo,
                                                       scheduler::idle_policy::wait>;

        ws_wait& as_ws(worker_pool_storage& pool) noexcept {
            return static_cast<ws_wait&>(pool);
        }

        const ws_wait& as_ws(const worker_pool_storage& pool) noexcept {
            return static_cast<const ws_wait&>(pool);
        }

        // ---- publish path (§6.1) -------------------------------------------

        // The whole tail of route_task: the local-deque fast path, the
        // self-publish rule and the hot/cold split, followed by the single
        // wake. Kept out of the router so that a second queue policy only has
        // to reimplement this function.
        bool ws_enqueue(worker_pool_storage& base, executors_local* loc, task_object* raw) noexcept {
            auto& pool = as_ws(base);

            if (!raw) {
                // Retire signal: it is not work, but a worker still has to see
                // it, so it goes to the shared queue with a wake.
                pool.queue_data.tasks.enqueue(nullptr);
                wake_work(pool.work_event, pool.pool_index);
                return true;
            }

            // A worker publishing into its own pool keeps the task in its
            // inline deque and only pays a wake when it might sleep (more than
            // one queued item).
            //
            // A task that publishes *itself* is the exception. this_task::yield()
            // re-publishes the running task and only then suspends it, so
            // putting it back on the bottom of the worker's LIFO deque makes the
            // very next fetch_one() pop it again: everything already runnable
            // underneath it -- including the task it just published, and
            // anything older -- never gets a turn. This shipped as a livelock in
            // TaskCvTest.HasWaiters under parallel load (the test spins on
            // cv.has_waiters() while yielding, and the waiter it had published
            // sat under it in the deque forever). A yielding task therefore goes
            // to the tail of the shared queue, i.e. behind everything that is
            // already ready, which is the rule Go's runtime.Gosched() uses.
            const bool self_publish = loc && loc->curr_task && &get_data(loc->curr_task) == raw;
            if (!self_publish && loc && loc->owner_pool == &base && loc->local_tasks.emplace(raw)) {
                if (loc->local_tasks.size() > 1)
                    wake_work(pool.work_event, pool.pool_index);
                return true;
            }

            if (pool.is_global && !can_be_scheduled_task_to_hot())
                pool.queue_data.cold_tasks.enqueue(raw);
            else
                pool.queue_data.tasks.enqueue(raw);
            wake_work(pool.work_event, pool.pool_index);
            return false;
        }

        // Put a task back without notifying: the caller owns the wake (worker
        // teardown drains, bulk-drain leftovers). One wake per batch instead of
        // one per task.
        bool ws_requeue(worker_pool_storage& base, task_object* raw) noexcept {
            as_ws(base).queue_data.tasks.enqueue(raw);
            return true;
        }

        // Timing-wheel "cold" tasks. The caller decides on the wake: the driver
        // batches them and calls wake_work_all() once.
        bool ws_enqueue_cold(worker_pool_storage& base, task_object* raw) noexcept {
            as_ws(base).queue_data.cold_tasks.enqueue(raw);
            return true;
        }

        // ---- consume path ---------------------------------------------------

        size_t ws_dequeue_bulk(worker_pool_storage& base, executors_local* loc, task_object** out, size_t max) noexcept {
            auto& pool = as_ws(base);
            size_t count = pool.queue_data.tasks.try_dequeue_bulk(out, max);
            if (count == 0 && pool.is_global && can_be_scheduled_task_to_hot())
                count = pool.queue_data.cold_tasks.try_dequeue_bulk(out, max);
            (void)loc;
            return count;
        }

        // ---- idle path (§2.7) -----------------------------------------------

        bool ws_has_queued_work(const worker_pool_storage& base, const executors_local* loc) noexcept {
            if (loc) {
                if (loc->run_next != nullptr)
                    return true;
                if (loc->local_tasks.size() != 0)
                    return true;
            }
            const auto& pool = as_ws(base);
            if (pool.queue_data.tasks.size_approx() != 0)
                return true;
            if (pool.is_global && pool.queue_data.cold_tasks.size_approx() != 0)
                return true;
            return false;
        }

        bool ws_has_runnable_work(const worker_pool_storage& base, const executors_local* loc) noexcept {
            if (ws_has_queued_work(base, loc))
                return true;
            // Something in a peer's deque that this worker could steal. The
            // dense list makes this O(active workers) instead of a slot scan.
            return base.registry.any_work();
        }

        // Total pause-instruction budget of the prober, in pause units, and the
        // longest the loop may go between two probes. 8192 pauses is ~150 us of
        // looking on a 3.5 GHz core; the 1024-pause interval cap keeps the
        // worst-case burst latency after a long idle stretch at ~20 us instead
        // of the ~150 us a doubling interval would give.
        //
        // The budget is deliberately narrow. A prober that never parks burns a
        // core per idle worker, and on a fully populated pool (16 workers on
        // 8 cores) that starves the very thread that waits for the burst to
        // finish: at 1K empty tasks the awaiting thread lost up to 2 ms of
        // wake-up time behind spinning workers. Parking after ~150 us costs one
        // futex round-trip when the next burst arrives late, which is the
        // cheaper of the two.
        constexpr unsigned spin_budget = 8192;
        constexpr unsigned spin_interval_cap = 1024;

        // Poll the queues, backing off, before parking.
        //
        // An eventcount on its own makes a *task stream* pay one kernel
        // round-trip per task: the publisher finds a parked worker, issues a
        // futex wake, the woken worker finds the queue already drained, and
        // parks again. So a worker looks for a moment before it parks.
        //
        // The probe interval backs off instead of being flat. The queue's
        // producer index lives in the publisher's cache, and every idle prober
        // drags it out of there, so a flat tight spin turns the enqueue itself
        // into the bottleneck (~500 producer cycles per publish with sixteen
        // flat spinners). Doubling the pause interval keeps the burst latency
        // of a tight spin (the first probe is immediate) while cutting the
        // steady-state read rate by orders of magnitude.
        //
        // Only the cheap witness is used here: scanning the peers' deques on
        // every iteration would pull the running workers' deque heads into the
        // idle workers' caches, which is the same mistake as the flat spin.
        inline bool spin_before_park(const worker_pool_storage& pool, const executors_local* loc) noexcept {
            unsigned budget = spin_budget;
            if (budget == 0)
                return false;

            const uint32_t epoch = pool.work_event.current_epoch();
            unsigned pause = 32;
            while (budget != 0) {
                const unsigned slice = pause < budget ? pause : budget;
                for (unsigned i = 0; i < slice; ++i)
                    pool_cpu_relax();
                budget -= slice;

                if (scheduler_stopping() || glob.stw_request.load(std::memory_order_relaxed))
                    return true;
                if (ws_has_queued_work(pool, loc))
                    return true;
                if (pool.work_event.current_epoch() != epoch)
                    return true;

                if (pause < spin_interval_cap)
                    pause <<= 1;
            }
            return false;
        }

        // idle_policy::wait: look briefly, then sleep on the pool's eventcount
        // until work, stop, a driver handoff or the deadline. Every enqueue
        // notifies that event, and a driver handoff is part of the predicate,
        // so nothing else is polled on a timer.
        bool ws_wait_until(worker_pool_storage& base, executors_local* loc, fast_task::time_point deadline) noexcept {
            if (deadline == fast_task::time_point::max() && spin_before_park(base, loc))
                return true;

            auto pred = [&base, loc] {
                return scheduler_stopping() ||
                       driver_claimable(loc) ||
                       ws_has_runnable_work(base, loc);
            };
            base.work_event.wait(pred, deadline);
            return true;
        }

        // ---- control / legacy close path -------------------------------------

        void ws_drain_all(worker_pool_storage& base, std::vector<task_object*>& out) noexcept {
            auto& pool = as_ws(base);
            task_object* raw = nullptr;
            while (pool.queue_data.tasks.try_dequeue(raw)) {
                if (raw)
                    out.push_back(raw);
            }
            while (pool.queue_data.cold_tasks.try_dequeue(raw)) {
                if (raw)
                    out.push_back(raw);
            }
        }

        // Drop whatever is still throttled. Used by clean_up(), which only
        // wants the references released.
        void ws_drain_cold(worker_pool_storage& base) noexcept {
            task_object* raw = nullptr;
            while (as_ws(base).queue_data.cold_tasks.try_dequeue(raw))
                task::adopt(raw);
        }

        size_t ws_pending(const worker_pool_storage& base) noexcept {
            const auto& pool = as_ws(base);
            size_t queued = pool.queue_data.tasks.size_approx();
            if (pool.is_global)
                queued += pool.queue_data.cold_tasks.size_approx();
            return queued;
        }

        void ws_destroy(worker_pool_storage& base) noexcept {
            as_ws(base).~ws_wait();
        }

        void ws_deallocate(worker_pool_storage& base) noexcept {
            delete &as_ws(base);
        }
    }

    template <scheduler::queue_policy Q, scheduler::idle_policy I>
    configured_worker_pool_storage<Q, I>::configured_worker_pool_storage() noexcept
        : queue_data() {
        this->ops = make_ops<Q, I>();
        this->registry = this->entry.registry.view();
    }

    template <scheduler::queue_policy Q, scheduler::idle_policy I>
    constexpr worker_pool_ops make_ops() noexcept {
        static_assert(Q == scheduler::queue_policy::work_stealing_lifo,
                      "S2b ships work_stealing_lifo; priority_fifo arrives in S3a");
        static_assert(I == scheduler::idle_policy::wait,
                      "S2b ships the wait idle policy; busy_spin arrives in S3a");
        return worker_pool_ops{
            &ws_enqueue,
            &ws_requeue,
            &ws_enqueue_cold,
            &ws_dequeue_bulk,
            &ws_has_queued_work,
            &ws_has_runnable_work,
            &ws_wait_until,
            &ws_drain_all,
            &ws_drain_cold,
            &ws_pending,
            &ws_destroy,
            &ws_deallocate};
    }

    template struct configured_worker_pool_storage<scheduler::queue_policy::work_stealing_lifo,
                                                  scheduler::idle_policy::wait>;
}
