// Copyright Danyil Melnytskyi 2026-Present
//
// scheduler::worker_context — a stack-resident worker that a foreign thread
// (UI loop, game loop, embedding host) can use to run tasks without becoming a
// permanently-registered scheduler thread.
//
// The whole point of this class is the STW quiescent state: the thread is only
// counted as "active in the scheduler" while it is inside poll*()/next*(). The
// rest of the time it is pre-paused, so request_stw() never waits for a thread
// that is blocked in SwapBuffers() or WaitMessage().
//
// S2a (plans/pool-architecture.md §2.2) made every pool — the global pool
// included — a `worker_pool_storage`, so this file no longer has a "global
// special case": a worker always has `owner_pool`, `pool_index` and
// `owner_pool->registry`. S2b moved every queue and idle-policy decision
// behind `owner_pool->ops`, so nothing here branches on the policy.

#include <tasks/_internal.hpp>

namespace fast_task::scheduler {

    namespace {
        // The executors_local lives inside worker_context::data, so we need a
        // way to get from the opaque byte buffer back to the object.
        inline executors_local* as_local(char* data) noexcept {
            return std::launder(reinterpret_cast<executors_local*>(data));
        }

        // has_runnable_work() lives in tasks/core/runtime.hpp: the driver needs
        // the same predicate as the enqueue-versus-park witness.

        // Take the driver role. The lock is the authority; a successful claim
        // consumes any pending handoff so the other idle workers stop looking.
        inline bool try_claim_driver() noexcept {
            if (!glob.driver.driver_lock.try_lock())
                return false;
            glob.driver.claim_handoff.store(false, std::memory_order_relaxed);
            return true;
        }

        // The idle prober and the park predicate moved to the pool's idle
        // policy (tasks/core/pool_ops.cpp, `wait_until`), because the policy --
        // not this loop -- decides how a worker looks for work and where it
        // sleeps (§2.7). `scheduler_stopping()`, `driver_claimable()` and
        // `pool_cpu_relax()` are shared from tasks/core/runtime.hpp.

        // Deadline for the bounded waits (poll_until/next_until). A thread that
        // does not hold the driver still has to poll it when a timer becomes
        // due, so the wait is capped by the wheel instead of being guessed at
        // with the old 10 ms slices. When the wheel is not running there is no
        // timer to wake us at all, so the backstop slice stays -- but it is now
        // only a cap: any enqueue or handoff wakes the wait immediately.
        fast_task::time_point bounded_wait_deadline(fast_task::time_point limit) noexcept {
            if (glob.time_control_enabled.load(std::memory_order_acquire)) {
                auto next = glob.timed_wheel.next_deadline();
                return next < limit ? next : limit;
            }
            auto backstop = fast_task::clock::now() + std::chrono::milliseconds(10);
            return backstop < limit ? backstop : limit;
        }
    }

    worker_context::worker_context(worker_options options) {
        if (get_loc() != nullptr)
            throw std::logic_error("Current thread already has an active worker_context");

        // The constructor is the single owner of thread naming: honour
        // options.prevent_thread_naming, otherwise remember the current name so
        // the destructor can put it back.
        if (!options.prevent_thread_naming) {
            // _get_name_thread_dbg takes a pthread_t, so it must be given this
            // thread's id: passing 0 would read thread 0's name instead.
            saved_thread_name = _get_name_thread_dbg(_thread_id());
            if (options.bind_id == static_cast<uint16_t>(-1))
                _set_name_thread_dbg("fast_task worker");
            else
                _set_name_thread_dbg("Binded worker " + std::to_string(options.bind_id));
        }

        auto* loc = new (data) executors_local();
        loc->options = options;
        set_loc(loc);

        // Legacy ids 0..254 are the table slots; anything else is global.
        const uint8_t index = options.bind_id == static_cast<uint16_t>(-1)
                                  ? global_pool_index
                                  : bind_pool_index(options.bind_id);
        worker_pool_storage* pool = pool_for_index(index);
        if (!pool) {
            // A throwing constructor does not run the destructor, so the
            // worker name set above must be put back here explicitly.
            if (!saved_thread_name.empty())
                _set_name_thread_dbg(saved_thread_name);
            set_loc(nullptr);
            loc->~executors_local();
            throw std::logic_error("Binded worker context not found");
        }

        loc->owner_pool = pool;
        loc->pool_index = index;
        loc->registry_slot = pool->registry.claim(&loc->local_tasks);
        pool->runtime.active_workers.fetch_add(1, std::memory_order_acq_rel);
        glob.total_active_workers.fetch_add(1, std::memory_order_acq_rel);
        pool->runtime.live_threads.fetch_add(1, std::memory_order_acq_rel);
    }

    worker_context::~worker_context() {
        // Restore the name first: the early return below must not leave the
        // worker name on a thread whose slot was taken over.
        if (!saved_thread_name.empty())
            _set_name_thread_dbg(saved_thread_name);

        auto* loc = as_local(data);
        if (get_loc() != loc) {
            // Someone else took over the thread-local slot; nothing sane to do
            // but leave the storage alone.
            return;
        }

        // Drain anything still owned by this context back to the pool so the
        // tasks are not lost when the thread goes away.
        if (auto* pool = loc->owner_pool) {
            pool->registry.release(loc->registry_slot);
            loc->registry_slot = UINT32_MAX;

            {
                fast_task::unique_lock guard(glob.task_thread_safety);
                task_object* raw = nullptr;
                // Requeue without notifying: the single control-plane wake
                // below covers the whole drained batch.
                while (loc->local_tasks.pop(raw))
                    pool->ops.requeue(*pool, raw);
                if (loc->run_next) {
                    pool->ops.requeue(*pool, loc->run_next);
                    loc->run_next = nullptr;
                }
            }

            // Whatever was pushed back is work for the workers that remain --
            // including the null retire tokens this context may have
            // bulk-dequeued and never consumed. Nothing else will notify them,
            // so this has to be a control-plane wake: the surviving worker of a
            // closing pool must observe it or the pool never drains.
            //
            // The wake must happen *before* the counter drops to zero: the
            // close path waits for active_workers == 0 and then releases the
            // storage, so touching `pool` after the decrement would race with
            // its deletion (§2.17).
            wake_work_all(pool->work_event, pool->pool_index);
            pool->runtime.live_threads.fetch_sub(1, std::memory_order_acq_rel);
            pool->runtime.active_workers.fetch_sub(1, std::memory_order_acq_rel);
            glob.total_active_workers.fetch_sub(1, std::memory_order_acq_rel);
        }

        set_loc(nullptr);
        loc->owner_pool = nullptr;
        loc->reset();
        loc->~executors_local();
        glob.executor_shutdown_notifier.notify_all();
    }

    bool worker_context::is_shut_down() const noexcept {
        return glob.executor_shutting_down.load(std::memory_order_acquire) ||
               glob.shutdown_requested.load(std::memory_order_acquire);
    }

    namespace {
        // Pull one runnable task into loc->curr_task. Mirrors loadTask() but
        // works for every pool.
        bool fetch_one(executors_local* loc) {
            task_object* raw = nullptr;
            if (loc->local_tasks.pop(raw)) {
                loc->curr_task = task::adopt(raw);
                return true;
            }

            worker_pool_storage* pool = loc->owner_pool;
            if (!pool) {
                loc->curr_task = nullptr;
                return false;
            }

            // Take a batch in one go: popping a single task per visit would pay
            // the shared queue's producer/consumer handshake once per task
            // instead of once per batch (§6.5). The policy decides which queues
            // to drain, including the global pool's cold queue and its throttle.
            constexpr size_t BATCH_SIZE = 32;
            task_object* batch[BATCH_SIZE];
            const size_t count = pool->ops.dequeue_bulk(*pool, loc, batch, BATCH_SIZE);
            if (count != 0) {
                for (size_t i = 1; i < count; ++i)
                    if (!loc->local_tasks.emplace(batch[i]))
                        pool->ops.requeue(*pool, batch[i]);
                loc->curr_task = task::adopt(batch[0]);
                // Bulk-dequeue re-notify (§2.6): the rest of the batch is work
                // for the other workers and the publisher's single wake has
                // already been consumed. Without this, one woken worker drains
                // the queue while the pool's other workers sleep.
                if (count > 1)
                    wake_work(pool->work_event, pool->pool_index);
                return true;
            }

            if (try_steal_from_registry(pool->registry, raw)) {
                loc->curr_task = task::adopt(raw);
                return true;
            }

            loc->curr_task = nullptr;
            return false;
        }

        // Run up to `count` tasks. Returns how many were executed.
        //
        // A null task in the queue is the retire signal published by
        // reduce_executor()/close_bind_only_executor(): it is not work, it means
        // "this worker is no longer wanted". It is reported through
        // `retire_requested` so the caller can unwind instead of spinning on an
        // empty queue forever.
        size_t run_batch(executors_local* loc, size_t count, bool* retire_requested = nullptr) {
            size_t done = 0;
            while (done < count) {
                if (!fetch_one(loc))
                    break;
                if (!loc->curr_task) {
                    // Retire signal: stop serving. Do not count it as work.
                    if (retire_requested)
                        *retire_requested = true;
                    break;
                }
                // A task assigned to a different pool must be handed back.
                auto& task_data = get_data(loc->curr_task);
                if (task_data.get_pool_assigned() && task_data.pool_index != loc->pool_index) {
                    transfer_task(std::move(loc->curr_task));
                    continue;
                }
                execute_task("");
                ++done;
            }
            return done;
        }
    }

    size_t worker_context::poll(size_t count) {
        auto* loc = as_local(data);
        if (count == 0)
            return 0;

        // Entering the scheduler: from here until we return we are counted as
        // active, so request_stw() may wait for us. We never block in poll().
        stw_active_guard guard;
        check_stw();

        size_t done = run_batch(loc, count);

        // Opportunistically drive timers/I/O if nobody else is. The driver lock
        // is released as soon as the multiplexer returns: this thread goes back
        // to its host loop, and a parked driver (or the next poll) takes over.
        if (done < count && loc->options.allow_driver_polling) {
            if (try_claim_driver()) {
                std::unique_lock<fast_task::native::spin_lock> driver_guard(glob.driver.driver_lock, std::adopt_lock);
                glob.driver.poll(loc);
            }
            done += run_batch(loc, count - done);
        }
        return done;
    }

    size_t worker_context::poll_drained() {
        auto* loc = as_local(data);
        stw_active_guard guard;
        check_stw();

        // Drain everything that is already runnable. A retire signal stops the
        // drain: it is not work, and continuing would spin on an empty queue.
        bool retire = false;
        size_t total = run_batch(loc, SIZE_MAX, &retire);

        // Give the driver one chance to publish completions/timers, then drain
        // once more. Deliberately no retry loop: retrying would degenerate into
        // poll_all() and never hand control back.
        if (!retire && loc->options.allow_driver_polling && try_claim_driver()) {
            {
                std::unique_lock<fast_task::native::spin_lock> driver_guard(glob.driver.driver_lock, std::adopt_lock);
                glob.driver.poll(loc);
            }
            // Control returns to the host thread: leave somebody else driving.
            glob.driver.ensure_driver();
            total += run_batch(loc, SIZE_MAX);
        }
        return total;
    }

    size_t worker_context::poll_all() {
        auto* loc = as_local(data);
        stw_active_guard guard;
        check_stw();

        // Serve until the final shutdown phase, or until this worker is
        // retired. An empty queue is *not* a reason to return: this is the
        // permanent-worker entry point (and the body of both taskExecutor and
        // bindedTaskExecutor), so we park and wait for work instead of
        // unwinding.
        //
        // Deliberately NOT is_shut_down(): shutdown_requested means "flush the
        // timing wheel and drain the world", and shut_down()'s await_no_tasks()
        // depends on the workers continuing to run driver_context::poll() so
        // sleeping tasks are re-transferred. Only executor_shutting_down stops
        // this loop; a user pool worker is additionally stopped by the null
        // retire signal enqueued by close_bind_only_executor().
        worker_pool_storage* pool = loc->owner_pool;
        size_t total = 0;
        while (!glob.executor_shutting_down.load(std::memory_order_acquire)) {
            bool retire = false;
            size_t done = run_batch(loc, SIZE_MAX, &retire);
            total += done;
            if (retire) {
                break;
            }
            if (done != 0)
                continue;

            // Nothing runnable: try to become the driver.
            if (loc->options.allow_driver_polling && try_claim_driver()) {
                std::unique_lock<fast_task::native::spin_lock> driver_guard(glob.driver.driver_lock, std::adopt_lock);

                // Snapshot the handoff token and this pool's work epoch
                // *before* polling: a wake or an enqueue that lands while we
                // are busy here (new I/O, a task published by another thread, a
                // timer armed elsewhere) must not be swallowed by the park that
                // follows.
                uint32_t token = glob.driver.wake_token.load(std::memory_order_seq_cst);
                uint32_t work_epoch = work_event_of(*loc).current_epoch();

                // Re-check the queue *before* touching the multiplexer. A task
                // published between the run_batch() at the top of the loop and
                // this point is served directly; polling first would pay a
                // lock, a wheel scan and an io_uring syscall to discover it.
                // This is the common shape of a hot enqueue path (publish while
                // the only worker is between two batches), so it matters more
                // than it looks.
                bool retire_before_poll = false;
                if (run_batch(loc, SIZE_MAX, &retire_before_poll) != 0) {
                    // Deliberately no handoff() here. This worker keeps the
                    // loop: it releases the driver lock and re-enters the
                    // driver branch on the next iteration, so waking a
                    // candidate would only bump the work epoch under the feet
                    // of the very workers parked on it (and, on the enqueue
                    // path, once per batch -- which turned the park witness
                    // into permanent churn).
                    driver_guard.unlock();
                    continue;
                }
                if (retire_before_poll) {
                    // Leaving for good: somebody else has to drive.
                    driver_guard.unlock();
                    glob.driver.handoff();
                    break;
                }

                // The drain phase (shut_down() has set shutdown_requested) has
                // to flush the timing wheel on every iteration: poll() is what
                // turns a sleeping task into a runnable one, and await_no_tasks()
                // cannot do it itself while this worker holds the driver lock.
                // Without this the drain only ends when the furthest sleeper's
                // deadline passes, i.e. a task sleeping one second turns
                // shut_down() into a one-second wait.
                const bool drain = glob.shutdown_requested.load(std::memory_order_acquire);

                // Enter the multiplexer only when it has something to report
                // right now, i.e. a timer that has come due and must be turned
                // into runnable tasks. Everything else is served by the park
                // below: its timeout comes from the wheel, and poll_all() drains
                // completions (and dispatches them) before it returns, so an
                // I/O completion wakes us through the park just as well.
                //
                // Without this guard the idle path degenerates into a spin:
                // poll() (rwlock + wheel scan + io_uring_enter) -> nothing to
                // run -> park -> wake token/epoch moved by the very publish we
                // just handled -> poll() again, with no sleep in between.
                const bool timer_due = drain || glob.timed_wheel.next_deadline() <= fast_task::clock::now();
                if (timer_due)
                    glob.driver.poll(loc);

                bool retire_after_poll = false;
                if (run_batch(loc, SIZE_MAX, &retire_after_poll) != 0) {
                    // Same as above: the loop continues, so nobody needs a
                    // handoff wake.
                    driver_guard.unlock();
                    continue;
                }
                if (retire_after_poll) {
                    driver_guard.unlock();
                    glob.driver.handoff();
                    break;
                }

                // While draining, do not park: the wheel was just flushed and
                // whatever it released has been run above, so the next iteration
                // is exactly what a task still in flight needs. A park here
                // would wait for the wheel deadline that clear() has just
                // removed, i.e. sleep through the whole drain. This is a spin,
                // but a short one -- and the workers that do not hold the driver
                // already re-check shutdown_requested in their own wait
                // predicate, so the drain spins either way while it lasts.
                if (drain) {
                    driver_guard.unlock();
                    continue;
                }

                // Park as the driver until the next timer, the next I/O
                // completion or a wake from any other thread. There is no time
                // slice: the multiplexer timeout is derived from the timer
                // wheel, and wake_work()/wake_control() poke us when they
                // publish something this pool must react to.
                //
                // The STW-active slot must be released first: a parked driver
                // runs no user code, so request_stw() must not wait for it.
                guard.release();
                glob.driver.park_until(loc, fast_task::time_point::max(), token, work_epoch);
                guard.reacquire();
                driver_guard.unlock();
                continue;
            }

            if (!pool) {
                break;
            }

            // Someone else owns the driver, or this worker must not poll it.
            // The idle policy owns both halves of "wait": it looks for work
            // with the cheap witness and then sleeps on the pool's eventcount
            // until work, stop or a driver handoff (§2.7). S3a's busy_spin
            // replaces exactly this call, not the loop.
            guard.release();
            pool->ops.wait_until(*pool, loc, fast_task::time_point::max());
            guard.reacquire();
        }
        return total;
    }

    size_t worker_context::poll_until(fast_task::time_point time_point) {
        return poll_until(SIZE_MAX, time_point);
    }

    size_t worker_context::poll_until(size_t count, fast_task::time_point time_point) {
        auto* loc = as_local(data);
        if (count == 0)
            return 0;

        stw_active_guard guard;
        check_stw();

        worker_pool_storage* pool = loc->owner_pool;
        if (!pool)
            return 0;

        scheduler_event& work_event = pool->work_event;
        auto pred = [loc, pool] {
            return glob.executor_shutting_down.load(std::memory_order_acquire) ||
                   glob.shutdown_requested.load(std::memory_order_acquire) ||
                   has_runnable_work(loc, pool);
        };

        size_t done = run_batch(loc, count);
        while (done < count && !is_shut_down()) {
            if (fast_task::clock::now() >= time_point)
                break;

            // Give the driver one chance to publish timers/completions, then
            // hand it on: what follows is user code or a wait, and neither may
            // stall the multiplexer.
            if (loc->options.allow_driver_polling && glob.driver.driver_lock.try_lock()) {
                {
                    std::unique_lock<fast_task::native::spin_lock> driver_guard(glob.driver.driver_lock, std::adopt_lock);
                    glob.driver.poll(loc);
                }
                glob.driver.handoff();

                size_t more = run_batch(loc, count - done);
                done += more;
                if (done >= count)
                    break;
                if (more != 0)
                    continue;
            }

            guard.release();
            // Woken by the eventcount: either a task arrived (immediate) or the
            // capped deadline expired so the driver can be polled again.
            work_event.wait(pred, bounded_wait_deadline(time_point));
            guard.reacquire();

            done += run_batch(loc, count - done);
        }
        return done;
    }

    bool worker_context::next() {
        return poll(1) == 1;
    }

    bool worker_context::next_until(fast_task::time_point time_point) {
        auto* loc = as_local(data);

        // Fast path: something is already runnable.
        if (poll(1) == 1)
            return true;
        if (is_shut_down())
            return false;

        stw_active_guard guard;
        check_stw();

        worker_pool_storage* pool = loc->owner_pool;
        if (!pool)
            return false;

        scheduler_event& work_event = pool->work_event;
        auto pred = [loc, pool] {
            return glob.executor_shutting_down.load(std::memory_order_acquire) ||
                   glob.shutdown_requested.load(std::memory_order_acquire) ||
                   has_runnable_work(loc, pool);
        };

        while (!is_shut_down()) {
            if (fast_task::clock::now() >= time_point)
                break;

            // Publish timers/completions first so a task that became runnable
            // during our last wait is not slept through.
            if (loc->options.allow_driver_polling && glob.driver.driver_lock.try_lock()) {
                {
                    std::unique_lock<fast_task::native::spin_lock> driver_guard(glob.driver.driver_lock, std::adopt_lock);
                    glob.driver.poll(loc);
                }
                glob.driver.handoff();
                if (run_batch(loc, 1) == 1)
                    return true;
            }

            guard.release();
            work_event.wait(pred, bounded_wait_deadline(time_point));
            guard.reacquire();

            if (run_batch(loc, 1) == 1)
                return true;
        }

        return run_batch(loc, 1) == 1;
    }

}
