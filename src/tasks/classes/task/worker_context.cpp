// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <new>

#include <tasks/_internal.hpp>
#include <tasks/util/cpu_topology.hpp>
#include <tasks/util/native_workers_singleton.hpp>

namespace fast_task::scheduler {

    worker_context_impl& worker_context_impl::of(worker_context& ctx) noexcept {
        static_assert(sizeof(worker_context_impl) <= 1024, "worker_context_impl must fit into worker_context");
        static_assert(alignof(worker_context_impl) <= 64, "worker_context_impl alignment must fit into worker_context");
        return *std::launder(reinterpret_cast<worker_context_impl*>(ctx.data));
    }

    namespace {
        inline bool try_claim_driver() noexcept {
            if (!glob.driver.driver_lock.try_lock())
                return false;
            glob.driver.claim_handoff.store(false, std::memory_order_relaxed);
            return true;
        }

        fast_task::time_point bounded_wait_deadline(fast_task::time_point limit) noexcept {
            if (glob.timing.enabled.load(std::memory_order_acquire)) {
                auto next = glob.timing.wheel.next_deadline();
                return next < limit ? next : limit;
            }
            auto backstop = fast_task::clock::now() + std::chrono::milliseconds(10);
            return backstop < limit ? backstop : limit;
        }

        bool runnable_or_shutting_down(const executors_local* loc, const worker_pool_storage* home) noexcept {
            return glob.shutdown.executors_down.load(std::memory_order_acquire) ||
                   glob.shutdown.requested.load(std::memory_order_acquire) ||
                   has_runnable_work(home, loc);
        }

        bool poll_driver_once(executors_local* loc) {
            if (!loc->options.allow_driver_polling || !glob.driver.driver_lock.try_lock())
                return false;
            {
                std::unique_lock<fast_task::native::spin_lock> driver_guard(glob.driver.driver_lock, std::adopt_lock);
                glob.driver.poll(loc);
            }
            glob.driver.handoff();
            return true;
        }

        void name_joined_worker(std::string& saved, const worker_pool_storage& pool) {
            saved = _get_name_thread_dbg(_thread_id());
            if (pool.is_global)
                _set_name_thread_dbg("fast_task worker");
            else
                _set_name_thread_dbg("pool " + std::to_string(pool.pool_index) + " worker");
        }
    }

    void worker_context_impl::join(worker_pool_storage& target, bool is_spawned, bool count_live) {
        if (joined)
            throw std::logic_error("worker_context is already joined to a pool");
        if (get_loc() != nullptr)
            throw std::logic_error("Current thread already has a joined worker_context");
        if (!is_spawned && (target.closing || target.runtime.stop_requested.load(std::memory_order_acquire)))
            throw std::logic_error("Cannot join a worker pool that is stopping");

        local.owner_pool = &target;
        local.pool_index = target.pool_index;
        local.host_context = owner;
        local.llc_id = util::current_llc();
        local.registry_slot = target.ops.executors.claim(target, &local.local_tasks, local.llc_id);
        joined = true;
        spawned = is_spawned;

        const bool name = is_spawned ? !target.config.prevent_thread_naming
                                     : !local.options.prevent_thread_naming;
        if (name)
            name_joined_worker(saved_thread_name, target);

        target.threads.attach(is_spawned, count_live);
        set_loc(&local);
    }

    void worker_context_impl::leave(bool count_live, bool count_active) noexcept {
        if (!joined)
            return;
        joined = false;
        const bool was_spawned = spawned;
        spawned = false;

        if (!saved_thread_name.empty()) {
            _set_name_thread_dbg(saved_thread_name);
            saved_thread_name.clear();
        }

        worker_pool_storage* home = local.owner_pool;
        if (!home) {
            if (get_loc() == &local)
                set_loc(nullptr);
            local.host_context = nullptr;
            return;
        }

        flush_completed_batch(local, home);
        flush_executing_batch(local, home);

        clear_local_nonempty(&local, *home);
        home->ops.executors.release(*home, local.registry_slot);
        local.registry_slot = UINT32_MAX;
        {
            fast_task::unique_lock guard(glob.no_tasks.guard);
            task_object* raw = nullptr;
            while (local.local_tasks.pop(raw))
                home->ops.queue.requeue(*home, raw);
            if (local.run_next) {
                home->ops.queue.requeue(*home, local.run_next);
                local.run_next = nullptr;
            }
        }

        wake_work_all(*home);
        home->threads.detach(was_spawned, count_live, count_active);

        if (get_loc() == &local)
            set_loc(nullptr);
        local.owner_pool = nullptr;
        local.host_context = nullptr;
        local.reset();
        glob.shutdown.notifier.notify_all();
    }

    bool worker_context_impl::shutting_down() const noexcept {
        if (joined) {
            if (const auto* home = local.owner_pool)
                if (home->runtime.stop_requested.load(std::memory_order_acquire) || home->closing)
                    return true;
        }
        return glob.shutdown.executors_down.load(std::memory_order_acquire) ||
               glob.shutdown.requested.load(std::memory_order_acquire);
    }

    namespace {
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
            clear_local_nonempty(loc, *pool);

            constexpr size_t BATCH_SIZE = 32;
            task_object* batch[BATCH_SIZE];
            const size_t count = pool->ops.queue.dequeue_bulk(*pool, loc, batch, BATCH_SIZE);
            if (count != 0) {
                for (size_t i = 1; i < count; ++i)
                    if (!loc->local_tasks.emplace(batch[i]))
                        pool->ops.queue.requeue(*pool, batch[i]);
                if (count > 1)
                    mark_local_nonempty(loc, *pool);
                loc->curr_task = task::adopt(batch[0]);
                if (count > 1) {
                    pool->work_event.clear_pending();
                    wake_work(*pool);
                }
                return true;
            }

            if (pool->ops.queue.steal(*pool, loc, raw)) {
                loc->curr_task = task::adopt(raw);
                return true;
            }

            loc->curr_task = nullptr;
            return false;
        }

        size_t run_batch(executors_local* loc, size_t count, bool* retire_requested = nullptr) {
            size_t done = 0;
            while (done < count) {
                if (!fetch_one(loc))
                    break;
                if (!loc->curr_task) {
                    if (retire_requested)
                        *retire_requested = true;
                    break;
                }
                auto& task_data = get_data(loc->curr_task);
                if (task_data.get_pool_assigned() && task_data.pool_index != loc->pool_index) {
                    transfer_task(std::move(loc->curr_task));
                    continue;
                }
                execute_task();
                ++done;
            }
            flush_completed_batch(*loc, loc->owner_pool);
            flush_executing_batch(*loc, loc->owner_pool);
            if (loc->owner_pool && loc->owner_pool->work_event.clear_pending() &&
                has_queued_work(loc->owner_pool, loc))
                loc->owner_pool->work_event.notify_one();
            return done;
        }

        void pause_service(worker_pool_storage& pool, executors_local* loc, stw_active_guard& guard) {
            if (loc->options.allow_driver_polling && try_claim_driver()) {
                std::unique_lock<fast_task::native::spin_lock> driver_guard(glob.driver.driver_lock, std::adopt_lock);
                const uint32_t token = glob.driver.wake_token.load(std::memory_order_seq_cst);
                if (glob.timing.wheel.next_deadline() <= fast_task::clock::now())
                    glob.driver.poll(nullptr);
                guard.release();
                glob.driver.park_until(nullptr, fast_task::clock::now() + std::chrono::milliseconds(10), token, 0);
                guard.reacquire();
                check_stw();
                driver_guard.unlock();
                glob.driver.handoff();
                return;
            }

            guard.release();
            pool.dormant_event.wait(
                [&pool] {
                    return !pool.runtime.paused.load(std::memory_order_acquire) ||
                           pool.runtime.stop_requested.load(std::memory_order_acquire) ||
                           glob.shutdown.executors_down.load(std::memory_order_acquire);
                },
                fast_task::time_point::max()
            );
            guard.reacquire();
        }

        inline bool dormant_should_exit(worker_pool_storage& home) noexcept {
            return glob.shutdown.executors_down.load(std::memory_order_acquire) ||
                   home.closing ||
                   home.runtime.stop_requested.load(std::memory_order_acquire);
        }

        inline bool dormant_home_wants(worker_pool_storage& home) noexcept {
            return home.threads.wants_worker() || home.ops.queue.has_runnable_work(home, nullptr);
        }

        void serve_dormant_lease(worker_context_impl& impl, worker_pool_storage& home, worker_pool_storage& borrower, executors_local* loc) {
            try {
                impl.join(borrower, true, true);
            } catch (...) {
                return_dormant_lease(home, borrower);
                return;
            }
            constexpr size_t lease_batch = 32;
            run_batch(loc, lease_batch);
            impl.leave(true, true);
            return_dormant_lease(home, borrower);
        }

        bool dormant_service(worker_context_impl& impl, worker_pool_storage& home, executors_local* loc, stw_active_guard& guard) {
            impl.leave(false, false);
            bool exit_thread = false;
            for (;;) {
                if (dormant_should_exit(home)) {
                    exit_thread = true;
                    break;
                }
                if (worker_pool_storage* borrower = take_dormant_lease(home)) {
                    serve_dormant_lease(impl, home, *borrower, loc);
                    continue;
                }
                if (dormant_home_wants(home))
                    break;
                guard.release();
                home.dormant_event.wait(
                    [&home] {
                        return dormant_should_exit(home) || dormant_home_wants(home) ||
                               home.threads.pending_leases() != 0;
                    },
                    fast_task::time_point::max()
                );
                guard.reacquire();
            }
            if (!exit_thread) {
                try {
                    impl.join(home, true, false);
                } catch (...) {
                    exit_thread = true;
                }
            }
            if (exit_thread)
                home.threads.detach_live();

            home.threads.unpark();
            return exit_thread;
        }
    }

    size_t worker_context_impl::poll(size_t count) {
        if (!joined)
            throw std::logic_error("worker_context is not joined to a pool");
        if (count == 0)
            return 0;

        stw_active_guard guard;
        check_stw();

        size_t done = run_batch(&local, count);

        if (done < count && local.options.allow_driver_polling) {
            if (try_claim_driver()) {
                std::unique_lock<fast_task::native::spin_lock> driver_guard(glob.driver.driver_lock, std::adopt_lock);
                glob.driver.poll(&local);
            }
            done += run_batch(&local, count - done);
        }
        return done;
    }

    size_t worker_context_impl::poll_drained() {
        if (!joined)
            throw std::logic_error("worker_context is not joined to a pool");

        stw_active_guard guard;
        check_stw();

        bool retire = false;
        size_t total = run_batch(&local, SIZE_MAX, &retire);

        if (!retire && local.options.allow_driver_polling && try_claim_driver()) {
            {
                std::unique_lock<fast_task::native::spin_lock> driver_guard(glob.driver.driver_lock, std::adopt_lock);
                glob.driver.poll(&local);
            }
            glob.driver.ensure_driver();
            total += run_batch(&local, SIZE_MAX);
        }
        return total;
    }

    size_t worker_context_impl::poll_all() {
        if (!joined)
            throw std::logic_error("worker_context is not joined to a pool");

        struct serving_guard {
            serving_guard() noexcept {
                glob.stw.serving_contexts.fetch_add(1, std::memory_order_acq_rel);
            }

            ~serving_guard() noexcept {
                glob.stw.serving_contexts.fetch_sub(1, std::memory_order_acq_rel);
            }
        } serving;

        stw_active_guard guard;
        check_stw();

        worker_pool_storage* home = local.owner_pool;
        size_t total = 0;
        while (!glob.shutdown.executors_down.load(std::memory_order_acquire)) {
            if (home && home->runtime.paused.load(std::memory_order_acquire)) {
                pause_service(*home, &local, guard);
                continue;
            }

            if (home)
                home->ops.balancer.run(*home);

            if (home && claim_dormant_slot(*home, spawned)) {
                if (dormant_service(*this, *home, &local, guard))
                    break;
                continue;
            }

            bool retire = false;
            size_t done = run_batch(&local, SIZE_MAX, &retire);
            total += done;
            if (retire)
                break;
            if (done != 0)
                continue;

            if (home && home->runtime.stop_requested.load(std::memory_order_acquire)) {
                glob.driver.handoff();
                break;
            }

            if (local.options.allow_driver_polling && try_claim_driver()) {
                std::unique_lock<fast_task::native::spin_lock> driver_guard(glob.driver.driver_lock, std::adopt_lock);

                uint32_t token = glob.driver.wake_token.load(std::memory_order_seq_cst);
                uint32_t work_epoch = work_event_of(local).current_epoch();

                bool retire_before_poll = false;
                const size_t ran_before_poll = run_batch(&local, SIZE_MAX, &retire_before_poll);
                if (retire_before_poll) {
                    driver_guard.unlock();
                    glob.driver.handoff();
                    break;
                }
                if (ran_before_poll != 0) {
                    driver_guard.unlock();
                    continue;
                }

                const bool drain = glob.shutdown.requested.load(std::memory_order_acquire);

                const bool timer_due = drain || glob.timing.wheel.next_deadline() <= fast_task::clock::now();
                if (timer_due || util::native_workers_singleton::has_ready_work())
                    glob.driver.poll(&local);

                bool retire_after_poll = false;
                const size_t ran_after_poll = run_batch(&local, SIZE_MAX, &retire_after_poll);
                if (retire_after_poll) {
                    driver_guard.unlock();
                    glob.driver.handoff();
                    break;
                }
                if (ran_after_poll != 0) {
                    driver_guard.unlock();
                    continue;
                }

                if (drain) {
                    driver_guard.unlock();
                    continue;
                }

                guard.release();
                glob.driver.park_until(&local, fast_task::time_point::max(), token, work_epoch);
                guard.reacquire();
                driver_guard.unlock();
                continue;
            }

            if (!home)
                break;

            guard.release();
            home->ops.queue.wait_until(*home, &local, fast_task::time_point::max());
            guard.reacquire();
        }
        return total;
    }

    size_t worker_context_impl::poll_until(size_t count, fast_task::time_point time_point) {
        if (!joined)
            throw std::logic_error("worker_context is not joined to a pool");
        if (count == 0)
            return 0;

        stw_active_guard guard;
        check_stw();

        worker_pool_storage* home = local.owner_pool;
        if (!home)
            return 0;

        scheduler_event& work_event = home->work_event;
        auto pred = [this, home] {
            return runnable_or_shutting_down(&local, home);
        };

        size_t done = run_batch(&local, count);
        while (done < count && !shutting_down()) {
            if (fast_task::clock::now() >= time_point)
                break;

            if (poll_driver_once(&local)) {
                size_t more = run_batch(&local, count - done);
                done += more;
                if (done >= count)
                    break;
                if (more != 0)
                    continue;
            }

            guard.release();
            work_event.wait(pred, bounded_wait_deadline(time_point));
            guard.reacquire();

            done += run_batch(&local, count - done);
        }
        return done;
    }

    bool worker_context_impl::next_until(fast_task::time_point time_point) {
        if (!joined)
            throw std::logic_error("worker_context is not joined to a pool");

        if (poll(1) == 1)
            return true;
        if (shutting_down())
            return false;

        stw_active_guard guard;
        check_stw();

        worker_pool_storage* home = local.owner_pool;
        if (!home)
            return false;

        scheduler_event& work_event = home->work_event;
        auto pred = [this, home] {
            return runnable_or_shutting_down(&local, home);
        };

        while (!shutting_down()) {
            if (fast_task::clock::now() >= time_point)
                break;

            if (poll_driver_once(&local) && run_batch(&local, 1) == 1)
                return true;

            guard.release();
            work_event.wait(pred, bounded_wait_deadline(time_point));
            guard.reacquire();

            if (run_batch(&local, 1) == 1)
                return true;
        }

        return run_batch(&local, 1) == 1;
    }

    worker_context::worker_context(worker_context_options options) {
        auto* impl = ::new (static_cast<void*>(data)) worker_context_impl();
        impl->owner = this;
        impl->local.options = options;
    }

    worker_context::~worker_context() {
        auto* impl = &worker_context_impl::of(*this);
        if (impl->joined)
            impl->leave(true, true);
        else if (get_loc() == &impl->local)
            set_loc(nullptr);
        impl->~worker_context_impl();
    }

    bool worker_context::is_joined() const noexcept {
        return worker_context_impl::of(const_cast<worker_context&>(*this)).joined;
    }

    bool worker_context::is_shut_down() const noexcept {
        return worker_context_impl::of(const_cast<worker_context&>(*this)).shutting_down();
    }

    size_t worker_context::poll(size_t count) {
        return worker_context_impl::of(*this).poll(count);
    }

    size_t worker_context::poll_drained() {
        return worker_context_impl::of(*this).poll_drained();
    }

    size_t worker_context::poll_all() {
        return worker_context_impl::of(*this).poll_all();
    }

    size_t worker_context::poll_until(fast_task::time_point time_point) {
        return worker_context_impl::of(*this).poll_until(SIZE_MAX, time_point);
    }

    size_t worker_context::poll_until(size_t count, fast_task::time_point time_point) {
        return worker_context_impl::of(*this).poll_until(count, time_point);
    }

    bool worker_context::next() {
        return worker_context_impl::of(*this).poll(1) == 1;
    }

    bool worker_context::next_until(fast_task::time_point time_point) {
        return worker_context_impl::of(*this).next_until(time_point);
    }
}
