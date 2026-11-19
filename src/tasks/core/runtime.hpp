// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)
//
// Runtime layer: the global scheduler state, allocator caches, stop-the-world
// protocol and process-wide debug helpers. Split out of tasks/_internal.hpp by
// S0b (plans/pool-architecture.md §4) without behaviour changes.
//
// S2a (plans/pool-architecture.md §2.2) replaced `executor_global` with
// `scheduler_runtime`:
//
//   * `pools` is the flat storage pointer table (slot 255 is the global pool);
//   * the global pool owns a `worker_pool_storage` placement-new'ed into
//     `global_pool_storage`, so it keeps its own queues, eventcounts and
//     per-pool accounting instead of the removed globals;
//   * `global_registry` is the 1024-slot registry of the global pool;
//   * `completion_event` / `shutdown_event` are the aggregate eventcounts of
//     §2.8;
//   * the `binded_workers` map, the global `tasks`/`cold_tasks` queues and the
//     global `executing_tasks` / `in_run_tasks` / `executors` counters are gone.

#ifndef FAST_TASK_CORE_RUNTIME
#define FAST_TASK_CORE_RUNTIME

#include <array>
#include <atomic>
#include <concurrentqueue/moodycamel/concurrentqueue.h>
#include <cstddef>
#include <functional>
#include <string>

#include <fast_task/native/condition_variable.hpp>
#include <fast_task/native/mutex.hpp>
#include <fast_task/shared.hpp>
#include <fast_task/task.hpp>
#include <tasks/core/driver.hpp>
#include <tasks/core/event.hpp>
#include <tasks/core/pool.hpp>
#include <tasks/core/queue.hpp>
#include <tasks/core/worker.hpp>
#include <tasks/util/_dbg_macro.hpp>
#include <tasks/util/fixed_task_allocator.hpp>
#include <tasks/util/hashed_timing_wheel.hpp>
#include <tasks/util/macro.hpp>

namespace fast_task {
    namespace scheduler {
        class worker_pool; // plans/pool-architecture.md §2.3, declared fully in S2c
    }

    struct FT_API_LOCAL allocators_local_t {
        tl_task_alloc_cache task_cache;
        tl_timing_alloc_cache timing_cache;

        // Intrusive link in the registry of live thread-local allocator caches.
        allocators_local_t* registry_next = nullptr;

        allocators_local_t();
        void reset();
        ~allocators_local_t();

        // Returns every live cache's free list to the global allocators. Called
        // from scheduler_runtime::~scheduler_runtime() *before* alloc_globals_alive
        // is cleared, so the arena destructor's "still used" assert holds even
        // when a worker thread outlives the scheduler.
        static void drain_all();
    };

    // Set to false once the global allocator state (glob.gba / glob.timing_alloc)
    // has been destroyed. Thread-local caches consult this flag before returning
    // their free lists, so a thread that outlives static destruction never
    // touches a destroyed global.
    extern FT_API_LOCAL bool alloc_globals_alive;

    NOINLINE allocators_local_t& get_alloc_loc() noexcept;

    struct FT_API_LOCAL scheduler_runtime {
        timing_allocator timing_alloc;
        global_task_allocator gba;
        condition_variable_any no_tasks_execute_notifier;
        driver_context driver;

        // Pool storage table (§2.2). Slot 255 is the global pool. The table
        // stores the storage pointer, so routing is one atomic load and no
        // extra pointer chase. Slots 0..254 are allocated under `pools_safety`.
        std::array<std::atomic<worker_pool_storage*>, pool_table_size> pools;

        // Reserved storage of the global pool. It is placement-new'ed in the
        // constructor and destroyed in the destructor, so the global pool never
        // lives on the heap and never moves.
        alignas(64) std::byte global_pool_storage[worker_pool_storage_size];

        std::atomic<scheduler::worker_pool*> global_pool{nullptr};

        // First user pool with `allow_implicit_start` (§2.10 legacy auto-bind).
        // Cached so route_task() does not have to scan the 255-slot table on
        // every publish; refreshed by pool create/assign/close.
        std::atomic<worker_pool_storage*> implicit_pool{nullptr};

        // The global pool's registry. The global storage's inline
        // `entry.registry` is unused; its queue view points here instead.
        global_executor_registry global_registry;

        // Guards slot allocation/release in `pools`.
        fast_task::native::rw_mutex pools_safety;

        // Aggregate eventcounts (§2.8): a task completion that leaves a pool
        // idle notifies completion_event, the final shutdown phase notifies
        // shutdown_event.
        scheduler_event completion_event;
        scheduler_event shutdown_event;

        fast_task::native::condition_variable_any executor_shutdown_notifier;
        hashed_timing_wheel timed_wheel;

        fast_task::native::rw_mutex task_thread_safety;

        std::atomic<bool> time_control_enabled{false};
        std::atomic<bool> shutdown_requested{false};
        std::atomic<bool> executor_shutting_down{false};

        alignas(hardware_destructive_interference_size) std::atomic_size_t interrupts = 0; //debug counter of the usermode fast_task interrupts
    #ifndef NDEBUG
        alignas(hardware_destructive_interference_size) std::atomic_size_t tasks_in_swap = 0; //this means the tasks is stored outside the scheduler and excepted to be rescheduled later, ex. mutex
#endif

        std::atomic<bool> stw_request{false};
        std::atomic<size_t> thread_count{0}; //including native worker and timer

        // Sum of every live pool's active_workers. Kept because legacy call
        // sites (scheduler::start/schedule_until, shut_down) ask "is there any
        // executor?" on the task-publish path; walking the 256-slot table there
        // cost ~0.4 us per publish. O(1) now.
        std::atomic<size_t> total_active_workers{0};
        fast_task::native::mutex stw_mutex;

        // Number of workers currently *inside* a poll cycle (i.e. able to observe
        // stw_request). A worker that is parked in a blocking wait has released
        // its slot, so it can never be counted here and can never be waited on.
        // This is what makes STW deadlock-free: the STW waits for this counter
        // to drain, not for the set of live threads.
        std::atomic<size_t> stw_active_workers{0};
        // Dedicated mutex for stw_cv. It must NOT be task_thread_safety: the
        // worker loops call stw_active_guard::reacquire() while already holding
        // task_thread_safety, so waiting on that mutex would self-deadlock.
        fast_task::native::mutex stw_cv_mutex;
        fast_task::native::condition_variable_any stw_cv;

        futex_global_t futex_global;
        scheduler_runtime();
        ~scheduler_runtime();
    };

    extern FT_API_LOCAL scheduler_runtime glob;

    // The storage behind table slot `index`. A null result for a live index is
    // a lifetime violation (§2.10): the caller either abort()s or, on a
    // best-effort notification path, falls back to the global pool.
    inline worker_pool_storage* pool_for_index(uint8_t index) noexcept {
        return glob.pools[index].load(std::memory_order_acquire);
    }

    // The global pool's storage. It is constructed eagerly in the runtime
    // constructor and its slot therefore is never null.
    inline worker_pool_storage& global_storage() noexcept {
        return *glob.pools[global_pool_index].load(std::memory_order_acquire);
    }

    // Thread-local worker context accessors. Declared here as well because the
    // accounting helpers below are inline in this header and tasks/_internal.hpp
    // (which carries the canonical declaration) is included *after* it.
    NOINLINE executors_local* get_loc() noexcept;
    void set_loc(executors_local*) noexcept;

    // Task identity accounting helpers (§2.11). Every schedule path that
    // increments `executing_tasks` must have a matching decrement on completion
    // or abort; the helper below also assigns an unassigned task to the current
    // worker's pool (or global) so the increments and the decrements in
    // task_object::free() cannot land on different counters.
    inline worker_pool_storage& task_account_pool(task_object& t) noexcept {
        if (!t.get_pool_assigned()) {
            auto* loc = get_loc();
            t.pool_index = loc ? loc->pool_index : global_pool_index;
            t.set_pool_assigned(true);
        }
        auto* pool = pool_for_index(t.pool_index);
        return pool ? *pool : global_storage();
    }

    inline void task_mark_created(task_object& t) noexcept {
        task_account_pool(t).runtime.executing_tasks.fetch_add(1, std::memory_order_acq_rel);
    }

    // The worker's pool owns in_run_tasks, never the task's current pool: a
    // task that is being retargeted is still running on the old worker and the
    // old pool must stay non-idle until it yields (§2.11).
    inline void task_run_enter() noexcept {
        auto* loc = get_loc();
        if (loc && loc->owner_pool)
            loc->owner_pool->runtime.in_run_tasks.fetch_add(1, std::memory_order_acq_rel);
    }

    inline void task_run_exit() noexcept {
        auto* loc = get_loc();
        if (loc && loc->owner_pool)
            loc->owner_pool->runtime.in_run_tasks.fetch_sub(1, std::memory_order_acq_rel);
    }

    inline void task_mark_completed(task_object& t) noexcept {
        worker_pool_storage* pool = t.get_pool_assigned() ? pool_for_index(t.pool_index) : nullptr;
        if (!pool)
            pool = &global_storage();
        auto rem_old = pool->runtime.executing_tasks.fetch_sub(1, std::memory_order_acq_rel);
        assert(rem_old != 0 && "executing_tasks underflow");
        if (rem_old == 1) {
            glob.completion_event.notify_all();
            fast_task::shared_lock guard(glob.task_thread_safety);
            glob.no_tasks_execute_notifier.notify_all();
        }
    }

    // Enqueue notification (§2.8). One published task needs one worker, so the
    // single wake is a notify_one. A driver parked on this very pool is *not*
    // waiting on work_event -- it is asleep in the multiplexer holding
    // driver_lock -- so it has to be poked explicitly, otherwise a pool whose
    // only worker is the driver would not run the task until the next timer.
    inline void wake_work(scheduler_event& work_event, uint8_t pool_index) noexcept {
        // If a worker parked on the eventcount was woken it will pick the task
        // up, and no driver poke is needed. Only when nobody was parked does
        // the driver have to be considered: it waits in the multiplexer, not on
        // this event.
        if (work_event.notify_one())
            return;
        if (glob.driver.parked_pool.load(std::memory_order_seq_cst) == pool_index)
            glob.driver.wake();
    }

    // The eventcount a worker of `loc` waits on, and the one that has to
    // change for the worker to notice new work while it is parked as the
    // driver.
    inline scheduler_event& work_event_of(const executors_local& loc) noexcept {
        return loc.owner_pool ? loc.owner_pool->work_event : global_storage().work_event;
    }

    // Would a worker find something to run right now?
    //
    // Two flavours, both dispatched through the pool's policy table (§2.5):
    //
    //  * has_queued_work(): the cheap witness -- the hand-off slot, this
    //    worker's own deque and the shared queue. This is what the spin prober
    //    uses, because it must not touch every other worker's deque head on
    //    each iteration: those lines belong to the workers that are running,
    //    and dragging them out is what made a flat tight spin slow the
    //    publisher down (see the comment on the prober budget).
    //  * has_runnable_work(): the cheap witness *plus* every active local deque
    //    via the dense list, so a sleeping worker notices a backlog it could
    //    steal. Scans O(active workers), so it is only used where a missed wake
    //    would strand a task: the eventcount predicate and the driver's
    //    enqueue-versus-park witness.
    //
    // Both can over-report (a producer may have reserved a slot that is not
    // published yet); over-reporting costs a spurious wake that the real
    // dequeue resolves. Under-reporting cannot happen: the notifier's release
    // store is synchronised with these loads.
    inline bool has_queued_work(const executors_local* loc, const worker_pool_storage* pool) noexcept {
        if (!pool)
            pool = &global_storage();
        return pool->ops.has_queued_work(*pool, loc);
    }

    inline bool has_runnable_work(const executors_local* loc, const worker_pool_storage* pool) noexcept {
        if (!pool)
            pool = &global_storage();
        return pool->ops.has_runnable_work(*pool, loc);
    }

    // Shared idle-path helpers: the wait policy in pool_ops.cpp and the worker
    // loop in worker_context.cpp must agree on all three.
    inline bool scheduler_stopping() noexcept {
        return glob.executor_shutting_down.load(std::memory_order_acquire) ||
               glob.shutdown_requested.load(std::memory_order_acquire);
    }

    // A worker that may poll the driver must also wake up when the driver is
    // handed off. `claim_handoff` keeps a driver that merely releases the lock
    // between batches from waking every idle worker.
    inline bool driver_claimable(const executors_local* loc) noexcept {
        return loc->options.allow_driver_polling &&
               glob.driver.claim_handoff.load(std::memory_order_seq_cst) &&
               !glob.driver.driver_lock.is_locked();
    }

    // A pause instruction. The idle prober costs one atomic load per iteration,
    // so it has to stay in user space: sched_yield() would cost as much as the
    // futex park it is trying to avoid.
    inline void pool_cpu_relax() noexcept {
#if defined(__x86_64__) || defined(__i386__)
        __builtin_ia32_pause();
#elif defined(__aarch64__) || defined(__arm__)
        asm volatile("yield" ::: "memory");
#else
        std::atomic_signal_fence(std::memory_order_seq_cst);
#endif
    }

    // Same, for a batch of published tasks: one wake per task would leave
    // all but one of them queued behind a single woken worker.
    inline void wake_work_all(scheduler_event& work_event, uint8_t pool_index) noexcept {
        work_event.notify_all();
        if (glob.driver.parked_pool.load(std::memory_order_seq_cst) == pool_index)
            glob.driver.wake();
    }

    // Control-plane notification (§2.8): shutdown, pause/resume and pool close
    // must reach every worker of the pool *and* the driver.
    inline void wake_control(scheduler_event& work_event, scheduler_event& dormant_event) noexcept {
        work_event.notify_all();
        dormant_event.notify_all();
        glob.driver.wake();
    }

    constexpr size_t native_thread_flag = size_t(1) << (sizeof(size_t) * 8 - 2);
    constexpr size_t native_thread_data = size_t(1) << (sizeof(size_t) * 8 - 1);
    constexpr size_t native_thread_mask = ~(size_t(3) << (sizeof(size_t) * 8 - 2));

    // RAII slot for "this worker is inside a poll cycle and will observe
    // stw_request". Every blocking wait must release() before sleeping and
    // reacquire() after waking, otherwise a parked worker would be counted as
    // active and the STW would wait for a thread that is asleep.
    //
    // The STW is a simple quiescence protocol, not a barrier:
    //   * A worker increments stw_active_workers, then re-checks stw_request.
    //     If a request appeared it decrements again and waits on stw_cv until
    //     the request clears. It never runs user code while a request is set.
    //   * The STW sets stw_request, then waits on stw_cv until
    //     stw_active_workers reaches zero. Every worker that was active when
    //     the request was set will observe it (its re-check follows its
    //     increment) and decrement, waking the STW.
    //   * A worker that increments after the request was set sees the request
    //     immediately and backs out, so it never delays the STW.
    // There is no barrier to size, so there is nothing to over- or
    // under-arrive: the STW simply waits for the counter to drain.
    struct FT_API_LOCAL stw_active_guard {
        bool held = false;

        stw_active_guard() {
            reacquire();
        }

        ~stw_active_guard() {
            if (held)
                release();
        }

        stw_active_guard(const stw_active_guard&) = delete;
        stw_active_guard& operator=(const stw_active_guard&) = delete;

        // Enter the active set, waiting out any in-flight STW first.
        //
        // The wait uses stw_cv_mutex, never task_thread_safety: callers such as
        // taskExecutor invoke reacquire() while already holding
        // task_thread_safety, so waiting on that mutex would self-deadlock.
        void reacquire() {
            if (held)
                return;
            for (;;) {
                glob.stw_active_workers.fetch_add(1, std::memory_order_acq_rel);
                if (!glob.stw_request.load(std::memory_order_acquire)) {
                    held = true;
                    return;
                }
                // An STW is in progress. Back out so it can drain, then wait
                // for it to finish before retrying.
                glob.stw_active_workers.fetch_sub(1, std::memory_order_acq_rel);
                glob.stw_cv.notify_all();
                fast_task::unique_lock guard(glob.stw_cv_mutex);
                while (glob.stw_request.load(std::memory_order_acquire))
                    glob.stw_cv.wait(guard);
            }
        }

        // Leave the active set. Must be called before any blocking wait.
        void release() {
            if (!held)
                return;
            held = false;
            glob.stw_active_workers.fetch_sub(1, std::memory_order_acq_rel);
            glob.stw_cv.notify_all();
        }
    };

    inline void FT_API_LOCAL unsafe_perform_stop_the_world(const std::function<void()>& work) {
        std::lock_guard lock(glob.stw_mutex);
        // Publish the request first: any worker that increments afterwards
        // will see it and back out, and any worker that incremented before
        // will see it on its re-check and decrement.
        glob.stw_request.store(true, std::memory_order_seq_cst);
        wake_control(global_storage().work_event, global_storage().dormant_event);

        // Wait for every worker that is currently inside a poll cycle to
        // leave it. Workers parked in a blocking wait have already released
        // their slot, so they cannot delay us.
        {
            fast_task::unique_lock guard(glob.stw_cv_mutex);
            while (glob.stw_active_workers.load(std::memory_order_seq_cst) != 0)
                glob.stw_cv.wait(guard);
        }

        work(); // Execute the dump with the world stopped

        glob.stw_request.store(false, std::memory_order_seq_cst);
        glob.stw_cv.notify_all(); // Release workers blocked in reacquire()
    }

    // Kept for source compatibility with the worker loops. Quiescence is now
    // handled entirely by stw_active_guard: a worker that holds a slot is
    // already counted, and the STW waits for the counter to drain. There is
    // nothing left to check here.
    template <class Mut>
    void FT_API_LOCAL check_stw(Mut&) {}

    inline void FT_API_LOCAL check_stw() {}

    bool FT_API_LOCAL _set_name_thread_dbg(const std::string& name, unsigned long thread_id);
    bool FT_API_LOCAL _set_name_thread_dbg(const std::string& name);
    std::string FT_API_LOCAL _get_name_thread_dbg(unsigned long thread_id);
    unsigned long FT_API_LOCAL _thread_id();
    bool FT_API_LOCAL is_debugger_attached();

    FT_DEBUG_ONLY(void FT_API_LOCAL register_object(mutex*));
    FT_DEBUG_ONLY(void FT_API_LOCAL register_object(recursive_mutex*));
    FT_DEBUG_ONLY(void FT_API_LOCAL register_object(rw_mutex*));
    FT_DEBUG_ONLY(void FT_API_LOCAL register_object(condition_variable*));
    FT_DEBUG_ONLY(void FT_API_LOCAL register_object(task_object*));
    FT_DEBUG_ONLY(void FT_API_LOCAL register_object(semaphore*));
    FT_DEBUG_ONLY(void FT_API_LOCAL register_object(limiter*));
    FT_DEBUG_ONLY(void FT_API_LOCAL register_object(queue*));
    FT_DEBUG_ONLY(void FT_API_LOCAL register_object(deadline_timer*));

    FT_DEBUG_ONLY(void FT_API_LOCAL unregister_object(mutex*));
    FT_DEBUG_ONLY(void FT_API_LOCAL unregister_object(recursive_mutex*));
    FT_DEBUG_ONLY(void FT_API_LOCAL unregister_object(rw_mutex*));
    FT_DEBUG_ONLY(void FT_API_LOCAL unregister_object(condition_variable*));
    FT_DEBUG_ONLY(void FT_API_LOCAL unregister_object(task_object*));
    FT_DEBUG_ONLY(void FT_API_LOCAL unregister_object(semaphore*));
    FT_DEBUG_ONLY(void FT_API_LOCAL unregister_object(limiter*));
    FT_DEBUG_ONLY(void FT_API_LOCAL unregister_object(queue*));
    FT_DEBUG_ONLY(void FT_API_LOCAL unregister_object(deadline_timer*));
}

#endif /* FAST_TASK_CORE_RUNTIME */
