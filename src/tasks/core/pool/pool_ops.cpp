// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <thread>

#include <tasks/_internal.hpp>

namespace fast_task {
    namespace {
        template <class StorageT>
        StorageT& storage_as(worker_pool_storage& pool) noexcept {
            return static_cast<StorageT&>(pool);
        }

        template <class StorageT>
        const StorageT& storage_as(const worker_pool_storage& pool) noexcept {
            return static_cast<const StorageT&>(pool);
        }

        template <class StorageT>
        auto& executor_registry_of(const worker_pool_storage& base) noexcept {
            if constexpr (StorageT::uses_global_registry)
                return glob.pools.registry;
            else
                return const_cast<StorageT&>(storage_as<StorageT>(base)).registry_data;
        }

        template <class StorageT>
        uint32_t exec_claim(worker_pool_storage& base, work_stealing_deque<task_object*>* deque, uint8_t llc) noexcept {
            return executor_registry_of<StorageT>(base).claim(deque, llc);
        }

        template <class StorageT>
        void exec_release(worker_pool_storage& base, uint32_t idx) noexcept {
            executor_registry_of<StorageT>(base).release(idx);
        }

        template <class StorageT>
        void exec_store_flags(worker_pool_storage& base, uint32_t idx, uint8_t flags) noexcept {
            executor_registry_of<StorageT>(base).store_slot_flags(idx, flags);
        }

        template <class StorageT>
        uint32_t exec_active(const worker_pool_storage& base) noexcept {
            return executor_registry_of<StorageT>(base).active();
        }

        template <class StorageT>
        bool exec_any_work(const worker_pool_storage& base) noexcept {
            return executor_registry_of<StorageT>(base).any_work();
        }

        inline bool pool_accepts_wake(const worker_pool_storage& pool) noexcept {
            return !pool.runtime.paused.load(std::memory_order_relaxed);
        }

        inline void pool_wake_dormant(worker_pool_storage& pool) noexcept {
            if (pool.threads.dormant() != 0)
                pool.dormant_event.notify_one();
        }

        inline void pool_wake_work(worker_pool_storage& pool) noexcept {
            wake_work(pool);
            pool_wake_dormant(pool);
        }

        template <class StorageT>
        bool ws_enqueue(worker_pool_storage& base, executors_local* loc, task_object* raw) noexcept {
            auto& pool = storage_as<StorageT>(base);

            if (!raw) {
                pool.queue_data.tasks.enqueue(nullptr);
                if (pool_accepts_wake(pool))
                    pool_wake_work(pool);
                return true;
            }

            const bool self_publish = loc && loc->curr_task && &get_data(loc->curr_task) == raw;
            if (!self_publish && loc && loc->owner_pool == &base && loc->local_tasks.emplace(raw)) {
                if (loc->local_tasks.size() > 1 && pool_accepts_wake(pool))
                    pool_wake_work(pool);
                mark_local_nonempty(loc, base);
                return true;
            }

            if (pool.is_global && !can_be_scheduled_task_to_hot())
                pool.queue_data.cold_tasks.enqueue(raw);
            else
                pool.queue_data.tasks.enqueue(raw);
            if (pool_accepts_wake(pool))
                pool_wake_work(pool);
            return false;
        }

        template <class StorageT>
        bool ws_requeue(worker_pool_storage& base, task_object* raw) noexcept {
            storage_as<StorageT>(base).queue_data.tasks.enqueue(raw);
            return true;
        }

        template <class StorageT>
        bool ws_enqueue_cold(worker_pool_storage& base, task_object* raw) noexcept {
            storage_as<StorageT>(base).queue_data.cold_tasks.enqueue(raw);
            return true;
        }

        template <class StorageT>
        size_t ws_dequeue_bulk(worker_pool_storage& base, executors_local* loc, task_object** out, size_t max) noexcept {
            auto& pool = storage_as<StorageT>(base);
            size_t count = pool.queue_data.tasks.try_dequeue_bulk(out, max);
            if (count == 0 && pool.is_global && can_be_scheduled_task_to_hot())
                count = pool.queue_data.cold_tasks.try_dequeue_bulk(out, max);
            (void)loc;
            return count;
        }

        template <class StorageT>
        bool ws_has_queued_work(const worker_pool_storage& base, const executors_local* loc) noexcept {
            if (loc) {
                if (loc->run_next != nullptr)
                    return true;
                if (loc->local_tasks.size() != 0)
                    return true;
            }
            const auto& pool = storage_as<StorageT>(base);
            if (pool.queue_data.tasks.size_approx() != 0)
                return true;
            if (pool.is_global && pool.queue_data.cold_tasks.size_approx() != 0 && can_be_scheduled_task_to_hot())
                return true;
            return false;
        }

        template <class StorageT>
        bool ws_has_runnable_work(const worker_pool_storage& base, const executors_local* loc) noexcept {
            if (ws_has_queued_work<StorageT>(base, loc))
                return true;
            return executor_registry_of<StorageT>(base).any_work();
        }

        inline size_t priority_index(task_object* raw) noexcept {
            const size_t idx = static_cast<size_t>(raw->get_priority());
            return idx < priority_level_count ? idx : priority_level_count - 1;
        }

        template <class StorageT>
        bool pf_enqueue(worker_pool_storage& base, executors_local* loc, task_object* raw) noexcept {
            auto& pool = storage_as<StorageT>(base);
            (void)loc;

            if (!raw) {
                pool.queue_data.tasks[priority_level_count - 1].enqueue(nullptr);
                if (pool_accepts_wake(pool))
                    pool_wake_work(pool);
                return false;
            }

            if (pool.is_global && !can_be_scheduled_task_to_hot())
                pool.queue_data.cold_tasks.enqueue(raw);
            else
                pool.queue_data.tasks[priority_index(raw)].enqueue(raw);
            if (pool_accepts_wake(pool))
                pool_wake_work(pool);
            return false;
        }

        template <class StorageT>
        bool pf_requeue(worker_pool_storage& base, task_object* raw) noexcept {
            auto& pool = storage_as<StorageT>(base);
            if (!raw)
                pool.queue_data.tasks[priority_level_count - 1].enqueue(nullptr);
            else
                pool.queue_data.tasks[priority_index(raw)].enqueue(raw);
            return true;
        }

        template <class StorageT>
        bool pf_enqueue_cold(worker_pool_storage& base, task_object* raw) noexcept {
            storage_as<StorageT>(base).queue_data.cold_tasks.enqueue(raw);
            return true;
        }

        template <class StorageT>
        size_t pf_dequeue_bulk(worker_pool_storage& base, executors_local* loc, task_object** out, size_t max) noexcept {
            auto& pool = storage_as<StorageT>(base);
            (void)loc;
            if (max == 0)
                return 0;
            for (size_t level = priority_level_count; level-- > 0;) {
                task_object* raw = nullptr;
                if (pool.queue_data.tasks[level].try_dequeue(raw)) {
                    out[0] = raw;
                    return 1;
                }
            }
            if (pool.is_global && can_be_scheduled_task_to_hot()) {
                task_object* raw = nullptr;
                if (pool.queue_data.cold_tasks.try_dequeue(raw)) {
                    out[0] = raw;
                    return 1;
                }
            }
            return 0;
        }

        template <class StorageT>
        bool pf_has_queued_work(const worker_pool_storage& base, const executors_local* loc) noexcept {
            if (loc) {
                if (loc->run_next != nullptr)
                    return true;
                if (loc->local_tasks.size() != 0)
                    return true;
            }
            const auto& pool = storage_as<StorageT>(base);
            for (size_t level = 0; level < priority_level_count; ++level) {
                if (pool.queue_data.tasks[level].size_approx() != 0)
                    return true;
            }
            if (pool.is_global && pool.queue_data.cold_tasks.size_approx() != 0 && can_be_scheduled_task_to_hot())
                return true;
            return false;
        }

        template <class StorageT>
        bool pf_has_runnable_work(const worker_pool_storage& base, const executors_local* loc) noexcept {
            return pf_has_queued_work<StorageT>(base, loc);
        }

        constexpr unsigned spin_budget = 8192;
        constexpr unsigned spin_interval_cap = 1024;

        inline uint16_t max_spinners(const worker_pool_storage& pool) noexcept {
            const uint16_t live = pool.threads.live();
            return live <= 1 ? 1 : 2;
        }

        template <bool (*HasQueued)(const worker_pool_storage&, const executors_local*) noexcept>
        inline bool spin_before_park(worker_pool_storage& pool, executors_local* loc) noexcept {
            scheduler_event& work_event = pool.work_event;
            spinner_ticket ticket(work_event.line());
            if (!ticket.try_acquire(max_spinners(pool)))
                return false;

            const uint32_t epoch = work_event.current_epoch();
            unsigned budget = spin_budget;
            unsigned pause = 32;
            bool found = false;
            while (budget != 0) {
                const unsigned slice = pause < budget ? pause : budget;
                for (unsigned i = 0; i < slice; ++i)
                    cpu_relax();
                budget -= slice;

                if (scheduler_stopping() ||
                    pool.runtime.stop_requested.load(std::memory_order_relaxed) ||
                    glob.stw.request.load(std::memory_order_relaxed) ||
                    HasQueued(pool, loc) || work_event.current_epoch() != epoch) {
                    found = true;
                    break;
                }

                if (pause < spin_interval_cap)
                    pause <<= 1;
            }

            ticket.release();
            if (found && HasQueued(pool, loc))
                work_event.cascade();
            return found;
        }

        template <bool (*HasQueued)(const worker_pool_storage&, const executors_local*) noexcept, bool (*HasRunnable)(const worker_pool_storage&, const executors_local*) noexcept>
        bool wait_until_with(worker_pool_storage& base, executors_local* loc, fast_task::time_point deadline) noexcept {
            if (deadline == fast_task::time_point::max() && spin_before_park<HasQueued>(base, loc))
                return true;

            auto pred = [&base, loc] {
                return scheduler_stopping() ||
                       base.runtime.stop_requested.load(std::memory_order_acquire) ||
                       driver_claimable(loc) ||
                       base.threads.surplus() ||
                       HasRunnable(base, loc);
            };
            base.work_event.wait(pred, deadline);
            return true;
        }

        constexpr unsigned probe_burst = 32;

        template <bool (*HasQueued)(const worker_pool_storage&, const executors_local*) noexcept>
        bool busy_spin_until(worker_pool_storage& base, executors_local* loc, fast_task::time_point deadline) noexcept {
            for (unsigned bursts = 0;; ++bursts) {
                if (scheduler_stopping() ||
                    base.threads.surplus() ||
                    base.runtime.stop_requested.load(std::memory_order_acquire))
                    return true;

                if (base.runtime.paused.load(std::memory_order_acquire)) {
                    auto pred = [&base] {
                        return scheduler_stopping() ||
                               base.runtime.stop_requested.load(std::memory_order_acquire) ||
                               base.threads.surplus() ||
                               !base.runtime.paused.load(std::memory_order_acquire);
                    };
                    base.work_event.wait(pred, deadline);
                    return true;
                }

                if (driver_claimable(loc) || HasQueued(base, loc))
                    return true;

                for (unsigned i = 0; i < probe_burst; ++i)
                    cpu_relax();

                if ((bursts & 0x1F) == 0) {
                    std::this_thread::yield();
                    if (deadline != fast_task::time_point::max() && fast_task::clock::now() >= deadline)
                        return false;
                }
            }
        }

        template <class StorageT>
        void ws_drain_all(worker_pool_storage& base, std::vector<task_object*>& out) noexcept {
            auto& pool = storage_as<StorageT>(base);
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

        template <class StorageT>
        void pf_drain_all(worker_pool_storage& base, std::vector<task_object*>& out) noexcept {
            auto& pool = storage_as<StorageT>(base);
            task_object* raw = nullptr;
            for (auto& queue : pool.queue_data.tasks) {
                while (queue.try_dequeue(raw)) {
                    if (raw)
                        out.push_back(raw);
                }
            }
            while (pool.queue_data.cold_tasks.try_dequeue(raw)) {
                if (raw)
                    out.push_back(raw);
            }
        }

        template <class StorageT>
        void common_drain_cold(worker_pool_storage& base) noexcept {
            task_object* raw = nullptr;
            while (storage_as<StorageT>(base).queue_data.cold_tasks.try_dequeue(raw))
                task::adopt(raw);
        }

        template <class StorageT>
        size_t ws_pending(const worker_pool_storage& base) noexcept {
            const auto& pool = storage_as<StorageT>(base);
            size_t queued = pool.queue_data.tasks.size_approx();
            if (pool.is_global)
                queued += pool.queue_data.cold_tasks.size_approx();
            return queued;
        }

        template <class StorageT>
        size_t pf_pending(const worker_pool_storage& base) noexcept {
            const auto& pool = storage_as<StorageT>(base);
            size_t queued = 0;
            for (const auto& queue : pool.queue_data.tasks)
                queued += queue.size_approx();
            if (pool.is_global)
                queued += pool.queue_data.cold_tasks.size_approx();
            return queued;
        }

        template <class StorageT>
        void storage_destroy(worker_pool_storage& base) noexcept {
            storage_as<StorageT>(base).~StorageT();
        }

        template <class StorageT>
        void balance_arm(worker_pool_storage& base) noexcept {
            storage_as<StorageT>(base).balancer.arm(base);
        }

        template <class StorageT>
        void balance_run(worker_pool_storage& base) noexcept {
            storage_as<StorageT>(base).balancer.run(base);
        }

        template <class StorageT>
        uint64_t balance_samples(const worker_pool_storage& base) noexcept {
            return storage_as<StorageT>(base).balancer.samples();
        }

        inline bool no_steal(worker_pool_storage&, executors_local*, task_object*&) noexcept {
            return false;
        }

        template <class StorageT>
        bool steal_from_pool(worker_pool_storage& pool, executors_local* loc, task_object*& out) noexcept {
            return executor_registry_of<StorageT>(pool).try_steal(&loc->local_tasks, loc->rand, &loc->steal_cache.last_slot, out, loc->llc_id);
        }

        template <scheduler::queue_policy Q, scheduler::idle_policy I, scheduler::worker_balancer B, bool IsGlobal, worker_scale S>
        worker_pool_ops make_ops() noexcept {
            using storage_t = configured_worker_pool_storage<Q, I, B, IsGlobal, S>;

            worker_pool_ops ops{};
            if constexpr (Q == scheduler::queue_policy::work_stealing_lifo) {
                ops.queue.enqueue = &ws_enqueue<storage_t>;
                ops.queue.requeue = &ws_requeue<storage_t>;
                ops.queue.enqueue_cold = &ws_enqueue_cold<storage_t>;
                ops.queue.dequeue_bulk = &ws_dequeue_bulk<storage_t>;
                ops.queue.has_queued_work = &ws_has_queued_work<storage_t>;
                ops.queue.has_runnable_work = &ws_has_runnable_work<storage_t>;
                ops.queue.drain_all = &ws_drain_all<storage_t>;
                ops.queue.pending = &ws_pending<storage_t>;
                if constexpr (I == scheduler::idle_policy::wait)
                    ops.queue.wait_until = &wait_until_with<&ws_has_queued_work<storage_t>, &ws_has_runnable_work<storage_t>>;
                else
                    ops.queue.wait_until = &busy_spin_until<&ws_has_queued_work<storage_t>>;
            } else {
                static_assert(Q == scheduler::queue_policy::priority_fifo, "unknown queue_policy: add its policy functions to pool_ops.cpp");
                ops.queue.enqueue = &pf_enqueue<storage_t>;
                ops.queue.requeue = &pf_requeue<storage_t>;
                ops.queue.enqueue_cold = &pf_enqueue_cold<storage_t>;
                ops.queue.dequeue_bulk = &pf_dequeue_bulk<storage_t>;
                ops.queue.has_queued_work = &pf_has_queued_work<storage_t>;
                ops.queue.has_runnable_work = &pf_has_runnable_work<storage_t>;
                ops.queue.drain_all = &pf_drain_all<storage_t>;
                ops.queue.pending = &pf_pending<storage_t>;
                if constexpr (I == scheduler::idle_policy::wait)
                    ops.queue.wait_until = &wait_until_with<&pf_has_queued_work<storage_t>, &pf_has_runnable_work<storage_t>>;
                else
                    ops.queue.wait_until = &busy_spin_until<&pf_has_queued_work<storage_t>>;
            }
            static_assert(I == scheduler::idle_policy::wait || I == scheduler::idle_policy::busy_spin, "unknown idle_policy: add its wait implementation to pool_ops.cpp");
            ops.queue.drain_cold = &common_drain_cold<storage_t>;
            ops.queue.destroy = &storage_destroy<storage_t>;
            ops.queue.multi_worker_steal = &steal_from_pool<storage_t>;
            if constexpr (S == worker_scale::single_worker)
                ops.queue.steal = &no_steal;
            else
                ops.queue.steal = &steal_from_pool<storage_t>;
            ops.executors.claim = &exec_claim<storage_t>;
            ops.executors.release = &exec_release<storage_t>;
            ops.executors.store_flags = &exec_store_flags<storage_t>;
            ops.executors.active = &exec_active<storage_t>;
            ops.executors.any_work = &exec_any_work<storage_t>;
            ops.balancer.arm = &balance_arm<storage_t>;
            ops.balancer.run = &balance_run<storage_t>;
            ops.balancer.samples = &balance_samples<storage_t>;
            return ops;
        }

        template <scheduler::queue_policy Q, scheduler::idle_policy I, scheduler::worker_balancer B, worker_scale S, bool IsGlobal>
        worker_pool_storage* make_pool_storage_at(void* buffer) {
            using storage_t = configured_worker_pool_storage<Q, I, B, IsGlobal, S>;
            static_assert(sizeof(storage_t) <= worker_pool_storage_size, "worker pool storage exceeds worker_pool_storage_size");
            return ::new (buffer) storage_t();
        }

        template <scheduler::queue_policy Q, scheduler::idle_policy I, bool IsGlobal>
        worker_pool_storage* make_pool_storage_for(void* buffer, scheduler::worker_balancer balancer, bool single_worker) {
            if (balancer == scheduler::worker_balancer::hill_climb) {
                if (single_worker)
                    return make_pool_storage_at<Q, I, scheduler::worker_balancer::hill_climb, worker_scale::single_worker, IsGlobal>(buffer);
                return make_pool_storage_at<Q, I, scheduler::worker_balancer::hill_climb, worker_scale::multi_worker, IsGlobal>(buffer);
            }
            if (single_worker)
                return make_pool_storage_at<Q, I, scheduler::worker_balancer::none, worker_scale::single_worker, IsGlobal>(buffer);
            return make_pool_storage_at<Q, I, scheduler::worker_balancer::none, worker_scale::multi_worker, IsGlobal>(buffer);
        }

        template <scheduler::queue_policy Q, bool IsGlobal>
        worker_pool_storage* make_pool_storage_for(void* buffer, scheduler::idle_policy idle, scheduler::worker_balancer balancer, bool single_worker) {
            if (idle == scheduler::idle_policy::busy_spin)
                return make_pool_storage_for<Q, scheduler::idle_policy::busy_spin, IsGlobal>(buffer, balancer, single_worker);
            return make_pool_storage_for<Q, scheduler::idle_policy::wait, IsGlobal>(buffer, balancer, single_worker);
        }

        template <bool IsGlobal>
        worker_pool_storage* make_pool_storage_for(void* buffer, scheduler::queue_policy queue, scheduler::idle_policy idle, scheduler::worker_balancer balancer, bool single_worker) {
            if (queue == scheduler::queue_policy::priority_fifo)
                return make_pool_storage_for<scheduler::queue_policy::priority_fifo, IsGlobal>(buffer, idle, balancer, single_worker);
            return make_pool_storage_for<scheduler::queue_policy::work_stealing_lifo, IsGlobal>(buffer, idle, balancer, single_worker);
        }

        void validate_policies(scheduler::queue_policy queue, scheduler::idle_policy idle) {
            if (queue != scheduler::queue_policy::work_stealing_lifo && queue != scheduler::queue_policy::priority_fifo)
                throw std::invalid_argument("worker_pool: unknown queue policy");
            if (idle != scheduler::idle_policy::wait && idle != scheduler::idle_policy::busy_spin)
                throw std::invalid_argument("worker_pool: unknown idle policy");
        }
    }

    template <scheduler::queue_policy Q, scheduler::idle_policy I, scheduler::worker_balancer B, bool IsGlobal, worker_scale S>
    configured_worker_pool_storage<Q, I, B, IsGlobal, S>::configured_worker_pool_storage()
        : queue_data() {
        this->ops = make_ops<Q, I, B, IsGlobal, S>();
    }

    void FT_API_LOCAL validate_pool_policies(scheduler::queue_policy queue, scheduler::idle_policy idle) {
        validate_policies(queue, idle);
    }

    FT_API_LOCAL worker_pool_storage* construct_pool_storage(void* buffer, scheduler::queue_policy queue, scheduler::idle_policy idle, scheduler::worker_balancer balancer, bool single_worker) {
        validate_policies(queue, idle);
        return make_pool_storage_for<false>(buffer, queue, idle, balancer, single_worker);
    }

    FT_API_LOCAL worker_pool_storage* construct_global_pool_storage(void* buffer, scheduler::queue_policy queue, scheduler::idle_policy idle, scheduler::worker_balancer balancer, bool single_worker) {
        validate_policies(queue, idle);
        return make_pool_storage_for<true>(buffer, queue, idle, balancer, single_worker);
    }

    template struct configured_worker_pool_storage<scheduler::queue_policy::work_stealing_lifo, scheduler::idle_policy::wait, scheduler::worker_balancer::none, true, worker_scale::multi_worker>;
}
