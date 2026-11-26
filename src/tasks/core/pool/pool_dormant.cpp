// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <cstdint>

#include <tasks/_internal.hpp>

namespace fast_task {
    void refresh_dormant_sharing() noexcept {
        bool enabled = false;
        for (uint16_t i = 0; i < pool_table_size; ++i) {
            auto pool = acquire_pool_ref(static_cast<uint8_t>(i));
            if (pool && pool->config.allow_dormant_sharing && !pool->closing) {
                enabled = true;
                break;
            }
        }
        glob.pools.dormant_sharing_enabled.store(enabled, std::memory_order_release);
        fast_task::lock_guard guard(glob.pools.dormant_broker.lock);
        if (!scheduler_stopping())
            glob.pools.dormant_broker.open = true;
    }

    bool claim_dormant_slot(worker_pool_storage& pool, bool spawned) noexcept {
        if (!spawned || !pool.threads.surplus())
            return false;
        for (;;) {
            if (pool.runtime.stop_requested.load(std::memory_order_acquire))
                return false;
            if (pool.ops.queue.has_runnable_work(pool, nullptr))
                return false;
            switch (pool.threads.park()) {
            case park_result::parked:
                return true;
            case park_result::no_surplus:
                return false;
            case park_result::retry:
                break;
            }
        }
    }

    bool try_borrow_dormant(worker_pool_storage& borrower) noexcept {
        if (!glob.pools.dormant_sharing_enabled.load(std::memory_order_relaxed))
            return false;
        if (borrower.closing || borrower.config.hooks.worker_body != nullptr)
            return false;
        auto& rt = borrower.runtime;
        if (rt.paused.load(std::memory_order_relaxed) || rt.stop_requested.load(std::memory_order_relaxed))
            return false;
        if (borrower.threads.dormant() != 0 || borrower.threads.borrowed_in() != 0)
            return false;
        const uint16_t active = borrower.threads.active();
        if (active == 0)
            return false;
        if (static_cast<uint32_t>(active) >= borrower.threads.max_limit())
            return false;
        if (pool_in_run_tasks(borrower) < active)
            return false;
        if (!borrower.ops.queue.has_runnable_work(borrower, nullptr))
            return false;

        pool_ref lender;
        {
            fast_task::lock_guard guard(glob.pools.dormant_broker.lock);
            if (!glob.pools.dormant_broker.open)
                return false;
            for (uint16_t i = 0; i < pool_table_size; ++i) {
                auto candidate = acquire_pool_ref(static_cast<uint8_t>(i));
                if (!candidate || candidate.get() == &borrower)
                    continue;
                if (!candidate->config.allow_dormant_sharing || candidate->config.hooks.worker_body != nullptr)
                    continue;
                if (!candidate->config.affinity.cpus.empty())
                    continue;
                auto& lrt = candidate->runtime;
                if (candidate->closing || lrt.stop_requested.load(std::memory_order_relaxed) ||
                    lrt.paused.load(std::memory_order_relaxed))
                    continue;
                const uint16_t dormant = candidate->threads.dormant();
                if (dormant <= candidate->threads.borrowed_out())
                    continue;
                if (static_cast<uint32_t>(candidate->threads.active()) + dormant <= 1)
                    continue;
                if (!glob.pools.dormant_broker.try_push(candidate.get(), &borrower))
                    return false;
                candidate->threads.lend();
                borrower.threads.accept_lease();
                glob.pools.dormant_broker.outstanding += 1;
                lender = std::move(candidate);
                break;
            }
        }
        if (!lender)
            return false;
        lender->dormant_event.notify_one();
        return true;
    }

    worker_pool_storage* take_dormant_lease(worker_pool_storage& home) noexcept {
        if (home.threads.pending_leases() == 0)
            return nullptr;
        fast_task::lock_guard guard(glob.pools.dormant_broker.lock);
        dormant_lease_grant grant = glob.pools.dormant_broker.take(&home);
        if (!grant.borrower)
            return nullptr;
        home.threads.take_pending();
        return grant.borrower;
    }

    void return_dormant_lease(worker_pool_storage& home, worker_pool_storage& borrower) noexcept {
        fast_task::lock_guard guard(glob.pools.dormant_broker.lock);
        borrower.threads.return_lease_to(home.threads);
        if (glob.pools.dormant_broker.outstanding != 0)
            glob.pools.dormant_broker.outstanding -= 1;
    }

    void drop_dormant_grants(worker_pool_storage& pool) noexcept {
        fast_task::lock_guard guard(glob.pools.dormant_broker.lock);
        auto& broker = glob.pools.dormant_broker;
        for (size_t i = 0; i < broker.grant_count;) {
            auto& grant = broker.grants[i];
            if (grant.lender != &pool && grant.borrower != &pool) {
                ++i;
                continue;
            }
            grant.lender->threads.drop_lease_of(grant.borrower->threads);
            if (broker.outstanding != 0)
                broker.outstanding -= 1;
            grant = broker.grants[--broker.grant_count];
        }
    }

    void close_dormant_broker() noexcept {
        {
            fast_task::lock_guard guard(glob.pools.dormant_broker.lock);
            auto& broker = glob.pools.dormant_broker;
            broker.open = false;
            for (size_t i = 0; i < broker.grant_count; ++i) {
                auto& grant = broker.grants[i];
                grant.lender->threads.drop_lease_of(grant.borrower->threads);
            }
            if (broker.grant_count != 0)
                broker.outstanding = broker.outstanding > broker.grant_count ? broker.outstanding - broker.grant_count : 0;
            broker.grant_count = 0;
        }
        for (uint16_t i = 0; i < pool_table_size; ++i) {
            if (auto pool = acquire_pool_ref(static_cast<uint8_t>(i)))
                pool->dormant_event.notify_all();
        }
    }
}
