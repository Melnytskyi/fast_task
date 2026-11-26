// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <vector>

#include <tasks/_internal.hpp>

namespace fast_task {
    void spawn_pool_worker(worker_pool_storage& storage, uint16_t count) {
        if (count == 0)
            return;

        const uint16_t wanted = storage.threads.claim_target(count);
        if (wanted == 0)
            return;

        const uint16_t dormant = storage.threads.dormant();
        const uint16_t sleepers = wanted < dormant ? wanted : dormant;
        const uint16_t spawn_count = static_cast<uint16_t>(wanted - sleepers);
        if (sleepers != 0)
            storage.dormant_event.notify_all();
        if (spawn_count == 0)
            return;

        const uint8_t slot = storage.pool_index;

        const auto& affinity = storage.config.affinity;
        const bool pin_round_robin =
            !affinity.cpus.empty() && affinity.mode == scheduler::pool_affinity_mode::round_robin;
        std::vector<uint32_t> cpus;
        try {
            if (!affinity.cpus.empty())
                cpus = affinity.cpus;
        } catch (...) {
            storage.threads.release_target(spawn_count);
            throw;
        }

        for (uint16_t i = 0; i < spawn_count; ++i) {
            bool launched_counted = false;
            try {
                if (pin_round_robin) {
                    const uint32_t cursor = storage.runtime.affinity_index.fetch_add(1, std::memory_order_relaxed);
                    cpus.assign(1, affinity.cpus[cursor % affinity.cpus.size()]);
                }
                threads_manager::count_thread_launch();
                launched_counted = true;
                native::thread worker(native::cpu_affinity{cpus}, pool_worker_main, slot);
                if (!worker.affinity_applied())
                    storage.runtime.affinity_failures.fetch_add(1, std::memory_order_relaxed);
                worker.detach();
            } catch (...) {
                if (launched_counted)
                    threads_manager::count_thread_exit();
                storage.threads.release_target(static_cast<uint16_t>(spawn_count - i));
                throw;
            }
        }
    }

    void ensure_pool_worker(worker_pool_storage& storage) noexcept {
        if (storage.runtime.paused.load(std::memory_order_acquire))
            return;
        if (storage.threads.dormant() != 0) {
            storage.dormant_event.notify_one();
            return;
        }
        if (storage.threads.live() != 0)
            return;
        if (storage.queue_empty())
            return;
        try {
            spawn_pool_worker(storage, 1);
        } catch (...) {
        }
    }

    void shrink_pool_workers(worker_pool_storage& storage, uint16_t count) noexcept {
        const uint16_t min = storage.threads.min_limit();
        if (storage.threads.release_target_clamped(count, min) != 0)
            wake_control(storage);
    }

}
