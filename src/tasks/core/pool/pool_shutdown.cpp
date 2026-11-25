// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <chrono>
#include <thread>
#include <vector>

#include <tasks/_internal.hpp>

namespace fast_task {
    void shutdown_pool(worker_pool_storage& storage, bool abort_tasks) {
        {
            fast_task::lock_guard guard(storage.no_race);
            if (storage.closing)
                return;
            storage.closing = true;
        }
        storage.runtime.stop_requested.store(true, std::memory_order_release);
        storage.runtime.paused.store(false, std::memory_order_release);
        if (storage.config.allow_implicit_start)
            refresh_implicit_pool();
        drop_dormant_grants(storage);
        auto retire_workers = [&storage] {
            const uint16_t active = storage.threads.active();
            for (uint16_t i = 0; i < active; ++i)
                storage.ops.queue.requeue(storage, nullptr);
            wake_control(storage);
        };

        auto wait_until_quiet = [](auto&& done, auto&& poke) {
            constexpr unsigned spin_budget = 1024;
            for (unsigned spins = 0; !done(); ++spins) {
                if (spins < spin_budget) {
                    std::this_thread::yield();
                    continue;
                }
                poke();
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        };

        auto wake = [&storage] {
            wake_control(storage);
        };

        retire_workers();

        auto all_retired = [&storage] {
            return storage.threads.active() == 0 &&
                   storage.threads.live() == 0 &&
                   storage.threads.foreign() == 0;
        };
        auto retire_or_wake = [&storage, &retire_workers] {
            if (storage.ops.queue.pending(storage) == 0 && storage.threads.active() != 0)
                retire_workers();
            else
                wake_control(storage);
        };
        wait_until_quiet(all_retired, retire_or_wake);

        auto no_dormant = [&storage] {
            return storage.threads.dormant() == 0;
        };
        auto no_borrowed_in = [&storage] {
            return storage.threads.borrowed_in() == 0;
        };
        auto no_borrowed_out = [&storage] {
            return storage.threads.borrowed_out() == 0;
        };
        wait_until_quiet(no_dormant, wake);
        wait_until_quiet(no_borrowed_in, wake);
        wait_until_quiet(no_borrowed_out, wake);

        std::vector<task_object*> drained;
        storage.ops.queue.drain_all(storage, drained);

        for (task_object* obj : drained) {
            task curr_task = task::adopt(obj);
            if (!curr_task)
                continue;
            if (!abort_tasks) {
                retarget_task(*obj, global_storage());
                transfer_task(std::move(curr_task));
                continue;
            }
            bool should_decrement = false;
            {
                fast_task::lock_guard task_guard(get_data(curr_task));
                if (!get_data(curr_task).get_completed()) {
                    get_data(curr_task).set_completed(true);
                    should_decrement = true;
                }
            }
            get_data(curr_task).end_of_life_notify();
            if (should_decrement)
                task_mark_completed(get_data(curr_task));
        }

        if (!storage.is_global) {
            release_pool_slot(storage.pool_index);
            auto no_refs = [&storage] {
                return storage.active_refs.load(std::memory_order_acquire) == 0;
            };
            auto noop = [] {};
            wait_until_quiet(no_refs, noop);
            storage.pool_index = global_pool_index;
        }
    }
}
