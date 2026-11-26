// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_INCLUDE_TASK_PARALLEL
#define FAST_TASK_INCLUDE_TASK_PARALLEL

#include "../native/spin_lock.hpp"
#include "latch.hpp"
#include "scheduler.hpp"
#include "task.hpp"
#include <algorithm>
#include <atomic>
#include <cstddef>
#include <exception>
#include <functional>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

namespace fast_task {
    // Work-stealing chunked parallel_for over [begin, end).
    // Spawns at most (workers - 1) helper tasks + work-helps on the calling task,
    // using a single stack-allocated latch and zero per-element allocations.
    template <class Index, class RangeFn>
    void parallel_for(
        Index begin,
        Index end,
        RangeFn&& fn,
        size_t min_grain = 1,
        scheduler::worker_pool* pool = nullptr
    ) {
        if (end <= begin)
            return;

        const size_t total = static_cast<size_t>(end - begin);
        const size_t grain = std::max<size_t>(1, min_grain);
        const size_t hw = std::max<size_t>(1, std::thread::hardware_concurrency());
        const size_t max_chunks = (total + grain - 1) / grain;
        const size_t desired_workers = std::min<size_t>(hw, max_chunks);

        if (desired_workers <= 1) {
            fn(begin, end);
            return;
        }

        // Partition into ~4x chunks per worker for dynamic load balancing.
        const size_t num_chunks = std::min<size_t>(max_chunks, desired_workers * 4);
        const size_t chunk_size = (total + num_chunks - 1) / num_chunks;
        const size_t helper_count = desired_workers - 1;

        std::atomic<size_t> next_chunk{0};
        std::atomic<bool> has_ex{false};
        fast_task::native::spin_lock ex_lock;
        std::exception_ptr first_ex;
        latch done(static_cast<std::ptrdiff_t>(helper_count));

        auto run_slices = [&] {
            for (;;) {
                if (has_ex.load(std::memory_order_acquire))
                    return;
                const size_t c = next_chunk.fetch_add(1, std::memory_order_relaxed);
                const size_t offset = c * chunk_size;
                if (offset >= total)
                    return;
                const size_t len = std::min<size_t>(chunk_size, total - offset);
                try {
                    fn(static_cast<Index>(begin + offset), static_cast<Index>(begin + offset + len));
                } catch (...) {
                    fast_task::lock_guard<fast_task::native::spin_lock> g(ex_lock);
                    if (!first_ex) {
                        first_ex = std::current_exception();
                        has_ex.store(true, std::memory_order_release);
                    }
                    return;
                }
            }
        };

        for (size_t i = 0; i < helper_count; ++i) {
            task t = task::create([&] {
                run_slices();
                done.count_down();
            });
            if (pool)
                pool->post(std::move(t));
            else
                scheduler::start(std::move(t));
        }

        // Work-help on the calling task/thread so single-worker pools never deadlock.
        run_slices();
        done.wait();

        if (first_ex)
            std::rethrow_exception(first_ex);
    }

    // Work-stealing chunked parallel_reduce over [begin, end).
    // Each worker accumulates into its own cache-line-isolated slot (zero lock contention),
    // then combines partial results sequentially with `reduce_fn`.
    template <class Index, class T, class MapRangeFn, class ReduceFn>
    T parallel_reduce(
        Index begin,
        Index end,
        T identity,
        MapRangeFn&& map_range,
        ReduceFn&& reduce_fn,
        size_t min_grain = 1,
        scheduler::worker_pool* pool = nullptr
    ) {
        if (end <= begin)
            return identity;

        const size_t total = static_cast<size_t>(end - begin);
        const size_t grain = std::max<size_t>(1, min_grain);
        const size_t hw = std::max<size_t>(1, std::thread::hardware_concurrency());
        const size_t max_chunks = (total + grain - 1) / grain;
        const size_t desired_workers = std::min<size_t>(hw, max_chunks);

        if (desired_workers <= 1)
            return reduce_fn(std::move(identity), map_range(begin, end));

        struct alignas(64) partial_slot {
            T value;
            bool has_value = false;
        };

        const size_t num_chunks = std::min<size_t>(max_chunks, desired_workers * 4);
        const size_t chunk_size = (total + num_chunks - 1) / num_chunks;
        const size_t helper_count = desired_workers - 1;

        std::vector<partial_slot> partials(desired_workers);
        std::atomic<size_t> next_chunk{0};
        std::atomic<bool> has_ex{false};
        fast_task::native::spin_lock ex_lock;
        std::exception_ptr first_ex;
        latch done(static_cast<std::ptrdiff_t>(helper_count));

        auto run_worker = [&](size_t worker_idx) {
            auto& slot = partials[worker_idx];
            for (;;) {
                if (has_ex.load(std::memory_order_acquire))
                    return;
                const size_t c = next_chunk.fetch_add(1, std::memory_order_relaxed);
                const size_t offset = c * chunk_size;
                if (offset >= total)
                    return;
                const size_t len = std::min<size_t>(chunk_size, total - offset);
                try {
                    T sub = map_range(static_cast<Index>(begin + offset), static_cast<Index>(begin + offset + len));
                    if (!slot.has_value) {
                        slot.value = std::move(sub);
                        slot.has_value = true;
                    } else {
                        slot.value = reduce_fn(std::move(slot.value), std::move(sub));
                    }
                } catch (...) {
                    fast_task::lock_guard<fast_task::native::spin_lock> g(ex_lock);
                    if (!first_ex) {
                        first_ex = std::current_exception();
                        has_ex.store(true, std::memory_order_release);
                    }
                    return;
                }
            }
        };

        for (size_t i = 0; i < helper_count; ++i) {
            const size_t worker_idx = i + 1;
            task t = task::create([&, worker_idx] {
                run_worker(worker_idx);
                done.count_down();
            });
            if (pool)
                pool->post(std::move(t));
            else
                scheduler::start(std::move(t));
        }

        run_worker(0);
        done.wait();

        if (first_ex)
            std::rethrow_exception(first_ex);

        T acc = std::move(identity);
        for (auto& slot : partials) {
            if (slot.has_value)
                acc = reduce_fn(std::move(acc), std::move(slot.value));
        }
        return acc;
    }
}

#endif /* FAST_TASK_INCLUDE_TASK_PARALLEL */
