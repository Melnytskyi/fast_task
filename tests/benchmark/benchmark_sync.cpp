// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include "benchmark_helpers.hpp"
#include <helpers.hpp>
#include <task.hpp>
#include <task/mutex.hpp>
#include <task/semaphore.hpp>
#include <thread>
#include <vector>

static const scale_point bench_mutex_scales[] = {
    {"1K", 1'000},
    {"10K", 10'000},
    {"50K", 50'000},
    {"100K", 100'000},
    {"1M", 1'000'000},
};

BENCHMARK(bench_mutex_lock_unlock, bench_mutex_scales) {
    fast_task::task t = fast_task::task::run([scale = scale] {
        fast_task::task_mutex mtx;
        for (uint64_t i = 0; i < scale; ++i) {
            mtx.lock();
            mtx.unlock();
        }
    });

    t.await_task();
}

BENCHMARK(bench_mutex_contention, bench_mutex_scales) {
    fast_task::task_mutex mtx;
    std::atomic<uint64_t> counter{0};

    auto worker = [&] {
        for (uint64_t i = 0; i < scale; ++i) {
            mtx.lock();
            counter.fetch_add(1, std::memory_order_relaxed);
            mtx.unlock();
        }
    };

    auto t1 = fast_task::task::run(worker);
    auto t2 = fast_task::task::run(worker);

    t1.await_task();
    t2.await_task();
}

BENCHMARK(bench_semaphore_lock_release, bench_mutex_scales) {
    fast_task::task t = fast_task::task::run([scale = scale] {
        fast_task::task_semaphore sem;
        sem.set_max_threshold(1);
        for (uint64_t i = 0; i < scale; ++i) {
            sem.lock();
            sem.release();
        }
    });

    t.await_task();
}

BENCHMARK(bench_limiter_lock_unlock, bench_mutex_scales) {
    fast_task::task t = fast_task::task::run([scale = scale] {
        fast_task::task_limiter lim;
        lim.set_max_threshold(1);
        for (uint64_t i = 0; i < scale; ++i) {
            lim.lock();
            lim.unlock();
        }
    });

    t.await_task();
}
