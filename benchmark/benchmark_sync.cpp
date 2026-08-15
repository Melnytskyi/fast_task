// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include "benchmark_helpers.hpp"
#include <task.hpp>
#include <task/mutex.hpp>
#include <task/semaphore.hpp>
#include <thread>
#include <vector>

static const scale_point sync_mutex_scales[] = {
    {"1K", 1'000},
    {"10K", 10'000},
    {"50K", 50'000},
    {"100K", 100'000},
    {"1M", 1'000'000},
};

BENCHMARK(sync_mutex_lock_unlock, sync_mutex_scales) {
    fast_task::task t = fast_task::task::run([scale = scale] {
        fast_task::mutex mtx;
        for (uint64_t i = 0; i < scale; ++i) {
            mtx.lock();
            mtx.unlock();
        }
    });

    t.await_task();
}

BENCHMARK(sync_mutex_lock_unlock_native, sync_mutex_scales) {
    fast_task::mutex mtx;
    for (uint64_t i = 0; i < scale; ++i) {
        mtx.lock();
        mtx.unlock();
    }
}

BENCHMARK(sync_mutex_contention, sync_mutex_scales) {
    fast_task::mutex mtx;
    uint64_t counter{0};

    auto t1 = fast_task::task::run([&] {
        for (uint64_t i = 0; i < scale; ++i) {
            mtx.lock();
            counter++;
            mtx.unlock();
        }
    });
    auto t2 = fast_task::task::run([&] {
        for (uint64_t i = 0; i < scale; ++i) {
            mtx.lock();
            counter++;
            mtx.unlock();
        }
    });

    t1.await_task();
    t2.await_task();
    if (counter != scale * 2)
        std::terminate(); //sanity check
}

BENCHMARK(sync_mutex_contention_with_native, sync_mutex_scales) {
    fast_task::mutex mtx;
    uint64_t counter{0};

    auto t1 = fast_task::task::run([&] {
        for (uint64_t i = 0; i < scale; ++i) {
            mtx.lock();
            counter++;
            mtx.unlock();
        }
    });
    for (uint64_t i = 0; i < scale; ++i) {
        mtx.lock();
        counter++;
        mtx.unlock();
    }

    t1.await_task();
    if (counter != scale * 2)
        std::terminate(); //sanity check
}

BENCHMARK(sync_semaphore_lock_release, sync_mutex_scales) {
    fast_task::task t = fast_task::task::run([scale = scale] {
        fast_task::semaphore sem;
        sem.set_max_threshold(1);
        for (uint64_t i = 0; i < scale; ++i) {
            sem.lock();
            sem.release();
        }
    });

    t.await_task();
}

BENCHMARK(sync_limiter_lock_unlock, sync_mutex_scales) {
    fast_task::task t = fast_task::task::run([scale = scale] {
        fast_task::limiter lim;
        lim.set_max_threshold(1);
        for (uint64_t i = 0; i < scale; ++i) {
            lim.lock();
            lim.unlock();
        }
    });

    t.await_task();
}
