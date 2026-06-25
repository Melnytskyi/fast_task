// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include "benchmark_helpers.hpp"
#include <helpers.hpp>
#include <task.hpp>
#include <thread>
#include <vector>

static const scale_point scheduler_spawn_scales[] = {
    {"1K", 1'000},
    {"10K", 10'000},
    {"50K", 50'000},
    {"100K", 100'000},
    {"1M", 1'000'000},
};

BENCHMARK(scheduler_spawn_complete, scheduler_spawn_scales) {
    std::vector<fast_task::task> tasks;
    tasks.reserve(scale);

    for (uint64_t i = 0; i < scale; ++i)
        tasks.push_back(fast_task::task::run([] { /* empty */ }));

    for (auto& t : tasks)
        t.await_task();
}

static const scale_point scheduler_compute_scales[] = {
    {"1K", 1'000},
    {"10K", 10'000},
    {"50K", 50'000},
    {"100K", 100'000},
    {"1M", 1'000'000},
};

BENCHMARK(scheduler_compute_bound, scheduler_compute_scales) {
    std::vector<fast_task::task> tasks;
    tasks.reserve(scale);

    for (uint64_t i = 0; i < scale; ++i) {
        tasks.push_back(fast_task::task::run([] {
            volatile uint64_t sum = 0;
            for (int j = 0; j < 10'000; ++j)
                sum += j;
            (void)sum;
        }));
    }

    for (auto& t : tasks)
        t.await_task();
}

static const scale_point scheduler_yield_scales[] = {
    {"1K", 1'000},
    {"10K", 10'000},
    {"50K", 50'000},
    {"100K", 100'000},
    {"1M", 1'000'000},
};

BENCHMARK(scheduler_yielding_tasks, scheduler_yield_scales) {
    std::vector<fast_task::task> tasks;
    tasks.reserve(scale);

    for (uint64_t i = 0; i < scale; ++i) {
        tasks.push_back(fast_task::task::run([] {
            for (int j = 0; j < 10; ++j)
                fast_task::this_task::yield();
        }));
    }

    for (auto& t : tasks)
        t.await_task();
}

static const scale_point scheduler_staggered_scales[] = {
    {"1K", 1'000},
    {"10K", 10'000},
    {"50K", 50'000},
    {"100K", 100'000},
    {"1M", 1'000'000},
};

BENCHMARK_MEM(scheduler_staggered_sleep, scheduler_staggered_scales) {
    std::vector<fast_task::task> tasks;
    tasks.reserve(scale);

    auto base = std::chrono::high_resolution_clock::now();
    for (uint64_t i = 0; i < scale; ++i) {
        auto tp = base + std::chrono::microseconds(1 * i);
        tasks.push_back(fast_task::task::run([tp] {
            fast_task::this_task::sleep_until(tp);
        }));
    }

    for (auto& t : tasks)
        t.await_task();
}

static const scale_point scheduler_schedule_scales[] = {
    {"1K", 1'000},
    {"10K", 10'000},
    {"50K", 50'000},
    {"100K", 100'000},
    {"1M", 1'000'000},
};

BENCHMARK(scheduler_schedule_until, scheduler_schedule_scales) {
    auto base = std::chrono::high_resolution_clock::now();
    for (uint64_t i = 0; i < scale; ++i) {
        auto tp = base + std::chrono::microseconds(200 * i);
        fast_task::scheduler::schedule_until(
            fast_task::task::create([] { /* empty */ }),
            tp
        );
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}
