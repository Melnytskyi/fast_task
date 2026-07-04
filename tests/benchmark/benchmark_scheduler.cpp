// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include "benchmark_helpers.hpp"
#include <coroutine.hpp>
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

BENCHMARK_MEM(scheduler_staggered_sleep, scheduler_staggered_scales, std::chrono::milliseconds(50)) {
    std::vector<fast_task::task> tasks;
    tasks.reserve(scale);
    auto coro = [](std::chrono::system_clock::time_point tp) -> fast_task::task_coro<void> {
        co_await fast_task::this_task::async_sleep_until(tp);
        co_return;
    };

    auto tp = std::chrono::high_resolution_clock::now() + std::chrono::milliseconds(50);
    for (uint64_t i = 0; i < scale; ++i) {
        auto task = coro(tp);
        task->start();
        tasks.push_back(task);
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

BENCHMARK_MEM(scheduler_schedule_until, scheduler_schedule_scales, std::chrono::milliseconds(100)) {
    auto tp = std::chrono::high_resolution_clock::now() + std::chrono::milliseconds(100);
    auto coro = []() -> fast_task::task_coro<void> {
        co_return;
    };
    for (uint64_t i = 0; i < scale; ++i) {
        fast_task::scheduler::schedule_until(
            coro(),
            tp
        );
    }

    fast_task::scheduler::await_no_tasks();
}
