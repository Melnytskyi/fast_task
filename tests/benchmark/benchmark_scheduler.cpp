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

static void bench_spawn_complete() {
    const scale_point scales[] = {
        {"1K", 1'000},
        {"10K", 10'000},
        {"50K", 50'000},
        {"100K", 100'000},
        {"1M", 1'000'000},
    };

    print_bench_header("Scheduler — Spawn + Complete (empty work)");
    warm_up();

    for (auto const& sp : scales) {
        benchmark_timer timer;

        std::vector<fast_task::task> tasks;
        tasks.reserve(sp.iterations);

        for (uint64_t i = 0; i < sp.iterations; ++i)
            tasks.push_back(fast_task::task::run([]{ /* empty */ }));

        for (auto& t : tasks)
            t.await_task();

        double ms = timer.elapsed_ms();
        print_bench_row(sp.label, sp.iterations, ms);
    }
}

static void bench_compute_bound() {
    const scale_point scales[] = {
        {"1K", 1'000},
        {"10K", 10'000},
        {"50K", 50'000},
        {"100K", 100'000},
        {"1M", 1'000'000},
    };

    print_bench_header("Scheduler — Compute-bound tasks (10k iters each)");
    warm_up();

    for (auto const& sp : scales) {
        benchmark_timer timer;

        std::vector<fast_task::task> tasks;
        tasks.reserve(sp.iterations);

        for (uint64_t i = 0; i < sp.iterations; ++i) {
            tasks.push_back(fast_task::task::run([] {
                volatile uint64_t sum = 0;
                for (int j = 0; j < 10'000; ++j)
                    sum += j;
                (void)sum;
            }));
        }

        for (auto& t : tasks)
            t.await_task();

        double ms = timer.elapsed_ms();
        print_bench_row(sp.label, sp.iterations, ms);
    }
}

static void bench_yielding_tasks() {
    const scale_point scales[] = {
        {"1K", 1'000},
        {"10K", 10'000},
        {"50K", 50'000},
        {"100K", 100'000},
        {"1M", 1'000'000},
    };

    print_bench_header("Scheduler — Yielding tasks (10 yields each)");
    warm_up();

    for (auto const& sp : scales) {
        benchmark_timer timer;

        std::vector<fast_task::task> tasks;
        tasks.reserve(sp.iterations);

        for (uint64_t i = 0; i < sp.iterations; ++i) {
            tasks.push_back(fast_task::task::run([] {
                for (int j = 0; j < 10; ++j)
                    fast_task::this_task::yield();
            }));
        }

        for (auto& t : tasks)
            t.await_task();

        double ms = timer.elapsed_ms();
        print_bench_row(sp.label, sp.iterations, ms);
    }
}

static void bench_staggered_sleep() {
    const scale_point scales[] = {
        {"1K", 1'000},
        {"10K", 10'000},
        {"50K", 50'000},
        {"100K", 100'000},
        {"1M", 1'000'000},
    };

    print_bench_header("Timing Wheel — Staggered sleep_until", true);
    warm_up();

    size_t baseline_kb = current_rss_kb();
    for (auto const& sp : scales) {
        benchmark_timer timer;

        std::vector<fast_task::task> tasks;
        tasks.reserve(sp.iterations);

        auto base = std::chrono::high_resolution_clock::now();
        for (uint64_t i = 0; i < sp.iterations; ++i) {
            auto tp = base + std::chrono::microseconds(1 * i);
            tasks.push_back(fast_task::task::run([tp] {
                fast_task::this_task::sleep_until(tp);
            }));
        }

        for (auto& t : tasks)
            t.await_task();


        size_t rss_kb = current_rss_kb();
        size_t delta_kb = (baseline_kb > 0) ? (rss_kb - baseline_kb) : 0;

        double ms = timer.elapsed_ms();
        print_bench_row(sp.label, sp.iterations, ms, delta_kb * 1024);
    }
}

static void bench_schedule_until() {
    const scale_point scales[] = {
        {"1K", 1'000},
        {"10K", 10'000},
        {"50K", 50'000},
        {"100K", 100'000},
        {"1M", 1'000'000},
    };

    print_bench_header("Timing Wheel — schedule_until (staggered deadlines)");
    warm_up();

    for (auto const& sp : scales) {
        benchmark_timer timer;

        auto base = std::chrono::high_resolution_clock::now();
        for (uint64_t i = 0; i < sp.iterations; ++i) {
            auto tp = base + std::chrono::microseconds(200 * i);
            fast_task::scheduler::schedule_until(
                fast_task::task::create([]{ /* empty */ }),
                tp
            );
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        double ms = timer.elapsed_ms();
        print_bench_row(sp.label, sp.iterations, ms);
    }
}

int main() {
    size_t n = std::max(2u, std::thread::hardware_concurrency());
    fast_task::scheduler::create_executor(n);
    while (fast_task::scheduler::total_executors() < n)
        std::this_thread::yield();

    bench_spawn_complete();
    bench_compute_bound();

    bench_staggered_sleep();
    bench_schedule_until();

    bench_yielding_tasks();

    fast_task::scheduler::shut_down();
    return 0;
}