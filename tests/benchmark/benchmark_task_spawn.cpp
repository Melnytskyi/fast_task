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

static void bench_empty_task_create_start_await() {
    const scale_point scales[] = {
        {"1K", 1'000},
        {"10K", 10'000},
        {"50K", 50'000},
        {"100K", 100'000},
        {"1M", 1'000'000},
    };

    std::cout << "# Task — Create, Start, Await (empty lambda)\n\n";
    std::cout << "|Scale        |   Create/ms  |   Start/ms   |     Await/ms    |     Total/ms    |   Tasks/s  |\n";
    std::cout << "|:------------|-------------:|-------------:|----------------:|----------------:|-----------:|\n";

    warm_up();

    for (auto const& sp : scales) {
        double create_ms = 0, start_ms = 0, await_ms = 0;

        {
            std::vector<fast_task::task> tasks;
            tasks.reserve(sp.iterations);

            benchmark_timer timer;
            for (uint64_t i = 0; i < sp.iterations; ++i)
                tasks.push_back(fast_task::task::create([]{ /* empty */ }));
            create_ms = timer.elapsed_ms();

            timer.reset();
            for (auto& t : tasks)
                t.start();
            start_ms = timer.elapsed_ms();

            timer.reset();
            for (auto& t : tasks)
                t.await_task();
            await_ms = timer.elapsed_ms();
        }

        // clang-format off
    std::cout << '|' << std::left << std::setw(13) << sp.label 
              << '|' << std::right << std::fixed << std::setw(14) << create_ms
              << '|' << std::setw(14) << std::right << std::fixed << std::setprecision(2) << start_ms
              << '|' << std::setw(17) << std::right << std::fixed << std::setprecision(2) << await_ms
              << '|' << std::setw(17) << std::right << std::fixed << std::setprecision(2) << create_ms + (start_ms + await_ms)
              << '|' << std::setw(12) << std::right << std::fixed <<std::setprecision(2) << (sp.iterations / ((create_ms + start_ms + await_ms) / 1000.0));
        // clang-format on

        std::cout << "|\n";
    }
}

static void bench_task_large_payload() {
    const scale_point scales[] = {
        {"1K", 1'000},
        {"10K", 10'000},
        {"50K", 50'000},
        {"100K", 100'000},
        {"1M", 1'000'000},
    };

    print_bench_header("Task — Large lambda payload (heap-allocated state)");
    warm_up();

    for (auto const& sp : scales) {
        std::vector<fast_task::task> tasks;
        tasks.reserve(sp.iterations);

        struct big_payload {
            char data[256];
            int id;
            void operator()() const { volatile char c = data[0]; (void)c; }
        };

        benchmark_timer timer;
        for (uint64_t i = 0; i < sp.iterations; ++i) {
            big_payload bp{};
            bp.id = static_cast<int>(i);
            bp.data[0] = static_cast<char>(i);
            tasks.push_back(fast_task::task::run(bp));
        }

        for (auto& t : tasks)
            t.await_task();

        double ms = timer.elapsed_ms();
        print_bench_row(sp.label, sp.iterations, ms);
    }
}

static void bench_run_and_await() {
    const scale_point scales[] = {
        {"1K", 1'000},
        {"10K", 10'000},
        {"50K", 50'000},
        {"100K", 100'000},
        {"1M", 1'000'000},
    };

    print_bench_header("Task — Run + Await (single call)");
    warm_up();

    for (auto const& sp : scales) {
        std::vector<fast_task::task> tasks;
        tasks.reserve(sp.iterations);

        benchmark_timer timer;
        for (uint64_t i = 0; i < sp.iterations; ++i)
            tasks.push_back(fast_task::task::run([]{ /* empty */ }));

        for (auto& t : tasks)
            t.await_task();

        double ms = timer.elapsed_ms();
        print_bench_row(sp.label, sp.iterations, ms);
    }
}

int main() {
    size_t n = std::max(2u, std::thread::hardware_concurrency());
    fast_task::scheduler::create_executor(n);
    while (fast_task::scheduler::total_executors() < n)
        std::this_thread::yield();

    bench_empty_task_create_start_await();
    bench_task_large_payload();
    bench_run_and_await();

    fast_task::scheduler::shut_down();
    return 0;
}