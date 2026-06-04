// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include "benchmark_helpers.hpp"
#include <fstream>
#include <sstream>
#include <string>
#include <task.hpp>
#include <thread>
#include <vector>


static void bench_idle_task_footprint(bool again) {
    const scale_point scales[] = {
        {"100", 100},
        {"1K", 1'000},
        {"10K", 10'000},
        {"50K", 50'000},
        {"100K", 100'000},
        {"1M", 1'000'000},
    };

    if (again)
        print_bench_header("Memory — Idle Task RSS Footprint(again)", /*show_memory=*/true);
    else
        print_bench_header("Memory — Idle Task RSS Footprint", /*show_memory=*/true);
    warm_up();


    size_t baseline_kb = current_rss_kb();
    for (auto const& sp : scales) {
        benchmark_timer timer;
        std::vector<fast_task::task> tasks;
        tasks.reserve(sp.iterations);
        fast_task::enter_state state{};

        for (uint64_t i = 0; i < sp.iterations; ++i) {
            tasks.push_back(
                fast_task::task::run(
                    [&state] {
                        if (!fast_task::this_task::is_cancellation_requested())
                            fast_task::this_task::enter_yield(state); //it's safe here bcuz implementation is not using the state(for now)
                        else
                            fast_task::this_task::the_coroutine_ended(fast_task::scheduler::current_context_task());
                    },
                    nullptr,
                    std::chrono::high_resolution_clock::time_point::min(),
                    fast_task::task_priority::high,
                    true
                )
            );
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        size_t rss_kb = current_rss_kb();
        size_t delta_kb = (baseline_kb > 0) ? (rss_kb - baseline_kb) : 0;

        double ms = timer.elapsed_ms(std::chrono::milliseconds(500));
        print_bench_row(sp.label, sp.iterations, ms, delta_kb * 1024);

        for (auto& t : tasks)
            t.notify_cancel();
        for (auto& t : tasks)
            t.await_task();
    }
}

static void bench_per_task_overhead() {
    const scale_point scales[] = {
        {"100", 100},
        {"1K", 1'000},
        {"10K", 10'000},
        {"50K", 50'000},
        {"100K", 100'000},
        {"1M", 1'000'000},
    };

    print_bench_header("Memory — Per-Task Stack Overhead", true);
    warm_up();

    for (auto const& sp : scales) {
        size_t before_kb = current_rss_kb();
        benchmark_timer timer;

        std::vector<fast_task::task> tasks;
        tasks.reserve(sp.iterations);
        fast_task::enter_state state{};
        for (uint64_t i = 0; i < sp.iterations; ++i) {

            tasks.push_back(
                fast_task::task::run(
                    [&state] {
                        if (!fast_task::this_task::is_cancellation_requested())
                            fast_task::this_task::enter_yield(state); //it's safe here bcuz implementation is not using the state(for now)
                        else
                            fast_task::this_task::the_coroutine_ended(fast_task::scheduler::current_context_task());
                    },
                    nullptr,
                    std::chrono::high_resolution_clock::time_point::min(),
                    fast_task::task_priority::high,
                    true
                )
            );
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        size_t after_kb = current_rss_kb();
        size_t delta_kb = (before_kb > 0 && after_kb > before_kb) ? (after_kb - before_kb) : 0;
        double kb_per_task = (delta_kb > 0) ? static_cast<double>(delta_kb) / sp.iterations : 0.0;


        double ms = timer.elapsed_ms(std::chrono::milliseconds(500));
        print_bench_row(sp.label, sp.iterations, ms, delta_kb * 1024);

        for (auto& t : tasks)
            t.notify_cancel();
        for (auto& t : tasks)
            t.await_task();
    }
}

static void bench_idle_task_footprint_stackful(bool again) {
    const scale_point scales[] = {
        {"100", 100},
        {"1K", 1'000},
        {"10K", 10'000},
        {"50K", 50'000},
        {"100K", 100'000},
        {"1M", 1'000'000},
    };

    if (again)
        print_bench_header("Memory — Idle Task RSS Footprint(stackful, again)", /*show_memory=*/true);
    else
        print_bench_header("Memory — Idle Task RSS Footprint(stackful)", /*show_memory=*/true);
    warm_up();


    size_t baseline_kb = current_rss_kb();
    for (auto const& sp : scales) {
        benchmark_timer timer;
        std::vector<fast_task::task> tasks;
        tasks.reserve(sp.iterations);

        for (uint64_t i = 0; i < sp.iterations; ++i) {
            tasks.push_back(fast_task::task::run([] {
                while (!fast_task::this_task::is_cancellation_requested())
                    fast_task::this_task::yield();
            }));
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        size_t rss_kb = current_rss_kb();
        size_t delta_kb = (baseline_kb > 0) ? (rss_kb - baseline_kb) : 0;

        double ms = timer.elapsed_ms(std::chrono::milliseconds(500));
        print_bench_row(sp.label, sp.iterations, ms, delta_kb * 1024);

        for (auto& t : tasks)
            t.notify_cancel();
        for (auto& t : tasks)
            t.await_task();
    }
}

static void bench_per_task_overhead_stackful() {
    const scale_point scales[] = {
        {"100", 100},
        {"1K", 1'000},
        {"10K", 10'000},
        {"50K", 50'000},
        {"100K", 100'000},
        {"1M", 1'000'000},
    };

    print_bench_header("Memory — Per-Task Stack Overhead (stackful)", true);
    warm_up();

    for (auto const& sp : scales) {
        size_t before_kb = current_rss_kb();
        benchmark_timer timer;

        std::vector<fast_task::task> tasks;
        tasks.reserve(sp.iterations);
        for (uint64_t i = 0; i < sp.iterations; ++i) {
            tasks.push_back(fast_task::task::run([] {
                while (!fast_task::this_task::is_cancellation_requested())
                    fast_task::this_task::yield();
            }));
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        size_t after_kb = current_rss_kb();
        size_t delta_kb = (before_kb > 0 && after_kb > before_kb) ? (after_kb - before_kb) : 0;
        double kb_per_task = (delta_kb > 0) ? static_cast<double>(delta_kb) / sp.iterations : 0.0;


        double ms = timer.elapsed_ms(std::chrono::milliseconds(500));
        print_bench_row(sp.label, sp.iterations, ms, delta_kb * 1024);

        for (auto& t : tasks)
            t.notify_cancel();
        for (auto& t : tasks)
            t.await_task();
    }
}

int main() {
    size_t n = std::max(2u, std::thread::hardware_concurrency());
    fast_task::scheduler::create_executor(n);
    while (fast_task::scheduler::total_executors() < n)
        std::this_thread::yield();

    bench_idle_task_footprint(false);
    bench_idle_task_footprint(true);

    bench_per_task_overhead();
    
    bench_idle_task_footprint_stackful(false);
    bench_idle_task_footprint_stackful(true);

    bench_per_task_overhead_stackful();

    fast_task::scheduler::shut_down();
    return 0;
}