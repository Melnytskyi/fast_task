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

static void bench_yield_burst() {
    const scale_point scales[] = {
        {"1K", 1'000},
        {"10K", 10'000},
        {"50K", 50'000},
        {"100K", 100'000},
        {"1M", 1'000'000},
        {"10M", 10'000'000},
    };

    print_bench_header("Context Switch — yield burst (single task)");
    warm_up();

    for (auto const& sp : scales) {
        benchmark_timer timer;

        fast_task::task t = fast_task::task::run([&sp] {
            for (uint64_t i = 0; i < sp.iterations; ++i)
                fast_task::this_task::yield();
        });

        t.await_task();
        double ms = timer.elapsed_ms();
        print_bench_row(sp.label, sp.iterations, ms);
    }
}

static void bench_stackful_yield_concurrent() {
    const scale_point scales[] = {
        {"1K", 1'000},
        {"10K", 10'000},
        {"50K", 50'000},
        {"100K", 100'000},
        {"1M", 1'000'000},
        {"10M", 10'000'000},
    };

    unsigned int hardware_threads = std::max(2u, std::thread::hardware_concurrency());

    // Multiplier > 1 ensures actual stack swapping occurs instead of yielding to self
    unsigned int multiplier = 2;
    unsigned int task_count = hardware_threads * multiplier;

    std::string title = "Context Switch — Stackful Yield (" + std::to_string(task_count) + " tasks)";
    print_bench_header(title.c_str());
    warm_up();

    for (auto const& sp : scales) {
        benchmark_timer timer;

        // Distribute total yields evenly across all tasks
        uint64_t yields_per_task = sp.iterations / task_count;
        if (yields_per_task == 0)
            yields_per_task = 1;
        uint64_t actual_ops = yields_per_task * task_count;

        std::vector<fast_task::task> tasks;
        tasks.reserve(task_count);

        for (unsigned int i = 0; i < task_count; ++i) {
            // fast_task::task::run creates a stackful task by default (is_on_scheduler = false)
            tasks.push_back(fast_task::task::run([yields_per_task] {
                for (uint64_t j = 0; j < yields_per_task; ++j) {
                    fast_task::this_task::yield();
                }
            }));
        }

        for (auto& t : tasks) {
            t.await_task();
        }

        double ms = timer.elapsed_ms();
        print_bench_row(sp.label, actual_ops, ms);
    }
}

static void bench_transfer_pingpong() {
    const scale_point scales[] = {
        {"1K", 1'000},
        {"10K", 10'000},
        {"50K", 50'000},
        {"100K", 100'000},
        {"1M", 1'000'000},
        {"10M", 10'000'000},
    };

    print_bench_header("Context Switch — transfer_to ping-pong (is_on_scheduler)");
    warm_up();

    struct shared_state {
        fast_task::task partner;
        int64_t remaining;
        bool yield = false;
        fast_task::enter_state state;
    };

    static fast_task::task_vtable vt{
        nullptr,
        nullptr,
        [](void* ptr) {
            auto* s = static_cast<shared_state*>(ptr);
            if (s->remaining > 0) {
                if (!s->yield)
                    --s->remaining;
                else
                    s->yield = false;
                if (!fast_task::this_task::transfer_to(s->partner)) {
                    s->yield = true;
                    fast_task::this_task::enter_yield(s->state);
                }
                if (s->remaining == 0)
                    fast_task::this_task::the_coroutine_ended(fast_task::scheduler::current_context_task());
            } else
                fast_task::this_task::the_coroutine_ended(fast_task::scheduler::current_context_task());
        },
        nullptr,
        nullptr,
        false
    };

    for (auto const& sp : scales) {
        benchmark_timer timer;


        shared_state state_a, state_b;
        state_a.remaining = sp.iterations;
        state_b.remaining = sp.iterations;


        auto task_a = fast_task::task(
            &state_a,
            &vt,
            true,
            true
        );
        auto task_b = fast_task::task(
            &state_b,
            &vt,
            true,
            true
        );

        state_a.partner = fast_task::task(task_b);
        state_b.partner = fast_task::task(task_a);

        task_a.await_task();
        fast_task::task::await_task(task_b, false);

        double ms = timer.elapsed_ms();
        uint64_t total_switches = sp.iterations * 2;
        print_bench_row(sp.label, total_switches, ms);
    }
}

int main() {
    size_t n = std::max(2u, std::thread::hardware_concurrency());
    fast_task::scheduler::create_executor(n);
    while (fast_task::scheduler::total_executors() < n)
        std::this_thread::yield();

    bench_yield_burst();
    bench_transfer_pingpong();
    bench_stackful_yield_concurrent();

    fast_task::scheduler::shut_down();
    return 0;
}