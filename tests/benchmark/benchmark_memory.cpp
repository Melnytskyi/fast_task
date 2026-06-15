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

BENCHMARK_MEM(bench_idle_task_footprint_multithreaded, scales_xxl_large) {
    fast_task::task tasks[4];
    for (auto& i : tasks)
        i = fast_task::task::run([&] {
            std::vector<fast_task::task> tasks;
            tasks.reserve(scale);
            for (uint64_t i = 0; i < scale; ++i) {
                tasks.push_back(
                    fast_task::task::run(
                        [] {},
                        nullptr,
                        std::chrono::high_resolution_clock::time_point::min(),
                        fast_task::task_priority::high,
                        true
                    )
                );
            }
            for (auto& t : tasks)
                t.notify_cancel();
            for (auto& t : tasks)
                t.await_task();
        });
    fast_task::task::await_multiple(tasks);
}

BENCHMARK_MEM(bench_idle_task_footprint, scales_xxl_large) {
    std::vector<fast_task::task> tasks;
    tasks.reserve(scale);

    for (uint64_t i = 0; i < scale; ++i) {
        tasks.push_back(
            fast_task::task::run(
                [] {},
                nullptr,
                std::chrono::high_resolution_clock::time_point::min(),
                fast_task::task_priority::high,
                true
            )
        );
    }

    //for (auto& t : tasks)
    //    t.notify_cancel();
    for (auto& t : tasks)
        t.await_task();
}

BENCHMARK_MEM(bench_per_task_overhead, scales_xxl_large, std::chrono::milliseconds(500)) {
    std::vector<fast_task::task> tasks;
    tasks.reserve(scale);
    for (uint64_t i = 0; i < scale; ++i) {

        tasks.push_back(
            fast_task::task::run(
                [] {},
                nullptr,
                std::chrono::high_resolution_clock::time_point::min(),
                fast_task::task_priority::high,
                true
            )
        );
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    //for (auto& t : tasks)
    //    t.notify_cancel();
    for (auto& t : tasks)
        t.await_task();
}

BENCHMARK_MEM(bench_idle_task_footprint_stackful, scales_xxl_large, std::chrono::milliseconds(500)) {
    std::vector<fast_task::task> tasks;
    tasks.reserve(scale);

    for (uint64_t i = 0; i < scale; ++i) {
        tasks.push_back(fast_task::task::run([] {
            while (!fast_task::this_task::is_cancellation_requested())
                fast_task::this_task::yield();
        }));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    for (auto& t : tasks)
        t.notify_cancel();
    for (auto& t : tasks)
        t.await_task();
}

BENCHMARK_MEM(bench_per_task_overhead_stackful, scales_xxl_large, std::chrono::milliseconds(500)) {
    std::vector<fast_task::task> tasks;
    tasks.reserve(scale);
    for (uint64_t i = 0; i < scale; ++i) {
        tasks.push_back(fast_task::task::run([] {
            while (!fast_task::this_task::is_cancellation_requested())
                fast_task::this_task::yield();
        }));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    for (auto& t : tasks)
        t.notify_cancel();
    for (auto& t : tasks)
        t.await_task();
}

int main() {
    //bench_idle_task_footprint_multithreaded();
    bench_idle_task_footprint();
    bench_per_task_overhead();
    bench_idle_task_footprint_stackful();
    bench_per_task_overhead_stackful();
    return 0;
}