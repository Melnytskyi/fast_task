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

BENCHMARK_MEM(memory_idle_task_footprint_multithreaded, scales_xxl_large) {
    size_t factored_scale = scale / 4;
    fast_task::task tasks[4];
    for (auto& i : tasks)
        i = fast_task::task::create([factored_scale] {
            std::vector<fast_task::task> tasks;
            tasks.reserve(factored_scale);
            for (uint64_t i = 0; i < factored_scale; ++i) {
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
        });
    fast_task::task::await_multiple(tasks);
}

BENCHMARK_MEM(memory_task_footprint_multithreaded, scales_xxl_large) {
    size_t factored_scale = scale / 4;
    fast_task::task tasks[4];
    for (auto& i : tasks)
        i = fast_task::task::create([factored_scale] {
            std::vector<fast_task::task> tasks;
            tasks.reserve(factored_scale);
            for (uint64_t i = 0; i < factored_scale; ++i) {
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

BENCHMARK_MEM(memory_idle_task_footprint, scales_xxl_large) {
    std::vector<fast_task::task> tasks;
    tasks.reserve(scale);

    for (uint64_t i = 0; i < scale; ++i) {
        tasks.push_back(
            fast_task::task::create(
                [] {},
                nullptr,
                std::chrono::high_resolution_clock::time_point::min(),
                fast_task::task_priority::high,
                true
            )
        );
    }
}

BENCHMARK_MEM(memory_per_task_overhead, scales_xxl_large) {
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
        t.await_task();
}

BENCHMARK_MEM(memory_idle_task_footprint_stackful, scales_xxl_large) {
    std::vector<fast_task::task> tasks;
    tasks.reserve(scale);

    for (uint64_t i = 0; i < scale; ++i) {
        tasks.push_back(fast_task::task::create([] {
            while (!fast_task::this_task::is_cancellation_requested())
                fast_task::this_task::yield();
        }));
    }
}

BENCHMARK_MEM(memory_per_task_overhead_stackful, scales_xxl_large) {
    std::vector<fast_task::task> tasks;
    tasks.reserve(scale);
    for (uint64_t i = 0; i < scale; ++i) {
        tasks.push_back(fast_task::task::run([] {
            while (!fast_task::this_task::is_cancellation_requested())
                fast_task::this_task::yield();
        }));
    }

    for (auto& t : tasks)
        t.notify_cancel();
    for (auto& t : tasks)
        t.await_task();
}

BENCHMARK_MEM(memory_allocate_and_cleanup, scales_xxl_large) {
    std::vector<fast_task::task> tasks;
    tasks.reserve(scale);
    for (uint64_t i = 0; i < scale; ++i)
        tasks.push_back(fast_task::task::create([] {}));
    tasks.clear();
    cleanup();
}
