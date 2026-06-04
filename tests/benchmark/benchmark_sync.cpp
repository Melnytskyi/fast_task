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

static void bench_mutex_lock_unlock() {
    const scale_point scales[] = {
        {"1K", 1'000},
        {"10K", 10'000},
        {"50K", 50'000},
        {"100K", 100'000},
        {"1M", 1'000'000},
    };

    print_bench_header("task_mutex — Lock / Unlock (single task, no contention)");
    warm_up();

    for (auto const& sp : scales) {
        benchmark_timer timer;

        fast_task::task t = fast_task::task::run([&sp] {
            fast_task::task_mutex mtx;
            for (uint64_t i = 0; i < sp.iterations; ++i) {
                mtx.lock();
                mtx.unlock();
            }
        });

        t.await_task();
        double ms = timer.elapsed_ms();
        print_bench_row(sp.label, sp.iterations * 2, ms);
    }
}
static void bench_mutex_contention() {
    const scale_point scales[] = {
        {"1K", 1'000},
        {"10K", 10'000},
        {"50K", 50'000},
        {"100K", 100'000},
        {"1M", 1'000'000},
    };

    print_bench_header("task_mutex — Lock / Unlock (2 tasks, contention)");
    warm_up();

    for (auto const& sp : scales) {
        benchmark_timer timer;

        fast_task::task_mutex mtx;
        std::atomic<uint64_t> counter{0};

        auto worker = [&] {
            for (uint64_t i = 0; i < sp.iterations; ++i) {
                mtx.lock();
                counter.fetch_add(1, std::memory_order_relaxed);
                mtx.unlock();
            }
        };

        auto t1 = fast_task::task::run(worker);
        auto t2 = fast_task::task::run(worker);

        t1.await_task();
        t2.await_task();

        double ms = timer.elapsed_ms();
        print_bench_row(sp.label, sp.iterations * 4, ms);
    }
}

static void bench_semaphore_lock_release() {
    const scale_point scales[] = {
        {"1K", 1'000},
        {"10K", 10'000},
        {"50K", 50'000},
        {"100K", 100'000},
        {"1M", 1'000'000},
    };

    print_bench_header("task_semaphore — Lock / Release");
    warm_up();

    for (auto const& sp : scales) {
        benchmark_timer timer;

        fast_task::task t = fast_task::task::run([&sp] {
            fast_task::task_semaphore sem;
            sem.set_max_threshold(1);
            for (uint64_t i = 0; i < sp.iterations; ++i) {
                sem.lock();
                sem.release();
            }
        });

        t.await_task();
        double ms = timer.elapsed_ms();
        print_bench_row(sp.label, sp.iterations * 2, ms);
    }
}

static void bench_limiter_lock_unlock() {
    const scale_point scales[] = {
        {"1K", 1'000},
        {"10K", 10'000},
        {"50K", 50'000},
        {"100K", 100'000},
        {"1M", 1'000'000},
    };

    print_bench_header("task_limiter — Lock / Unlock");
    warm_up();

    for (auto const& sp : scales) {
        benchmark_timer timer;

        fast_task::task t = fast_task::task::run([&sp] {
            fast_task::task_limiter lim;
            lim.set_max_threshold(1);
            for (uint64_t i = 0; i < sp.iterations; ++i) {
                lim.lock();
                lim.unlock();
            }
        });

        t.await_task();
        double ms = timer.elapsed_ms();
        print_bench_row(sp.label, sp.iterations * 2, ms);
    }
}
int main() {
    size_t n = std::max(2u, std::thread::hardware_concurrency());
    fast_task::scheduler::create_executor(n);
    while (fast_task::scheduler::total_executors() < n)
        std::this_thread::yield();

    bench_mutex_lock_unlock();
    bench_mutex_contention();
    bench_semaphore_lock_release();
    bench_limiter_lock_unlock();

    fast_task::scheduler::shut_down();
    return 0;
}