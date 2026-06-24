// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_BENCHMARK_HELPERS
#define FAST_TASK_BENCHMARK_HELPERS

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>
using Clock = std::chrono::high_resolution_clock;

#if defined(__linux__) || defined(__unix__)
    #define BENCH_KEEP_ALIVE __attribute__((used))
#elif defined(_MSC_VER)
    #define BENCH_KEEP_ALIVE
#else
    #define BENCH_KEEP_ALIVE
#endif

namespace benchmark_registry {
    struct benchmark_entry {
        const char* name;
        void (*run_fn)();
        bool tracks_memory;

        benchmark_entry(const char* name, void (*run_fn)(), bool tracks_memory)
            : name(name), run_fn(run_fn), tracks_memory(tracks_memory) {}

        benchmark_entry() = default;
        benchmark_entry(const benchmark_entry&) = default;
        benchmark_entry& operator=(const benchmark_entry&) = default;
    };

    inline std::vector<benchmark_entry>& get_registry() {
        static std::vector<benchmark_entry> registry;
        return registry;
    }

    inline int add(const char* name, void (*run_fn)(), bool tracks_memory) {
        get_registry().push_back({name, run_fn, tracks_memory});
        return 0;
    }
}

struct benchmark_timer {
    Clock::time_point start;

    benchmark_timer() : start(Clock::now()) {}

    void reset() {
        start = Clock::now();
    }

    uint64_t elapsed_us() const {
        return std::chrono::duration_cast<std::chrono::microseconds>(
                   Clock::now() - start
        )
            .count();
    }

    double elapsed_ms() const {
        return static_cast<double>(elapsed_us()) / 1000.0;
    }

    double elapsed_s() const {
        return static_cast<double>(elapsed_us()) / 1'000'000.0;
    }

    template <class Rep, class Period>
    uint64_t elapsed_us(const std::chrono::duration<Rep, Period>& duration) const {
        return std::chrono::duration_cast<std::chrono::microseconds>(
                   Clock::now() - start - duration
        )
            .count();
    }

    template <class Rep, class Period>
    double elapsed_ms(const std::chrono::duration<Rep, Period>& duration) const {
        return static_cast<double>(elapsed_us(duration)) / 1000.0;
    }

    template <class Rep, class Period>
    double elapsed_s(const std::chrono::duration<Rep, Period>& duration) const {
        return static_cast<double>(elapsed_us(duration)) / 1'000'000.0;
    }
};

struct scale_point {
    const char* label;
    uint64_t iterations;
};

inline void print_bench_row(const char* scale_label, uint64_t ops, double elapsed_ms) {
    double latency_us = (ops > 0) ? (elapsed_ms * 1000.0) / static_cast<double>(ops) : 0.0;
    double throughput = (elapsed_ms > 0.0)
                            ? (static_cast<double>(ops) / (elapsed_ms / 1000.0))
                            : 0.0;

    // clang-format off
    std::cout << '|' << std::left << std::setw(13) << scale_label 
              << '|' << std::right << std::setw(10) << ops
              << '|' << std::setw(11) << std::fixed << std::setprecision(2) << elapsed_ms
              << '|' << std::setw(13) << std::fixed << std::setprecision(2) << latency_us
              << '|' << std::setw(17) << std::fixed << std::setprecision(0) << throughput;

    std::cout << "|\n";
}

inline void print_bench_row(const char* scale_label, uint64_t ops, double elapsed_ms, uint64_t bytes_allocated) {
    double latency_us = (ops > 0) ? (elapsed_ms * 1000.0) / static_cast<double>(ops) : 0.0;
    double throughput = (elapsed_ms > 0.0)
                            ? (static_cast<double>(ops) / (elapsed_ms / 1000.0))
                            : 0.0;
    double mb = static_cast<double>(bytes_allocated) / (1024.0 * 1024.0);

    // clang-format off
    std::cout << '|' << std::left << std::setw(13) << scale_label 
              << '|' << std::right << std::setw(10) << ops
              << '|' << std::setw(11) << std::fixed << std::setprecision(2) << elapsed_ms
              << '|' << std::setw(13) << std::fixed << std::setprecision(2) << latency_us
              << '|' << std::setw(17) << std::fixed << std::setprecision(0) << throughput
              << '|' << std::setw(10) << std::fixed << std::setprecision(2) << mb;
    // clang-format on

    std::cout << "|\n";
}

inline void print_bench_header(const char* title, bool show_memory = false) {
    std::cout << "\n# " << title << "\n\n";
    std::cout << "|Scale        |       Ops|   Time(ms)|  Latency(us)|Throughput(ops/s)|";
    if (show_memory)
        std::cout << "   Mem(MB)|";

    std::cout << "\n|:------------|---------:|----------:|------------:|----------------:|";
    if (show_memory)
        std::cout << "---------:|";
    std::cout << '\n';
}

inline void warm_up() {
    volatile uint64_t sink = 0;
    for (int i = 0; i < 100'000; ++i)
        sink += i;
    (void)sink;
}

static size_t current_rss_kb() {
#ifdef __linux__
    std::ifstream status("/proc/self/status");
    std::string line;
    while (std::getline(status, line)) {
        if (line.compare(0, 6, "VmRSS:") == 0) {
            std::istringstream iss(line.substr(6));
            size_t kb;
            iss >> kb;
            return kb;
        }
    }
#endif
    return 0;
}

template <size_t size>
inline double avg_bench_time(double (&times)[size]) {
    double res = 0;
    for (size_t i = 0; i < size; i++)
        res += times[i];
    return res / size;
}

template <size_t size>
inline size_t avg_bench_mem(size_t (&usage)[size]) {
    size_t res = 0;
    for (size_t i = 0; i < size; i++)
        res += usage[i];
    return res / size;
}

#define BENCHMARK(name, scales, ...)                                             \
    struct name {                                                                \
        void run(size_t scale);                                                  \
        name() {                                                                 \
            size_t n = std::max(2u, std::thread::hardware_concurrency());        \
            fast_task::scheduler::create_executor(n);                            \
            while (fast_task::scheduler::total_executors() < n)                  \
                std::this_thread::yield();                                       \
            print_bench_header(#name);                                           \
            warm_up();                                                           \
            for (auto const& sp : (scales)) {                                    \
                double times[20]{0};                                             \
                for (size_t i = 0; i < 20; i++) {                                \
                    benchmark_timer timer;                                       \
                    run(sp.iterations);                                          \
                    times[i] = timer.elapsed_ms(__VA_ARGS__);                    \
                }                                                                \
                print_bench_row(sp.label, sp.iterations, avg_bench_time(times)); \
            }                                                                    \
            fast_task::scheduler::shut_down();                                   \
            std::cout << std::endl;                                              \
        }                                                                        \
    };                                                                           \
    namespace {                                                                  \
        BENCH_KEEP_ALIVE static const int _reg_##name =                          \
            (benchmark_registry::add(#name, [] { name(); }, false), 0);          \
    }                                                                            \
    void name::run(size_t scale)

#define BENCHMARK_CPU(name, scales, ...)                                  \
    struct name {                                                         \
        void run(size_t scale);                                           \
        name() {                                                          \
            size_t n = std::max(2u, std::thread::hardware_concurrency()); \
            fast_task::scheduler::create_executor(n);                     \
            while (fast_task::scheduler::total_executors() < n)           \
                std::this_thread::yield();                                \
            print_bench_header(#name);                                    \
            warm_up();                                                    \
            for (auto const& sp : (scales)) {                             \
                benchmark_timer timer;                                    \
                run(sp.iterations);                                       \
                auto time = timer.elapsed_ms(__VA_ARGS__);                \
                print_bench_row(sp.label, sp.iterations, time);           \
            }                                                             \
            fast_task::scheduler::shut_down();                            \
            std::cout << std::endl;                                       \
        }                                                                 \
    };                                                                    \
    namespace {                                                           \
        BENCH_KEEP_ALIVE static const int _reg_##name =                   \
            (benchmark_registry::add(#name, [] { name(); }, false), 0);   \
    }                                                                     \
    void name::run(size_t scale)

#define BENCHMARK_MEM(name, scales, ...)                                                                \
    struct name {                                                                                       \
        void run(size_t scale);                                                                         \
        name() {                                                                                        \
            size_t n = std::max(2u, std::thread::hardware_concurrency());                               \
            fast_task::scheduler::create_executor(n);                                                   \
            while (fast_task::scheduler::total_executors() < n)                                         \
                std::this_thread::yield();                                                              \
            print_bench_header(#name, true);                                                            \
            warm_up();                                                                                  \
            size_t baseline_kb = current_rss_kb();                                                      \
            for (auto const& sp : (scales)) {                                                           \
                double times[20]{0};                                                                    \
                size_t memuse[20]{0};                                                                   \
                for (size_t i = 0; i < 20; i++) {                                                       \
                    benchmark_timer timer;                                                              \
                    run(sp.iterations);                                                                 \
                    times[i] = timer.elapsed_ms(__VA_ARGS__);                                           \
                    size_t rss_kb = current_rss_kb();                                                   \
                    size_t delta_kb = (baseline_kb > 0) ? (rss_kb - baseline_kb) : 0;                   \
                    memuse[i] = delta_kb * 1024;                                                        \
                }                                                                                       \
                print_bench_row(sp.label, sp.iterations, avg_bench_time(times), avg_bench_mem(memuse)); \
            }                                                                                           \
            fast_task::scheduler::shut_down();                                                          \
            fast_task::scheduler::clean_up();                                                           \
            std::cout << std::endl;                                                                     \
        }                                                                                               \
    };                                                                                                  \
    namespace {                                                                                         \
        BENCH_KEEP_ALIVE static const int _reg_##name =                                                 \
            (benchmark_registry::add(#name, [] { name(); }, true), 0);                                  \
    }                                                                                                   \
    void name::run(size_t scale)

inline const scale_point scales_small[] = {
    {"1K", 1'000},
    {"10K", 10'000},
    {"100K", 100'000},
    {"1M", 1'000'000},
};

inline const scale_point scales_tiny[] = {
    {"100", 100},
    {"1K", 1'000},
    {"10K", 10'000},
    {"50K", 50'000},
};

inline const scale_point scales_large[] = {
    {"1K", 1'000},
    {"10K", 10'000},
    {"100K", 100'000},
    {"500K", 500'000},
    {"1M", 1'000'000},
};

inline const scale_point scales_xxl_large[] = {
    {"100", 100},
    {"1K", 1'000},
    {"10K", 10'000},
    {"50K", 50'000},
    {"100K", 100'000},
    {"500K", 500'000},
    {"1M", 1'000'000},
};

#endif // FAST_TASK_BENCHMARK_HELPERS