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

#define BENCHMARK_GRADUATED(name, scales, body)           \
    do {                                                  \
        print_bench_header(name);                         \
        warm_up();                                        \
        for (auto const& sp : (scales)) {                 \
            benchmark_timer timer;                        \
            {                                             \
                body                                      \
            }                                             \
            double ms = timer.elapsed_ms();               \
            print_bench_row(sp.label, sp.iterations, ms); \
        }                                                 \
        std::cout << std::endl;                           \
    } while (0)
#define BENCHMARK_GRADUATED_WARM(name, scales, warmup, measured) \
    do {                                                         \
        print_bench_header(name);                                \
        for (auto const& sp : (scales)) {                        \
            /* warmup */                                         \
            for (int _w = 0; _w < 3; ++_w) {                     \
                warmup                                           \
            }                                                    \
            /* measured */                                       \
            benchmark_timer timer;                               \
            {                                                    \
                measured                                         \
            }                                                    \
            double ms = timer.elapsed_ms();                      \
            print_bench_row(sp.label, sp.iterations, ms);        \
        }                                                        \
        std::cout << std::endl;                                  \
    } while (0)
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
#endif // FAST_TASK_BENCHMARK_HELPERS