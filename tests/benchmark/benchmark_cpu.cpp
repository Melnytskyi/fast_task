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
#include <cmath>
#include <algorithm>

static constexpr int fib_n = 30;
static const scale_point cpu_fib_scales[] = {
    {"1K", 1'000},
    {"10K", 10'000},
    {"50K", 50'000},
    {"100K", 100'000},
};

BENCHMARK_CPU(cpu_fibonacci_recursive, cpu_fib_scales) {
    auto fib_worker = [](int n) -> uint64_t {
        auto fib = [](int n, auto& self) -> uint64_t {
            if (n <= 1)
                return (uint64_t)n;
            return self(n - 1, self) + self(n - 2, self);
        };
        return fib(n, fib);
    };

    std::vector<fast_task::task> tasks;
    tasks.reserve(scale);
    for (uint64_t i = 0; i < scale; ++i)
        tasks.push_back(fast_task::task::run([fib_worker] { fib_worker(fib_n); }));

    for (auto& t : tasks)
        t.await_task();
}

static constexpr int mat_dim = 128;
static const scale_point cpu_mat_scales[] = {
    {"100", 100},
    {"500", 500},
    {"1K", 1'000},
    {"5K", 5'000},
    {"10K", 10'000},
};

BENCHMARK_CPU(cpu_matrix_multiply, cpu_mat_scales) {
    static const std::vector<double> mat_a(mat_dim * mat_dim, 1.0);
    static const std::vector<double> mat_b(mat_dim * mat_dim, 2.0);

    std::vector<fast_task::task> tasks;
    tasks.reserve(scale);
    for (uint64_t i = 0; i < scale; ++i) {
        tasks.push_back(fast_task::task::run([] {
            std::vector<double> result(mat_dim * mat_dim, 0.0);
            for (int r = 0; r < mat_dim; ++r) {
                for (int c = 0; c < mat_dim; ++c) {
                    double sum = 0.0;
                    for (int k = 0; k < mat_dim; ++k)
                        sum += mat_a[r * mat_dim + k] * mat_b[k * mat_dim + c];
                    result[r * mat_dim + c] = sum;
                }
            }
            volatile double sink = result[0];
            (void)sink;
        }));
    }

    for (auto& t : tasks)
        t.await_task();
}

static constexpr int prime_limit = 50'000;
static const scale_point cpu_prime_scales[] = {
    {"1K", 1'000},
    {"5K", 5'000},
    {"10K", 10'000},
    {"50K", 50'000},
    {"100K", 100'000},
};

BENCHMARK_CPU(cpu_prime_count, cpu_prime_scales) {
    std::vector<fast_task::task> tasks;
    tasks.reserve(scale);
    for (uint64_t i = 0; i < scale; ++i) {
        tasks.push_back(fast_task::task::run([] {
            std::vector<bool> is_prime(static_cast<size_t>(prime_limit) + 1, true);
            is_prime[0] = is_prime[1] = false;
            for (int p = 2; p * p <= prime_limit; ++p) {
                if (is_prime[static_cast<size_t>(p)]) {
                    for (int multiple = p * p; multiple <= prime_limit; multiple += p)
                        is_prime[static_cast<size_t>(multiple)] = false;
                }
            }
            int count = 0;
            for (int n = 2; n <= prime_limit; ++n) {
                if (is_prime[static_cast<size_t>(n)])
                    ++count;
            }
            volatile int sink = count;
            (void)sink;
        }));
    }

    for (auto& t : tasks)
        t.await_task();
}

static constexpr int nq_board_size = 10;
static const scale_point cpu_nq_scales[] = {
    {"100", 100},
    {"500", 500},
    {"1K", 1'000},
    {"5K", 5'000},
    {"10K", 10'000},
};

BENCHMARK_CPU(cpu_nqueens, cpu_nq_scales) {
    std::vector<fast_task::task> tasks;
    tasks.reserve(scale);
    for (uint64_t i = 0; i < scale; ++i) {
        tasks.push_back(fast_task::task::run([] {
            std::vector<int> cols(static_cast<size_t>(nq_board_size), 0);
            int solutions = 0;

            auto is_safe = [&cols](int row, int col) -> bool {
                for (int prev = 0; prev < row; ++prev) {
                    if (cols[static_cast<size_t>(prev)] == col ||
                        std::abs(cols[static_cast<size_t>(prev)] - col) == row - prev)
                        return false;
                }
                return true;
            };

            auto solve = [&](int row, auto& self) -> void {
                if (row == nq_board_size) {
                    ++solutions;
                    return;
                }
                for (int col = 0; col < nq_board_size; ++col) {
                    if (is_safe(row, col)) {
                        cols[static_cast<size_t>(row)] = col;
                        self(row + 1, self);
                    }
                }
            };

            solve(0, solve);
            volatile int sink = solutions;
            (void)sink;
        }));
    }

    for (auto& t : tasks)
        t.await_task();
}

static constexpr int64_t pi_iters = 5'000'000;
static const scale_point cpu_pi_scales[] = {
    {"100", 100},
    {"500", 500},
    {"1K", 1'000},
    {"5K", 5'000},
    {"10K", 10'000},
};

BENCHMARK_CPU(cpu_pi_approximation, cpu_pi_scales) {
    std::vector<fast_task::task> tasks;
    tasks.reserve(scale);
    for (uint64_t i = 0; i < scale; ++i) {
        tasks.push_back(fast_task::task::run([] {
            double pi = 0.0;
            for (int64_t k = 0; k < pi_iters; ++k) {
                pi += (k % 2 == 0 ? 1.0 : -1.0) / (2.0 * k + 1.0);
            }
            pi *= 4.0;
            volatile double sink = pi;
            (void)sink;
        }));
    }

    for (auto& t : tasks)
        t.await_task();
}

static constexpr int sort_array_size = 10'000;
static const scale_point cpu_sort_scales[] = {
    {"1K", 1'000},
    {"5K", 5'000},
    {"10K", 10'000},
    {"50K", 50'000},
    {"100K", 100'000},
};

BENCHMARK_CPU(cpu_sorted_insertion, cpu_sort_scales) {
    std::vector<fast_task::task> tasks;
    tasks.reserve(scale);
    for (uint64_t i = 0; i < scale; ++i) {
        tasks.push_back(fast_task::task::run([] {
            std::vector<int> data(static_cast<size_t>(sort_array_size));
            for (int j = 0; j < sort_array_size; ++j)
                data[static_cast<size_t>(j)] = sort_array_size - j;

            std::sort(data.begin(), data.end());
            auto pos = std::lower_bound(data.begin(), data.end(), sort_array_size / 2);
            data.insert(pos, sort_array_size / 2);

            volatile int sink = data[0];
            (void)sink;
        }));
    }

    for (auto& t : tasks)
        t.await_task();
}

static constexpr int mandel_width = 200;
static constexpr int mandel_height = 200;
static constexpr int mandel_max_iter = 500;
static const scale_point cpu_mandel_scales[] = {
    {"100", 100},
    {"500", 500},
    {"1K", 1'000},
    {"5K", 5'000},
    {"10K", 10'000},
};

BENCHMARK_CPU(cpu_mandelbrot, cpu_mandel_scales) {
    std::vector<fast_task::task> tasks;
    tasks.reserve(scale);
    for (uint64_t i = 0; i < scale; ++i) {
        tasks.push_back(fast_task::task::run([] {
            int pixels_computed = 0;
            for (int py = 0; py < mandel_height; ++py) {
                for (int px = 0; px < mandel_width; ++px) {
                    double x0 = -2.5 + 3.5 * px / static_cast<double>(mandel_width);
                    double y0 = -1.25 + 2.5 * py / static_cast<double>(mandel_height);

                    double x = 0.0, y = 0.0;
                    int iteration = 0;
                    while (x * x + y * y <= 4.0 && iteration < mandel_max_iter) {
                        double xtemp = x * x - y * y + x0;
                        y = 2.0 * x * y + y0;
                        x = xtemp;
                        ++iteration;
                    }
                    if (iteration < mandel_max_iter)
                        ++pixels_computed;
                }
            }
            volatile int sink = pixels_computed;
            (void)sink;
        }));
    }

    for (auto& t : tasks)
        t.await_task();
}
