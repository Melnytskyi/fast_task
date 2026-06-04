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

static void bench_fibonacci_recursive() {
    constexpr int fib_n = 30;
    const scale_point scales[] = {
        {"1K",  1'000},
        {"10K", 10'000},
        {"50K", 50'000},
        {"100K", 100'000},
    };

    auto fib_title = "CPU — Fibonacci(" + std::to_string(fib_n) + ") recursive per task";
    print_bench_header(fib_title.c_str());
    warm_up();

    for (auto const& sp : scales) {
        benchmark_timer timer;

        // Each task computes fib(n) recursively
        auto fib_worker = [](int n) -> uint64_t {
            auto fib = [](int n, auto& self) -> uint64_t {
                if (n <= 1) return (uint64_t)n;
                return self(n - 1, self) + self(n - 2, self);
            };
            return fib(n, fib);
        };

        std::vector<fast_task::task> tasks;
        tasks.reserve(sp.iterations);
        for (uint64_t i = 0; i < sp.iterations; ++i)
            tasks.push_back(fast_task::task::run([fib_worker] { fib_worker(fib_n); }));

        for (auto& t : tasks)
            t.await_task();

        double ms = timer.elapsed_ms();
        print_bench_row(sp.label, sp.iterations, ms);
    }
}

static void bench_matrix_multiply() {
    constexpr int dim = 128;
    const scale_point scales[] = {
        {"100",  100},
        {"500",  500},
        {"1K",   1'000},
        {"5K",   5'000},
        {"10K",  10'000},
    };

    auto mat_title = "CPU — Matrix multiply " + std::to_string(dim) + "x" + std::to_string(dim) + " per task";
    print_bench_header(mat_title.c_str());
    warm_up();

    // Pre-allocate a matrix for all tasks (same data, no aliasing between tasks)
    std::vector<double> mat_a(dim * dim, 1.0);
    std::vector<double> mat_b(dim * dim, 2.0);

    for (auto const& sp : scales) {
        benchmark_timer timer;

        std::vector<fast_task::task> tasks;
        tasks.reserve(sp.iterations);
        for (uint64_t i = 0; i < sp.iterations; ++i) {
            tasks.push_back(fast_task::task::run([&mat_a, &mat_b] {
                std::vector<double> result(dim * dim, 0.0);
                for (int r = 0; r < dim; ++r) {
                    for (int c = 0; c < dim; ++c) {
                        double sum = 0.0;
                        for (int k = 0; k < dim; ++k)
                            sum += mat_a[r * dim + k] * mat_b[k * dim + c];
                        result[r * dim + c] = sum;
                    }
                }
                volatile double sink = result[0];
                (void)sink;
            }));
        }

        for (auto& t : tasks)
            t.await_task();

        double ms = timer.elapsed_ms();
        print_bench_row(sp.label, sp.iterations, ms);
    }
}

static void bench_prime_count() {
    constexpr int limit = 50'000;
    const scale_point scales[] = {
        {"1K",  1'000},
        {"5K",  5'000},
        {"10K", 10'000},
        {"50K", 50'000},
        {"100K", 100'000},
    };

    auto prime_title = "CPU — Prime counting (sieve up to " + std::to_string(limit) + ") per task";
    print_bench_header(prime_title.c_str());
    warm_up();

    for (auto const& sp : scales) {
        benchmark_timer timer;

        std::vector<fast_task::task> tasks;
        tasks.reserve(sp.iterations);
        for (uint64_t i = 0; i < sp.iterations; ++i) {
            tasks.push_back(fast_task::task::run([limit] {
                std::vector<bool> is_prime(static_cast<size_t>(limit) + 1, true);
                is_prime[0] = is_prime[1] = false;
                for (int p = 2; p * p <= limit; ++p) {
                    if (is_prime[static_cast<size_t>(p)]) {
                        for (int multiple = p * p; multiple <= limit; multiple += p)
                            is_prime[static_cast<size_t>(multiple)] = false;
                    }
                }
                int count = 0;
                for (int n = 2; n <= limit; ++n) {
                    if (is_prime[static_cast<size_t>(n)])
                        ++count;
                }
                volatile int sink = count;
                (void)sink;
            }));
        }

        for (auto& t : tasks)
            t.await_task();

        double ms = timer.elapsed_ms();
        print_bench_row(sp.label, sp.iterations, ms);
    }
}

static void bench_nqueens() {
    constexpr int board_size = 10;
    const scale_point scales[] = {
        {"100",  100},
        {"500",  500},
        {"1K",   1'000},
        {"5K",   5'000},
        {"10K",  10'000},
    };

    auto nq_title = "CPU — N-Queens (board=" + std::to_string(board_size) + ") per task";
    print_bench_header(nq_title.c_str());
    warm_up();

    for (auto const& sp : scales) {
        benchmark_timer timer;

        std::vector<fast_task::task> tasks;
        tasks.reserve(sp.iterations);
        for (uint64_t i = 0; i < sp.iterations; ++i) {
            tasks.push_back(fast_task::task::run([board_size] {
                std::vector<int> cols(static_cast<size_t>(board_size), 0);
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
                    if (row == board_size) {
                        ++solutions;
                        return;
                    }
                    for (int col = 0; col < board_size; ++col) {
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

        double ms = timer.elapsed_ms();
        print_bench_row(sp.label, sp.iterations, ms);
    }
}

static void bench_pi_approximation() {
    constexpr int64_t iterations = 5'000'000;
    const scale_point scales[] = {
        {"100",  100},
        {"500",  500},
        {"1K",   1'000},
        {"5K",   5'000},
        {"10K",  10'000},
    };

    auto pi_title = "CPU — Pi approximation (Leibniz, " + std::to_string(iterations) + " terms) per task";
    print_bench_header(pi_title.c_str());
    warm_up();

    for (auto const& sp : scales) {
        benchmark_timer timer;

        std::vector<fast_task::task> tasks;
        tasks.reserve(sp.iterations);
        for (uint64_t i = 0; i < sp.iterations; ++i) {
            tasks.push_back(fast_task::task::run([iterations] {
                double pi = 0.0;
                for (int64_t k = 0; k < iterations; ++k) {
                    pi += (k % 2 == 0 ? 1.0 : -1.0) / (2.0 * k + 1.0);
                }
                pi *= 4.0;
                volatile double sink = pi;
                (void)sink;
            }));
        }

        for (auto& t : tasks)
            t.await_task();

        double ms = timer.elapsed_ms();
        print_bench_row(sp.label, sp.iterations, ms);
    }
}

static void bench_sorted_insertion() {
    constexpr int array_size = 10'000;
    const scale_point scales[] = {
        {"1K",  1'000},
        {"5K",  5'000},
        {"10K", 10'000},
        {"50K", 50'000},
        {"100K", 100'000},
    };

    auto sort_title = "CPU — Sort + Binary Insertion (" + std::to_string(array_size) + " elements) per task";
    print_bench_header(sort_title.c_str());
    warm_up();

    for (auto const& sp : scales) {
        benchmark_timer timer;

        std::vector<fast_task::task> tasks;
        tasks.reserve(sp.iterations);
        for (uint64_t i = 0; i < sp.iterations; ++i) {
            tasks.push_back(fast_task::task::run([array_size] {
                std::vector<int> data(static_cast<size_t>(array_size));
                for (int j = 0; j < array_size; ++j)
                    data[static_cast<size_t>(j)] = array_size - j; // reverse sorted

                // Sort
                std::sort(data.begin(), data.end());

                // Binary insertion
                auto pos = std::lower_bound(data.begin(), data.end(), array_size / 2);
                data.insert(pos, array_size / 2);

                volatile int sink = data[0];
                (void)sink;
            }));
        }

        for (auto& t : tasks)
            t.await_task();

        double ms = timer.elapsed_ms();
        print_bench_row(sp.label, sp.iterations, ms);
    }
}

static void bench_mandelbrot() {
    constexpr int width = 200;
    constexpr int height = 200;
    constexpr int max_iter = 500;
    const scale_point scales[] = {
        {"100",  100},
        {"500",  500},
        {"1K",   1'000},
        {"5K",   5'000},
        {"10K",  10'000},
    };

    auto mandel_title = "CPU — Mandelbrot set (" + std::to_string(width) + "x" + std::to_string(height)
                       + ", " + std::to_string(max_iter) + " iter) per task";
    print_bench_header(mandel_title.c_str());
    warm_up();

    for (auto const& sp : scales) {
        benchmark_timer timer;

        std::vector<fast_task::task> tasks;
        tasks.reserve(sp.iterations);
        for (uint64_t i = 0; i < sp.iterations; ++i) {
            tasks.push_back(fast_task::task::run([width, height, max_iter] {
                int pixels_computed = 0;
                for (int py = 0; py < height; ++py) {
                    for (int px = 0; px < width; ++px) {
                        double x0 = -2.5 + 3.5 * px / static_cast<double>(width);
                        double y0 = -1.25 + 2.5 * py / static_cast<double>(height);

                        double x = 0.0, y = 0.0;
                        int iteration = 0;
                        while (x * x + y * y <= 4.0 && iteration < max_iter) {
                            double xtemp = x * x - y * y + x0;
                            y = 2.0 * x * y + y0;
                            x = xtemp;
                            ++iteration;
                        }
                        if (iteration < max_iter)
                            ++pixels_computed;
                    }
                }
                volatile int sink = pixels_computed;
                (void)sink;
            }));
        }

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

    bench_fibonacci_recursive();
    bench_matrix_multiply();
    bench_prime_count();
    bench_nqueens();
    bench_pi_approximation();
    bench_sorted_insertion();
    bench_mandelbrot();

    fast_task::scheduler::shut_down();
    return 0;
}