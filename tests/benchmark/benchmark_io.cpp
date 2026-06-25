// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include "benchmark_helpers.hpp"
#include <coroutine/file.hpp>
#include <cstring>
#include <filesystem>
#include <helpers.hpp>
#include <task.hpp>
#include <task/future.hpp>
#include <thread>
#include <vector>

namespace fs = std::filesystem;

struct bench_io_env {
    fs::path dir;

    bench_io_env()
        : dir(fs::temp_directory_path() / ("fast_task_io_bench_" + std::to_string(rand()))) {
        fs::create_directories(dir);
    }

    fs::path temp_path(const char* suffix = "") {
        return dir / ("bench_" + std::to_string(rand()) + suffix);
    }

    ~bench_io_env() {
        std::error_code ec;
        fs::remove_all(dir, ec);
    }
};

static bench_io_env& env() {
    static bench_io_env e;
    return e;
}

const scale_point io_fast_scales[] = {
    {"1K", 1'000},
    {"10K", 10'000},
    {"100K", 100'000},
};

const scale_point io_read_scales[] = {
    {"100", 100},
    {"500", 500},
    {"1K", 1000},
};

auto file_open_close_prepare() {
    auto path = env().temp_path();
    auto fh = fast_task::file::file_handle::open(
        path,
        fast_task::file::open_mode::write,
        fast_task::file::on_open_action::always_new
    );
    fh.close();
    return path;
}

auto prepare_for_read() {
    auto p = env().temp_path("_fr");
    constexpr uint64_t file_size = 256ULL * 1024;

    auto fh = fast_task::file::file_handle::open(
        p,
        fast_task::file::open_mode::write,
        fast_task::file::on_open_action::always_new
    );
    std::vector<uint8_t> block(4096, 0xEF);
    for (uint64_t written = 0; written < file_size; written += 4096)
        fh.write(block.data(), 4096);
    fh.close();

    return p;
}

struct open_only_s {
    std::vector<fast_task::file::file_handle> handles;
    fs::path path;

    open_only_s(size_t scale) : path(env().temp_path()) {
        std::vector<fast_task::file::file_handle> handles;
        handles.reserve(scale);
    }

    ~open_only_s() {
        for (auto& h : handles)
            h.close();
        fs::remove_all(path);
    }
};

BENCHMARK_IO(io_file_file_open_close, io_fast_scales, file_open_close_prepare) {
    for (uint64_t i = 0; i < scale; ++i) {
        auto fh = fast_task::file::file_handle::open(
            path,
            fast_task::file::open_mode::write,
            fast_task::file::on_open_action::open
        );
        fh.close();
    }
}

BENCHMARK_CUSTOM(io_file_open_only, io_fast_scales, open_only_s) {
    for (uint64_t i = 0; i < scale; ++i)
        item.handles.push_back(
            fast_task::file::file_handle::open(
                item.path / std::to_string(i),
                fast_task::file::open_mode::write,
                fast_task::file::on_open_action::always_new
            )
        );
}

BENCHMARK_IO(io_file_sync_read, io_read_scales, prepare_for_read) {
    uint64_t blocks = 256ULL * 1024 / 4096;
    for (uint64_t i = 0; i < scale; ++i) {
        auto fh = fast_task::file::file_handle::open(
            path,
            fast_task::file::open_mode::read,
            fast_task::file::on_open_action::open_exists
        );

        std::vector<uint8_t> buf(4096);
        (void)fh.read(buf.data(), 4096);
        (void)buf;
        fh.close();
    }
}

BENCHMARK_IO(io_file_future_read, io_read_scales, prepare_for_read) {
    for (uint64_t i = 0; i < scale; ++i) {
        auto fh = fast_task::file::file_handle::open(
            path,
            fast_task::file::open_mode::read,
            fast_task::file::on_open_action::open_exists
        );
        auto future = fh.fut_read(4096);
        volatile auto count = future->get().size();
        (void)count;
        fh.close();
    }
}