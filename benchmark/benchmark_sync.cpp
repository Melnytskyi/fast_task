// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include "benchmark_helpers.hpp"
#include <atomic>
#include <fast_task/debug.hpp>
#include <fast_task/task.hpp>
#include <fast_task/task/mutex.hpp>
#include <fast_task/task/semaphore.hpp>
#include <thread>
#include <vector>

static const scale_point sync_mutex_scales[] = {
    {"1K", 1'000},
    {"10K", 10'000},
    {"50K", 50'000},
    {"100K", 100'000},
    {"1M", 1'000'000},
};

BENCHMARK(sync_mutex_lock_unlock, sync_mutex_scales) {
    fast_task::task t = fast_task::task::run([scale = scale] {
        fast_task::mutex mtx;
        for (uint64_t i = 0; i < scale; ++i) {
            mtx.lock();
            mtx.unlock();
        }
    });

    t.await_task();
}

BENCHMARK(sync_mutex_lock_unlock_native, sync_mutex_scales) {
    fast_task::mutex mtx;
    for (uint64_t i = 0; i < scale; ++i) {
        mtx.lock();
        mtx.unlock();
    }
}

BENCHMARK(sync_mutex_contention, sync_mutex_scales) {
    fast_task::mutex mtx;
    uint64_t counter{0};

    auto t1 = fast_task::task::run([&] {
        for (uint64_t i = 0; i < scale; ++i) {
            mtx.lock();
            counter++;
            mtx.unlock();
        }
    });
    auto t2 = fast_task::task::run([&] {
        for (uint64_t i = 0; i < scale; ++i) {
            mtx.lock();
            counter++;
            mtx.unlock();
        }
    });

    t1.await_task();
    t2.await_task();
    if (counter != scale * 2)
        std::terminate(); //sanity check
}

BENCHMARK(sync_mutex_contention_with_native, sync_mutex_scales) {
    fast_task::mutex mtx;
    uint64_t counter{0};
    auto deb_data = collect_task_objects();

    auto t1 = fast_task::task::run([&] {
        for (uint64_t i = 0; i < scale; ++i) {
            mtx.lock();
            counter++;
            mtx.unlock();
        }
    });
    for (uint64_t i = 0; i < scale; ++i) {
        mtx.lock();
        counter++;
        mtx.unlock();
    }

    t1.await_task();
    if (counter != scale * 2)
        std::terminate(); //sanity check
}

BENCHMARK(sync_semaphore_lock_release, sync_mutex_scales) {
    fast_task::task t = fast_task::task::run([scale = scale] {
        fast_task::semaphore sem;
        sem.set_max_threshold(1);
        for (uint64_t i = 0; i < scale; ++i) {
            sem.lock();
            sem.release();
        }
    });

    t.await_task();
}

BENCHMARK(sync_limiter_lock_unlock, sync_mutex_scales) {
    fast_task::task t = fast_task::task::run([scale = scale] {
        fast_task::limiter lim;
        lim.set_max_threshold(1);
        for (uint64_t i = 0; i < scale; ++i) {
            lim.lock();
            lim.unlock();
        }
    });

    t.await_task();
}

BENCHMARK(sync_rw_mutex_read_lock_unlock, sync_mutex_scales) {
    fast_task::task t = fast_task::task::run([scale = scale] {
        fast_task::rw_mutex mtx;
        for (uint64_t i = 0; i < scale; ++i) {
            mtx.read_lock();
            mtx.read_unlock();
        }
    });

    t.await_task();
}

BENCHMARK(sync_rw_mutex_write_lock_unlock, sync_mutex_scales) {
    fast_task::task t = fast_task::task::run([scale = scale] {
        fast_task::rw_mutex mtx;
        for (uint64_t i = 0; i < scale; ++i) {
            mtx.write_lock();
            mtx.write_unlock();
        }
    });

    t.await_task();
}

BENCHMARK(sync_rw_mutex_read_lock_unlock_native, sync_mutex_scales) {
    fast_task::rw_mutex mtx;
    for (uint64_t i = 0; i < scale; ++i) {
        mtx.read_lock();
        mtx.read_unlock();
    }
}

BENCHMARK(sync_rw_mutex_write_lock_unlock_native, sync_mutex_scales) {
    fast_task::rw_mutex mtx;
    for (uint64_t i = 0; i < scale; ++i) {
        mtx.write_lock();
        mtx.write_unlock();
    }
}

BENCHMARK(sync_rw_mutex_reader_contention, sync_mutex_scales) {
    fast_task::rw_mutex mtx;
    // Readers run concurrently, so the counter must be atomic to avoid a data
    // race (and to keep the sanity check deterministic).
    std::atomic<uint64_t> counter{0};

    auto t1 = fast_task::task::run([&] {
        for (uint64_t i = 0; i < scale; ++i) {
            mtx.read_lock();
            counter.fetch_add(1, std::memory_order_relaxed);
            mtx.read_unlock();
        }
    });
    auto t2 = fast_task::task::run([&] {
        for (uint64_t i = 0; i < scale; ++i) {
            mtx.read_lock();
            counter.fetch_add(1, std::memory_order_relaxed);
            mtx.read_unlock();
        }
    });

    t1.await_task();
    t2.await_task();
    if (counter.load() != scale * 2)
        std::terminate(); //sanity check
}

BENCHMARK(sync_rw_mutex_writer_contention, sync_mutex_scales) {
    fast_task::rw_mutex mtx;
    uint64_t counter{0};

    auto t1 = fast_task::task::run([&] {
        for (uint64_t i = 0; i < scale; ++i) {
            mtx.write_lock();
            counter++;
            mtx.write_unlock();
        }
    });
    auto t2 = fast_task::task::run([&] {
        for (uint64_t i = 0; i < scale; ++i) {
            mtx.write_lock();
            counter++;
            mtx.write_unlock();
        }
    });

    t1.await_task();
    t2.await_task();
    if (counter != scale * 2)
        std::terminate(); //sanity check
}

BENCHMARK(sync_rw_mutex_mixed_readers_writer, sync_mutex_scales) {
    fast_task::rw_mutex mtx;
    // The two readers run concurrently with each other, so the counter must be
    // atomic to avoid a data race (and to keep the sanity check deterministic).
    std::atomic<uint64_t> counter{0};

    auto reader1 = fast_task::task::run([&] {
        for (uint64_t i = 0; i < scale; ++i) {
            mtx.read_lock();
            counter.fetch_add(1, std::memory_order_relaxed);
            mtx.read_unlock();
        }
    });
    auto reader2 = fast_task::task::run([&] {
        for (uint64_t i = 0; i < scale; ++i) {
            mtx.read_lock();
            counter.fetch_add(1, std::memory_order_relaxed);
            mtx.read_unlock();
        }
    });
    auto writer = fast_task::task::run([&] {
        for (uint64_t i = 0; i < scale; ++i) {
            mtx.write_lock();
            counter.fetch_add(1, std::memory_order_relaxed);
            mtx.write_unlock();
        }
    });

    reader1.await_task();
    reader2.await_task();
    writer.await_task();
    if (counter.load() != scale * 3)
        std::terminate(); //sanity check
}
