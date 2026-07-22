// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef SRC_TASKS_CLASSES_SYNCHRONIZATION_FUTEX_WAITER
#define SRC_TASKS_CLASSES_SYNCHRONIZATION_FUTEX_WAITER
#include <atomic>
#include <cstdint>
#include <chrono>

namespace fast_task {
    // single consumer-multiple producers futex
    struct futex_waiter {
        alignas(64) std::atomic<uint32_t> wake_count{0};
        alignas(64) std::atomic<uint32_t> sleepers{0};

        void notify_one() noexcept;
        void wait() noexcept;
        bool wait_until(std::chrono::high_resolution_clock::time_point deadline) noexcept;
    };
}

#endif /* SRC_TASKS_CLASSES_SYNCHRONIZATION_FUTEX_WAITER */
