// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <tasks/classes/synchronization/futex_waiter.hpp>
#include <tasks/util/macro.hpp>

#if PLATFORM_LINUX
    #include <errno.h>
    #include <linux/futex.h>
    #include <sys/syscall.h>
    #include <unistd.h>
#elif PLATFORM_WINDOWS
    #define NOMINMAX
    #include <Windows.h>
#endif

namespace fast_task {
    void futex_waiter::notify_one() noexcept {
        wake_count.fetch_add(1, std::memory_order_release);

        if (sleepers.load(std::memory_order_acquire) > 0) {
#if PLATFORM_LINUX
            syscall(SYS_futex, reinterpret_cast<uint32_t*>(&wake_count), FUTEX_WAKE_PRIVATE, 1, nullptr, nullptr, 0);
#elif PLATFORM_WINDOWS
            WakeByAddressSingle(reinterpret_cast<void*>(&wake_count));
#endif
        }
    }

    void futex_waiter::wait() noexcept {
        uint32_t expected = wake_count.load(std::memory_order_acquire);

        for (int spin = 0; spin < 200; ++spin) {
            if (expected > 0) {
                if (wake_count.compare_exchange_weak(expected, expected - 1, std::memory_order_acquire)) {
                    return;
                }
            } else {
#if PLATFORM_LINUX
                __builtin_ia32_pause();
#elif PLATFORM_WINDOWS
                YieldProcessor();
#endif
                expected = wake_count.load(std::memory_order_acquire);
            }
        }

        // 2. Slow path: We must sleep. Announce intention to sleep.
        while (true) {
            if (expected > 0) {
                if (wake_count.compare_exchange_weak(expected, expected - 1, std::memory_order_acquire)) {
                    return;
                }
            } else {
                // Increment sleepers so producers know to call syscall(FUTEX_WAKE)
                sleepers.fetch_add(1, std::memory_order_seq_cst);

                // Double check wake_count after announcing sleep to close the race condition
                expected = wake_count.load(std::memory_order_acquire);
                if (expected == 0) {
#if PLATFORM_LINUX
                    syscall(SYS_futex, reinterpret_cast<uint32_t*>(&wake_count), FUTEX_WAIT_PRIVATE, 0, nullptr, nullptr, 0);
#elif PLATFORM_WINDOWS
                    WaitOnAddress(&wake_count, &expected, sizeof(expected), INFINITE);
#endif
                }

                // We woke up (either via signal or spurious). Remove ourselves from sleepers.
                sleepers.fetch_sub(1, std::memory_order_relaxed);
                expected = wake_count.load(std::memory_order_acquire);
            }
        }
    }

    bool futex_waiter::wait_until(std::chrono::high_resolution_clock::time_point deadline) noexcept {
        uint32_t expected = wake_count.load(std::memory_order_acquire);

        while (true) {
            if (expected > 0) {
                if (wake_count.compare_exchange_weak(expected, expected - 1, std::memory_order_acquire)) {
                    return true;
                }
            } else {
                auto now = std::chrono::high_resolution_clock::now();
                if (now >= deadline)
                    return false;

                sleepers.fetch_add(1, std::memory_order_seq_cst);
                expected = wake_count.load(std::memory_order_acquire);

                if (expected == 0) {
                    now = std::chrono::high_resolution_clock::now();
                    if (now < deadline) {
#if PLATFORM_LINUX
                        auto delta_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(deadline - now);
                        struct timespec ts;
                        ts.tv_sec = delta_ns.count() / 1'000'000'000;
                        ts.tv_nsec = delta_ns.count() % 1'000'000'000;

                        syscall(SYS_futex, reinterpret_cast<uint32_t*>(&wake_count), FUTEX_WAIT_PRIVATE, 0, &ts, nullptr, 0);
#elif PLATFORM_WINDOWS
                        auto delta_ms = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
                        DWORD timeout = static_cast<DWORD>(delta_ms.count());
                        if (timeout == 0)
                            timeout = 1;

                        WaitOnAddress(&wake_count, &expected, sizeof(expected), timeout);
#endif
                    }
                }

                sleepers.fetch_sub(1, std::memory_order_relaxed);
                expected = wake_count.load(std::memory_order_acquire);
            }
        }
    }
}
