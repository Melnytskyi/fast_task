// Copyright Danyil Melnytskyi 2022-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <cassert>
#include <fast_task/interrupt.hpp>
#include <fast_task/native/spin_lock.hpp>
#include <thread>

#if defined(__x86_64__) || defined(__i386__) || defined(_M_IX86) || defined(_M_X64)
    #define __IS_X86_OR_X64
#endif

namespace fast_task::native {
    namespace {
        // One pause instruction. On a contended lock the flag line sits in
        // another core's cache; pausing between the read attempts keeps the
        // store buffer free and stops the pipeline from speculating into a
        // loop that has no side effects.
        inline void spin_pause() noexcept {
#ifdef _WIN32
    #ifdef __IS_X86_OR_X64
            _mm_pause();
    #else
            std::this_thread::yield();
    #endif
#else
    #if (defined(__GNUC__) || defined(__clang__)) && defined(__IS_X86_OR_X64)
            __builtin_ia32_pause();
    #else
            std::this_thread::yield();
    #endif
#endif
        }
    }

    spin_lock::spin_lock() = default;

    spin_lock::~spin_lock() = default;

    void spin_lock::lock() {
        interrupt_unsafe_region::lock();
        if (!flag.test(std::memory_order_relaxed) &&
            !flag.test_and_set(std::memory_order_acquire))
            return;
        do {
            while (flag.test(std::memory_order_relaxed))
                spin_pause();
        } while (flag.test_and_set(std::memory_order_acquire));
    }

    bool spin_lock::try_lock() {
        interrupt_unsafe_region::lock();
        if (flag.test(std::memory_order_relaxed) || flag.test_and_set(std::memory_order_acquire)) {
            interrupt_unsafe_region::unlock();
            return false;
        }
        return true;
    }

    void spin_lock::unlock() {
        flag.clear(std::memory_order_release);
        interrupt_unsafe_region::unlock();
    }

    bool spin_lock::is_locked() const noexcept {
        return flag.test(std::memory_order_relaxed);
    }
}
