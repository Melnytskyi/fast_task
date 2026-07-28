// Copyright Danyil Melnytskyi 2022-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <cassert>
#include <native/spin_lock.hpp>
#include <interrupt.hpp>

#if defined(__x86_64__) || defined(__i386__) || defined(_M_IX86) || defined(_M_X64)
    #define __IS_X86_OR_X64
#endif


namespace fast_task::native {
    spin_lock::spin_lock() = default;

    spin_lock::~spin_lock() = default;

    void spin_lock::lock() {
        interrupt_unsafe_region::lock();
        while (flag.test_and_set(std::memory_order_acquire)) {

#ifdef _WIN32
    #ifdef __IS_X86_OR_X64
            _mm_pause();
    #endif
#else
    #if (defined(__GNUC__) || defined(__clang__)) && defined(__IS_X86_OR_X64)
            __builtin_ia32_pause();
    #endif
#endif
        }
    }

    bool spin_lock::try_lock() {
        interrupt_unsafe_region::lock();
        bool prev = flag.test_and_set(std::memory_order_acquire);
        if (prev) {
            interrupt_unsafe_region::unlock();
            return false;
        }
        return true;
    }

    void spin_lock::unlock() {
        flag.clear(std::memory_order_release);
        interrupt_unsafe_region::unlock();
    }
}
