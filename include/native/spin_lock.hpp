// Copyright Danyil Melnytskyi 2022-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_INCLUDE_NATIVE_SPIN_LOCK
#define FAST_TASK_INCLUDE_NATIVE_SPIN_LOCK

#include "../shared.hpp"
#include "../shared/primitives.hpp"
#include <atomic>

namespace fast_task::native {
    class FT_API alignas(8) spin_lock {
#ifdef _MSC_VER
    #pragma warning(push)
    #pragma warning(disable : 4251)
#endif
        std::atomic_flag flag = ATOMIC_FLAG_INIT;

#ifdef _MSC_VER
    #pragma warning(pop)
#endif

    public:
        spin_lock();
        spin_lock(const spin_lock& other) = delete;
        spin_lock(spin_lock&& other) = delete;
        spin_lock& operator=(const spin_lock& other) = delete;
        spin_lock& operator=(spin_lock&& other) = delete;
        ~spin_lock();

        void lock();
        bool try_lock();
        void unlock();
    };
}

#endif /* FAST_TASK_INCLUDE_NATIVE_SPIN_LOCK */
