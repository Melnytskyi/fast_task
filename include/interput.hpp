// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_INCLUDE_INTERPUT
#define FAST_TASK_INCLUDE_INTERPUT
#include "shared.hpp"
#include <cstdint>

namespace fast_task {
    struct FT_API interrupt_unsafe_region {
        interrupt_unsafe_region();
        ~interrupt_unsafe_region();
        static void lock();
        static void unlock();
        static std::size_t lock_swap(std::size_t);
    };
}
#endif /* FAST_TASK_INCLUDE_INTERPUT */
