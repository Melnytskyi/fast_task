// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_CORE_HDI
#define FAST_TASK_CORE_HDI

#include <cstddef>
#include <new>

#ifndef FAST_TASK_HDI_SIZE
    #define FAST_TASK_HDI_SIZE
    // Cap at 64 bytes to match fixed inline storage alignment in worker_context / worker_pool
    // (GCC AArch64 reports std::hardware_destructive_interference_size == 256).
    //TODO remove the cap
    #ifdef __cpp_lib_hardware_interference_size
constexpr std::size_t hardware_destructive_interference_size =
    std::hardware_destructive_interference_size < 64 ? std::hardware_destructive_interference_size : 64;
    #else
constexpr std::size_t hardware_destructive_interference_size = 64;
    #endif
#endif

#endif /* FAST_TASK_CORE_HDI */
