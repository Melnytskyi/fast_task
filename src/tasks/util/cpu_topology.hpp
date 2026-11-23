// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_UTIL_CPU_TOPOLOGY
#define FAST_TASK_UTIL_CPU_TOPOLOGY

#include <cstdint>

#include <fast_task/shared.hpp>

namespace fast_task::util {
    constexpr int tracked_cpu_count = 256;
    constexpr uint8_t unknown_llc = UINT8_MAX;

    uint8_t FT_API_LOCAL llc_of_cpu(int cpu) noexcept;
    uint8_t FT_API_LOCAL current_llc() noexcept;
    uint8_t FT_API_LOCAL llc_count() noexcept;
}

#endif /* FAST_TASK_UTIL_CPU_TOPOLOGY */
