// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_CORE_THREAD_IDENTITY
#define FAST_TASK_CORE_THREAD_IDENTITY

#include <cstddef>

namespace fast_task {
    constexpr size_t native_thread_flag = size_t(1) << (sizeof(size_t) * 8 - 2);
    constexpr size_t native_thread_data = size_t(1) << (sizeof(size_t) * 8 - 1);
    constexpr size_t native_thread_mask = ~(size_t(3) << (sizeof(size_t) * 8 - 2));
}

#endif /* FAST_TASK_CORE_THREAD_IDENTITY */
