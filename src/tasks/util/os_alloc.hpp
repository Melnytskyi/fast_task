// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef SRC_TASKS_UTIL_OS_ALLOC
#define SRC_TASKS_UTIL_OS_ALLOC
#include <cstdint>

namespace fast_task {
    void* os_alloc(std::uintptr_t size) noexcept;
    void os_free(void* ptr, std::uintptr_t size) noexcept;
}

#endif /* SRC_TASKS_UTIL_OS_ALLOC */
