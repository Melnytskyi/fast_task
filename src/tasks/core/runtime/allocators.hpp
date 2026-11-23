// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_CORE_ALLOCATORS
#define FAST_TASK_CORE_ALLOCATORS

#include <fast_task/shared.hpp>
#include <tasks/util/fixed_task_allocator.hpp>
#include <tasks/util/hashed_timing_wheel.hpp>
#include <tasks/util/macro.hpp>

namespace fast_task {
    struct FT_API_LOCAL allocators_local_t {
        tl_task_alloc_cache task_cache;
        tl_timing_alloc_cache timing_cache;

        allocators_local_t* registry_next = nullptr;

        allocators_local_t();
        void reset();
        ~allocators_local_t();
        static void drain_all();
    };

    extern FT_API_LOCAL bool alloc_globals_alive;

    NOINLINE allocators_local_t& get_alloc_loc() noexcept;

    struct FT_API_LOCAL runtime_allocators {
        timing_allocator timing_alloc;
        global_task_allocator gba;
    };
}

#endif /* FAST_TASK_CORE_ALLOCATORS */
