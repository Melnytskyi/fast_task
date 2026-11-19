// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)
//
// Internal umbrella header. After S0b (plans/pool-architecture.md §4) the
// scheduler internals live in tasks/core/*; this header aggregates them so the
// rest of the tree keeps a single internal include, and keeps the thread-local
// context accessors.

#pragma once
#ifndef FAST_TASK_INTERNAL
    #define FAST_TASK_INTERNAL


    #include <atomic>
    #include <barrier>
    #include <boost/context/continuation.hpp>
    #include <concurrentqueue/moodycamel/concurrentqueue.h>
    #include <cstdint>
    #include <exception>
    #include <queue>
    #include <unordered_set>

    #include <fast_task/exceptions.hpp>
    #include <fast_task/internal/futex.hpp>
    #include <fast_task/internal/task_object.hpp>
    #include <fast_task/shared.hpp>
    #include <fast_task/task.hpp>
    #include <tasks/util/_dbg_macro.hpp>
    #include <tasks/util/fixed_task_allocator.hpp>
    #include <tasks/util/hashed_timing_wheel.hpp>
    #include <tasks/util/macro.hpp>
    #include <tasks/util/pcg32.hpp>
    #include <tasks/util/work_stealing_deque.hpp>

    // Core layers, in dependency order.
    #include <tasks/core/driver.hpp>
    #include <tasks/core/event.hpp>
    #include <tasks/core/pool.hpp>
    #include <tasks/core/queue.hpp>
    #include <tasks/core/router.hpp>
    #include <tasks/core/runtime.hpp>
    #include <tasks/core/worker.hpp>

namespace fast_task {
    // Thread-local worker context accessors. The storage itself is defined in
    // tasks/_internal.cpp so the definition order relative to the allocator
    // caches and `glob` is unchanged from the pre-split build.
    NOINLINE executors_local* get_loc() noexcept;
    void set_loc(executors_local*) noexcept;
}

#endif
