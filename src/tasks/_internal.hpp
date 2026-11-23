// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

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
    #include <tasks/util/cpu_relax.hpp>
    #include <tasks/util/fixed_task_allocator.hpp>
    #include <tasks/util/hashed_timing_wheel.hpp>
    #include <tasks/util/macro.hpp>
    #include <tasks/util/pcg32.hpp>
    #include <tasks/util/work_stealing_deque.hpp>

    #include <tasks/core/execution/preemption.hpp>
    #include <tasks/core/pool/dormant_broker.hpp>
    #include <tasks/core/runtime/allocators.hpp>
    #include <tasks/core/runtime/debug_objects.hpp>
    #include <tasks/core/runtime/hdi.hpp>
    #include <tasks/core/runtime/thread_identity.hpp>

    #include <tasks/core/notify/driver.hpp>
    #include <tasks/core/notify/event.hpp>
    #include <tasks/core/notify/notifier.hpp>

    #include <tasks/core/pool/executor_registry.hpp>
    #include <tasks/core/pool/pool.hpp>
    #include <tasks/core/pool/pool_balancer.hpp>
    #include <tasks/core/pool/pool_dormant.hpp>
    #include <tasks/core/pool/pool_impl.hpp>
    #include <tasks/core/pool/pool_lifecycle.hpp>
    #include <tasks/core/pool/pool_ops.hpp>
    #include <tasks/core/pool/pool_storage.hpp>
    #include <tasks/core/pool/pool_table.hpp>
    #include <tasks/core/pool/queue_storage.hpp>
    #include <tasks/core/pool/router.hpp>
    #include <tasks/core/pool/threads_manager.hpp>

    #include <tasks/core/runtime/pool_manager.hpp>
    #include <tasks/core/runtime/runtime.hpp>
    #include <tasks/core/runtime/stw.hpp>

    #include <tasks/core/execution/context_impl.hpp>
    #include <tasks/core/execution/context_switch.hpp>
    #include <tasks/core/execution/executor_wake.hpp>
    #include <tasks/core/execution/executors_local.hpp>
    #include <tasks/core/execution/task_access.hpp>
    #include <tasks/core/execution/task_accounting.hpp>
    #include <tasks/core/execution/worker.hpp>

    #include <tasks/core/notify/pool_wake.hpp>

#endif
