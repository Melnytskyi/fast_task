// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_CORE_QUEUE_STORAGE
#define FAST_TASK_CORE_QUEUE_STORAGE

#include <array>
#include <cstddef>

#include <concurrentqueue/moodycamel/concurrentqueue.h>

#include <fast_task/shared.hpp>
#include <fast_task/task.hpp>
#include <fast_task/task/scheduler.hpp>

namespace fast_task {
    template <scheduler::queue_policy Q>
    struct queue_storage;

    template <>
    struct FT_API_LOCAL queue_storage<scheduler::queue_policy::work_stealing_lifo> {
        moodycamel::ConcurrentQueue<task_object*> tasks;
        moodycamel::ConcurrentQueue<task_object*> cold_tasks;
    };

    inline constexpr size_t priority_level_count =
        static_cast<size_t>(task_priority::semi_realtime) + 1;

    template <>
    struct FT_API_LOCAL queue_storage<scheduler::queue_policy::priority_fifo> {
        std::array<moodycamel::ConcurrentQueue<task_object*>, priority_level_count> tasks;
        moodycamel::ConcurrentQueue<task_object*> cold_tasks;
    };
}

#endif /* FAST_TASK_CORE_QUEUE_STORAGE */
