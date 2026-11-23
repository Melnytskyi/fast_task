// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_CORE_CONTEXT_IMPL
#define FAST_TASK_CORE_CONTEXT_IMPL

#include <cstddef>
#include <string>

#include <fast_task/shared.hpp>
#include <fast_task/task/scheduler.hpp>
#include <tasks/core/execution/worker.hpp>

namespace fast_task::scheduler {
    struct FT_API_LOCAL worker_context_impl {
        executors_local local;
        worker_context* owner = nullptr;
        std::string saved_thread_name;
        bool joined = false;
        bool spawned = false;

        static worker_context_impl& of(worker_context& ctx) noexcept;

        worker_pool_storage* pool() const noexcept {
            return local.owner_pool;
        }

        void join(worker_pool_storage& target, bool is_spawned, bool count_live);
        void leave(bool count_live, bool count_active) noexcept;
        bool shutting_down() const noexcept;
        size_t poll(size_t count);
        size_t poll_drained();
        size_t poll_all();
        size_t poll_until(size_t count, fast_task::time_point time_point);
        bool next_until(fast_task::time_point time_point);
    };
}

#endif /* FAST_TASK_CORE_CONTEXT_IMPL */
