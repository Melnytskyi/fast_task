// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <fast_task/native.hpp>
#include <fast_task/task.hpp>
#include <tasks/_internal.hpp>
#include <tasks/util/interrupt.hpp>
#include <tasks/util/light_stack.hpp>

namespace fast_task {
    std::atomic<size_t> task::max_running_tasks{0};

    void taskExecutor(worker_entry_options options) {
        set_interruptTask();

        {
            scheduler::worker_context_options ctx_options;
            ctx_options.prevent_thread_naming = options.prevent_naming;
            scheduler::worker_context ctx(ctx_options);
            scheduler::worker_context_impl::of(ctx).join(global_storage(), true, true);
            if (options.mode == worker_entry::until_drained)
                ctx.poll_drained();
            else
                ctx.poll_all();
        }

        threads_manager::count_thread_exit();
    }

    void pool_worker_main(uint8_t slot) {
        set_interruptTask();

        pool_ref ref = acquire_pool_ref(slot);
        if (!ref) {
            threads_manager::count_thread_exit();
            return;
        }

        {
            scheduler::worker_context ctx;
            try {
                scheduler::worker_context_impl::of(ctx).join(*ref, true, true);
            } catch (...) {
                threads_manager::count_thread_exit();
                return;
            }
            ctx.poll_all();
        }

        threads_manager::count_thread_exit();
    }
}
