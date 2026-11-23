// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <tasks/_internal.hpp>

namespace fast_task {
    std::atomic<size_t> threads_manager::total_active_{0};
    std::atomic<size_t> threads_manager::thread_count_{0};

    void threads_manager::count_thread_launch() noexcept {
        thread_count_.fetch_add(1, std::memory_order_acq_rel);
    }

    void threads_manager::count_thread_exit() noexcept {
        fast_task::lock_guard lock(glob.no_tasks.guard);
        thread_count_.fetch_sub(1, std::memory_order_acq_rel);
        glob.shutdown.notifier.notify_all();
    }
}
