// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_CORE_RUNTIME
#define FAST_TASK_CORE_RUNTIME

#include <atomic>
#include <cstddef>

#include <fast_task/native/condition_variable.hpp>
#include <fast_task/native/mutex.hpp>
#include <fast_task/shared.hpp>
#include <tasks/core/notify/driver.hpp>
#include <tasks/core/pool/pool.hpp>
#include <tasks/core/runtime/allocators.hpp>
#include <tasks/core/runtime/futex_global.hpp>
#include <tasks/core/runtime/hdi.hpp>
#include <tasks/core/runtime/pool_manager.hpp>
#include <tasks/core/runtime/stw.hpp>
#include <tasks/util/macro.hpp>

namespace fast_task {
    struct executors_local;

    struct FT_API_LOCAL scheduler_runtime {
        struct no_tasks_state {
            fast_task::native::rw_mutex guard;
            condition_variable_any notifier;
            std::atomic<uint32_t> waiters{0};
        };

        struct timing_state {
            hashed_timing_wheel wheel;
            std::atomic<bool> enabled{false};
        };

        struct shutdown_state {
            std::atomic<bool> requested{false};
            std::atomic<bool> executors_down{false};
            fast_task::native::condition_variable_any notifier;
        };

        runtime_allocators allocators;
        no_tasks_state no_tasks;

        driver_context driver;
        pool_manager pools;

        timing_state timing;
        shutdown_state shutdown;

        alignas(hardware_destructive_interference_size) std::atomic_size_t interrupts = 0;
#ifndef NDEBUG
        alignas(hardware_destructive_interference_size) std::atomic_size_t tasks_in_swap = 0;
#endif

        stw_manager stw;
        futex_global_t futex_global;

        scheduler_runtime();
        ~scheduler_runtime();
    };

    extern FT_API_LOCAL scheduler_runtime glob;

    inline worker_pool_storage* pool_for_index(uint8_t index) noexcept {
        return glob.pools.find(index);
    }

    inline worker_pool_storage& global_storage() noexcept {
        return glob.pools.global();
    }

    NOINLINE executors_local* get_loc() noexcept;
    void set_loc(executors_local*) noexcept;
}

#endif /* FAST_TASK_CORE_RUNTIME */
