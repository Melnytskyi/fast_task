// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_CORE_WORKER
#define FAST_TASK_CORE_WORKER

#include <cstdint>

#include <fast_task/shared.hpp>
#include <tasks/core/execution/context_switch.hpp>
#include <tasks/core/execution/executors_local.hpp>
#include <tasks/core/execution/task_access.hpp>
#include <tasks/util/macro.hpp>

namespace fast_task {
    enum class worker_entry : uint8_t {
        until_drained,
        until_shutdown,
    };

    struct worker_entry_options {
        worker_entry mode = worker_entry::until_shutdown;
        bool prevent_naming = false;
    };

    void FT_API_LOCAL taskExecutor(worker_entry_options options = {});

    void FT_API_LOCAL pool_worker_main(uint8_t slot);

    bool FT_API_LOCAL execute_task();
}

namespace fast_task::scheduler {
    void FT_API_LOCAL ensure_global_worker();
}

#endif /* FAST_TASK_CORE_WORKER */
