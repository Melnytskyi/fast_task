// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_CORE_ROUTER
#define FAST_TASK_CORE_ROUTER

#include <fast_task/shared.hpp>
#include <fast_task/task/task.hpp>

namespace fast_task {
    class enter_state;

    void FT_API_LOCAL route_task(task&&, enter_state* stat = nullptr, bool pre_scheduled = false);
    void FT_API_LOCAL transfer_task(task&&, enter_state* stat = nullptr);
    bool FT_API_LOCAL can_be_scheduled_task_to_hot();
}

#endif /* FAST_TASK_CORE_ROUTER */
