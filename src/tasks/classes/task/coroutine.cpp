// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)
#include <task.hpp>

namespace fast_task {
    std::suspend_always task_promise_base::initial_suspend() noexcept {
        return {};
    }

    std::suspend_always task_promise_base::final_suspend() noexcept {
        fast_task::lock_guard guard(get_data(task_object).no_race);
        get_data(task_object).callbacks.extended_mode.is_restartable = false;
        get_data(task_object).end_of_life = true;
        get_data(task_object).result_notify.notify_all();
        return {};
    }
}