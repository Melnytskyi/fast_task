// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <tasks.hpp>
#include <tasks/_internal.hpp>

namespace fast_task {
    task_result::~task_result() {
        if (context) {
            delete context;
            context = nullptr;
        }
    }

    void task_result::awaitEnd(std::unique_lock<mutex_unify>& l) {
        while (!end_of_life)
            result_notify.wait(l);
    }

    task_result::task_result() = default;

    task_result::task_result(task_result&& move) noexcept {
        end_of_life = move.end_of_life;
        move.end_of_life = true;
    }
}
