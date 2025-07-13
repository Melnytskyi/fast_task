// Copyright Danyil Melnytskyi 2022-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_CPU_USAGE
#define FAST_TASK_CPU_USAGE
#include <cstdint>

namespace fast_task::util::cpu {
    struct usage_prev_stat {
        uint64_t total_ticks = 0;
        uint64_t idle_ticks = 0;
    };

    double get_usage(usage_prev_stat& prev_stat);
    double get_usage_percents(usage_prev_stat& prev_stat);
}


#endif /* SRC_RUN_TIME_TASKS_UTIL_CPU_USAGE */
