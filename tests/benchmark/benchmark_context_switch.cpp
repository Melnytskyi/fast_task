// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include "benchmark_helpers.hpp"
#include <helpers.hpp>
#include <task.hpp>
#include <thread>
#include <vector>

static const scale_point c_switch_yield_burst_scales[] = {
    {"1K", 1'000},
    {"10K", 10'000},
    {"50K", 50'000},
    {"100K", 100'000},
    {"1M", 1'000'000},
    {"10M", 10'000'000},
};

BENCHMARK(c_switch_yield_burst, c_switch_yield_burst_scales) {
    fast_task::task t = fast_task::task::run([scale = scale] {
        for (uint64_t i = 0; i < scale; ++i)
            fast_task::this_task::yield();
    });

    t.await_task();
}

static const scale_point c_switch_stackful_scales[] = {
    {"1K", 1'000},
    {"10K", 10'000},
    {"50K", 50'000},
    {"100K", 100'000},
    {"1M", 1'000'000},
    {"10M", 10'000'000},
};

BENCHMARK(c_switch_stackful_yield_concurrent, c_switch_stackful_scales) {
    unsigned int hardware_threads = std::max(2u, std::thread::hardware_concurrency());
    unsigned int multiplier = 2;
    unsigned int task_count = hardware_threads * multiplier;

    uint64_t yields_per_task = scale / task_count;
    if (yields_per_task == 0)
        yields_per_task = 1;

    std::vector<fast_task::task> tasks;
    tasks.reserve(task_count);

    for (unsigned int i = 0; i < task_count; ++i) {
        tasks.push_back(fast_task::task::run([yields_per_task] {
            for (uint64_t j = 0; j < yields_per_task; ++j)
                fast_task::this_task::yield();
        }));
    }

    for (auto& t : tasks)
        t.await_task();
}

static const scale_point c_switch_pingpong_scales[] = {
    {"1K", 1'000},
    {"10K", 10'000},
    {"50K", 50'000},
    {"100K", 100'000},
    {"1M", 1'000'000},
    {"10M", 10'000'000},
};

static fast_task::task_vtable c_switch_transfer_vt{
    nullptr,
    nullptr,
    [](void* ptr) {
        struct shared_state {
            fast_task::task partner;
            int64_t remaining;
            bool yield = false;
            fast_task::enter_state state;
        };
        auto* s = static_cast<shared_state*>(ptr);
        if (s->remaining > 0) {
            if (!s->yield)
                --s->remaining;
            else
                s->yield = false;
            if (!fast_task::this_task::transfer_to(s->partner)) {
                s->yield = true;
                fast_task::this_task::enter_yield(s->state);
            }
            if (s->remaining == 0)
                fast_task::this_task::the_coroutine_ended(fast_task::scheduler::current_context_task());
        } else
            fast_task::this_task::the_coroutine_ended(fast_task::scheduler::current_context_task());
    },
    nullptr,
    nullptr,
    false
};

BENCHMARK(c_switch_transfer_pingpong, c_switch_pingpong_scales) {
    struct shared_state {
        fast_task::task partner;
        int64_t remaining;
        bool yield = false;
        fast_task::enter_state state;
    };

    shared_state state_a, state_b;
    state_a.remaining = scale;
    state_b.remaining = scale;

    auto task_a = fast_task::task(&state_a, &c_switch_transfer_vt, true, true);
    auto task_b = fast_task::task(&state_b, &c_switch_transfer_vt, true, true);

    state_a.partner = fast_task::task(task_b);
    state_b.partner = fast_task::task(task_a);

    task_a.await_task();
    fast_task::task::await_task(task_b, false);
}
