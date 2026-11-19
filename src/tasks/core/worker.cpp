// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)
//
// Worker-layer implementation: the quantum helpers and the local context
// lifecycle. Moved verbatim out of tasks/_internal.cpp by S0b
// (plans/pool-architecture.md §4); no behaviour changes.

#include <tasks/_internal.hpp>

namespace fast_task {
    inline static constexpr std::chrono::nanoseconds priority_quantum_basic[] = {
        std::chrono::nanoseconds(FT_PREEMPT_BACKGROUND_BASIC_QUANTUM_NS),
        std::chrono::nanoseconds(FT_PREEMPT_LOW_BASIC_QUANTUM_NS),
        std::chrono::nanoseconds(FT_PREEMPT_LOWER_BASIC_QUANTUM_NS),
        std::chrono::nanoseconds(FT_PREEMPT_NORMAL_BASIC_QUANTUM_NS),
        std::chrono::nanoseconds(FT_PREEMPT_HIGHER_BASIC_QUANTUM_NS),
        std::chrono::nanoseconds(FT_PREEMPT_HIGH_BASIC_QUANTUM_NS),
        std::chrono::nanoseconds::min()
    };

    inline static constexpr std::chrono::nanoseconds priority_quantum_max[] = {
        std::chrono::nanoseconds(FT_PREEMPT_BACKGROUND_MAX_QUANTUM_NS),
        std::chrono::nanoseconds(FT_PREEMPT_LOW_MAX_QUANTUM_NS),
        std::chrono::nanoseconds(FT_PREEMPT_LOWER_MAX_QUANTUM_NS),
        std::chrono::nanoseconds(FT_PREEMPT_NORMAL_MAX_QUANTUM_NS),
        std::chrono::nanoseconds(FT_PREEMPT_HIGHER_MAX_QUANTUM_NS),
        std::chrono::nanoseconds(FT_PREEMPT_HIGH_MAX_QUANTUM_NS),
        std::chrono::nanoseconds::min()
    };

    std::chrono::nanoseconds next_quantum(task_priority priority, std::chrono::nanoseconds& current_available_quantum) {
        if (priority == task_priority::semi_realtime)
            return std::chrono::nanoseconds::min();

        current_available_quantum += priority_quantum_basic[(size_t)priority];
        if (current_available_quantum > priority_quantum_max[(size_t)priority])
            current_available_quantum = priority_quantum_max[(size_t)priority];
        return current_available_quantum > std::chrono::nanoseconds(0) ? current_available_quantum : std::chrono::nanoseconds(0);
    }

    std::chrono::nanoseconds peek_quantum(task_priority priority, std::chrono::nanoseconds current_available_quantum) {
        if (priority == task_priority::semi_realtime)
            return std::chrono::nanoseconds::min();

        current_available_quantum += priority_quantum_basic[(size_t)priority];
        if (current_available_quantum > priority_quantum_max[(size_t)priority])
            current_available_quantum = priority_quantum_max[(size_t)priority];
        return current_available_quantum > std::chrono::nanoseconds(0) ? current_available_quantum : std::chrono::nanoseconds(0);
    }

    void task_switch(task_priority priority, std::chrono::nanoseconds& current_available_quantum, std::chrono::nanoseconds elapsed) {
        if (priority == task_priority::semi_realtime)
            return;
        current_available_quantum -= elapsed;
    }

    std::chrono::nanoseconds init_quantum(task_priority priority) {
        return priority_quantum_basic[(size_t)priority];
    }

    void executors_local::reset() {
        ex_ptr = nullptr;
        curr_task.reset();
        transfer_state.pending.reset();
        pending_timer = fast_task::time_point::min();
        run_next = nullptr;
        completed_tasks_batch = 0;
    }

    executors_local::~executors_local() {
        reset();
    }
}
