// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <new>

#include <tasks/_internal.hpp>

namespace fast_task {
    namespace {
        constexpr uint32_t execution_data_cache_capacity = 16;

        struct execution_data_cache {
            void* free_list = nullptr;
            uint32_t count = 0;

            ~execution_data_cache() {
                while (free_list) {
                    void* node = free_list;
                    free_list = *static_cast<void**>(node);
                    ::operator delete(node);
                }
                count = 0;
            }
        };

        thread_local execution_data_cache cached_execution_data;
    }

    task_object::execution_data* acquire_execution_data() noexcept {
        if (cached_execution_data.free_list) {
            void* node = cached_execution_data.free_list;
            cached_execution_data.free_list = *static_cast<void**>(node);
            --cached_execution_data.count;
            return new (node) task_object::execution_data{};
        }
        return new task_object::execution_data{};
    }

    void release_execution_data(task_object::execution_data* data) noexcept {
        if (!data)
            return;
        data->~execution_data();
        if (cached_execution_data.count >= execution_data_cache_capacity) {
            ::operator delete(static_cast<void*>(data));
            return;
        }
        *reinterpret_cast<void**>(data) = cached_execution_data.free_list;
        cached_execution_data.free_list = data;
        ++cached_execution_data.count;
    }

    inline static constexpr std::chrono::nanoseconds priority_quantum_basic[] = {
        std::chrono::nanoseconds(FT_PREEMPT_BACKGROUND_BASIC_QUANTUM_NS),
        std::chrono::nanoseconds(FT_PREEMPT_LOW_BASIC_QUANTUM_NS),
        std::chrono::nanoseconds(FT_PREEMPT_LOWER_BASIC_QUANTUM_NS),
        std::chrono::nanoseconds(FT_PREEMPT_NORMAL_BASIC_QUANTUM_NS),
        std::chrono::nanoseconds(FT_PREEMPT_HIGHER_BASIC_QUANTUM_NS),
        std::chrono::nanoseconds(FT_PREEMPT_HIGH_BASIC_QUANTUM_NS),
        std::chrono::nanoseconds::zero()
    };

    inline static constexpr std::chrono::nanoseconds priority_quantum_max[] = {
        std::chrono::nanoseconds(FT_PREEMPT_BACKGROUND_MAX_QUANTUM_NS),
        std::chrono::nanoseconds(FT_PREEMPT_LOW_MAX_QUANTUM_NS),
        std::chrono::nanoseconds(FT_PREEMPT_LOWER_MAX_QUANTUM_NS),
        std::chrono::nanoseconds(FT_PREEMPT_NORMAL_MAX_QUANTUM_NS),
        std::chrono::nanoseconds(FT_PREEMPT_HIGHER_MAX_QUANTUM_NS),
        std::chrono::nanoseconds(FT_PREEMPT_HIGH_MAX_QUANTUM_NS),
        std::chrono::nanoseconds::zero()
    };

    std::chrono::nanoseconds next_quantum(task_priority priority, std::chrono::nanoseconds& current_available_quantum) {
        if (priority == task_priority::semi_realtime)
            return std::chrono::nanoseconds::zero();

        current_available_quantum += priority_quantum_basic[(size_t)priority];
        if (current_available_quantum > priority_quantum_max[(size_t)priority])
            current_available_quantum = priority_quantum_max[(size_t)priority];
        return current_available_quantum > std::chrono::nanoseconds(0) ? current_available_quantum : std::chrono::nanoseconds(0);
    }

    std::chrono::nanoseconds peek_quantum(task_priority priority, std::chrono::nanoseconds current_available_quantum) {
        if (priority == task_priority::semi_realtime)
            return std::chrono::nanoseconds::zero();

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
        batch.completed = 0;
        batch.executing = 0;
        slot_flags = 0;
    }

    executors_local::~executors_local() {
        reset();
    }
}
