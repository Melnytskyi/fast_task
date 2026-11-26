// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_CORE_TASK_ACCESS
#define FAST_TASK_CORE_TASK_ACCESS

#include <atomic>
#include <chrono>
#include <cstddef>
#include <exception>

#include <boost/context/continuation.hpp>

#include <fast_task/internal/task_object.hpp>
#include <fast_task/shared.hpp>
#include <fast_task/task.hpp>
#include <tasks/core/execution/preemption.hpp>

#if defined(__SANITIZE_THREAD__)
    #define FT_TSAN_ENABLED 1
#elif defined(__has_feature)
    #if __has_feature(thread_sanitizer)
        #define FT_TSAN_ENABLED 1
    #endif
#endif
#ifdef FT_TSAN_ENABLED
    #include <sanitizer/tsan_interface.h>
#endif

namespace fast_task {
    struct FT_API_LOCAL task_object::execution_data {
        fast_task::time_point::rep timeout = fast_task::time_point::min().time_since_epoch().count();
        boost::context::continuation context;
        size_t context_switch_count = 0;
#ifdef FT_ENABLE_PREEMPTIVE_SCHEDULER
        std::chrono::nanoseconds current_available_quantum = std::chrono::nanoseconds(0);
        task_priority priority = task_priority::high;
        size_t interrupt_count = 0;
        size_t interrupt_data = 0;
#endif
#if PLATFORM_LINUX
        void* stack_ptr = nullptr;
        size_t stack_size = 0;
        unsigned int valgrind_stack_id = 0;
#endif
#if defined(FT_EXCEPTION_POLICY_PRESERVE)
        std::exception_ptr switch_preserve;
#endif
#ifdef FT_TSAN_ENABLED
        void* tsan_fiber = nullptr;

        ~execution_data() {
            if (tsan_fiber) {
                if (context) {
                    void* caller_fiber = __tsan_get_current_fiber();
                    __tsan_switch_to_fiber(tsan_fiber, 0);
                    context = boost::context::continuation{};
                    __tsan_switch_to_fiber(caller_fiber, 0);
                }
                __tsan_destroy_fiber(tsan_fiber);
                tsan_fiber = nullptr;
            }
        }
#endif
    };

    inline auto FT_API_LOCAL get_data(const class task& task) -> task_object& {
        return *task.obj;
    }

    inline auto FT_API_LOCAL get_data(class task* task) -> task_object& {
        return *task->obj;
    }

    FT_API_LOCAL task_object::execution_data* acquire_execution_data() noexcept;
    void FT_API_LOCAL release_execution_data(task_object::execution_data* data) noexcept;

    inline auto FT_API_LOCAL execution_data_of(std::atomic<task_object::execution_data*>& slot) -> task_object::execution_data& {
        auto* p = slot.load(std::memory_order_acquire);
        if (!p) {
            task_object::execution_data* fresh = acquire_execution_data();
            task_object::execution_data* expected = nullptr;
            if (slot.compare_exchange_strong(expected, fresh, std::memory_order_acq_rel, std::memory_order_acquire))
                p = fresh;
            else {
                release_execution_data(fresh);
                p = expected;
            }
        }
        return *p;
    }

    inline auto FT_API_LOCAL get_execution_data(class task* task) -> task_object::execution_data& {
        return execution_data_of(get_data(task).exdata);
    }

    inline auto FT_API_LOCAL get_execution_data(task_object* task) -> task_object::execution_data& {
        return execution_data_of(task->exdata);
    }

    inline auto FT_API_LOCAL get_execution_data(class task& task) -> task_object::execution_data& {
        return get_execution_data(&task);
    }

    inline auto FT_API_LOCAL get_execution_data(const class task& task) -> task_object::execution_data& {
        return get_execution_data(const_cast<class task*>(&task));
    }
}

#endif /* FAST_TASK_CORE_TASK_ACCESS */
