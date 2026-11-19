// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)
//
// Worker layer: the per-thread executor context, the per-task execution data,
// the quantum helpers and the entry points implemented by the worker loops in
// tasks/scheduler.cpp. Split out of tasks/_internal.hpp by S0b
// (plans/pool-architecture.md §4) without behaviour changes. S2a/S2c rewrite
// `executors_local` (pool index, per-pool accounting) and add join/leave.

#ifndef FAST_TASK_CORE_WORKER
#define FAST_TASK_CORE_WORKER

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <string>

#include <boost/context/continuation.hpp>

#include <fast_task/internal/task_object.hpp>
#include <fast_task/shared.hpp>
#include <fast_task/task.hpp>
#include <tasks/core/pool.hpp>
#include <tasks/core/queue.hpp>
#include <tasks/util/macro.hpp>
#include <tasks/util/pcg32.hpp>
#include <tasks/util/work_stealing_deque.hpp>

namespace fast_task {

    struct FT_API_LOCAL task_object::execution_data {
        fast_task::time_point::rep timeout = fast_task::time_point::min().time_since_epoch().count();
        boost::context::continuation context;
        size_t context_switch_count = 0;
    #ifdef FT_ENABLE_PREEMPTIVE_SCHEDULER
        std::chrono::nanoseconds current_available_quantum = std::chrono::nanoseconds(0);
        task_priority priority = task_priority::high;
        size_t interrupt_count = 0;
        size_t interrupt_data = 0; //used only when task requested switch but it has interrupt lock
    #endif
    #if PLATFORM_LINUX
        void* stack_ptr = nullptr;
        size_t stack_size = 0;
        unsigned int valgrind_stack_id = 0;
    #endif
    #if defined(FT_EXCEPTION_POLICY_PRESERVE)
        std::exception_ptr switch_preserve;
    #endif
    };

    inline auto FT_API_LOCAL get_data(const class task& task) -> task_object& {
        return *task.obj;
    }

    inline auto FT_API_LOCAL get_data(class task* task) -> task_object& {
        return *task->obj;
    }

    inline auto FT_API_LOCAL get_execution_data(class task* task) -> task_object::execution_data& {
        auto& slot = get_data(task).exdata;
        auto* p = slot.load(std::memory_order_acquire);
        if (!p) {
            p = new task_object::execution_data{};
            slot.store(p, std::memory_order_release);
        }
        return *p;
    }

    inline auto FT_API_LOCAL get_execution_data(task_object* task) -> task_object::execution_data& {
        auto& slot = task->exdata;
        auto* p = slot.load(std::memory_order_acquire);
        if (!p) {
            p = new task_object::execution_data{};
            slot.store(p, std::memory_order_release);
        }
        return *p;
    }

    inline auto FT_API_LOCAL get_execution_data(class task& task) -> task_object::execution_data& {
        return get_execution_data(&task);
    }

    inline auto FT_API_LOCAL get_execution_data(const class task& task) -> task_object::execution_data& {
        return get_execution_data(const_cast<class task*>(&task));
    }

    //per task has n quantum(ms) to execute depends on priority
    //if task spend it all it will be suspended
    //if task not spend it all, unused quantum will be added to next task quantum(ms limited by priority)
    //after resume if quantum is not more basic quantum, limit will be set to basic quantum
    //semi_realtime tasks has no limits
    //std::chrono::nanoseconds::min(); means no limit
    //std::chrono::nanoseconds(0); means no quantum, task last time spend more quantum than it has
    std::chrono::nanoseconds FT_API_LOCAL next_quantum(task_priority priority, std::chrono::nanoseconds& current_available_quantum);
    std::chrono::nanoseconds FT_API_LOCAL peek_quantum(task_priority priority, std::chrono::nanoseconds current_available_quantum);
    void FT_API_LOCAL task_switch(task_priority priority, std::chrono::nanoseconds& current_available_quantum, std::chrono::nanoseconds elapsed);
    std::chrono::nanoseconds FT_API_LOCAL init_quantum(task_priority priority);

    struct FT_API_LOCAL executors_local {
        // Inline (was std::unique_ptr) so the whole context can live inside
        // scheduler::worker_context::data[1024]. work_stealing_deque is
        // non-movable, therefore executors_local is non-movable as well and
        // must always be constructed in place.
        work_stealing_deque<task_object*> local_tasks{1024};

        // Hand-off slot used by driver_context to publish a single runnable
        // task without touching the deque.
        task_object* run_next = nullptr;

        // Pool this worker serves (plans/pool-architecture.md §2.2). It is
        // always set: the global pool has its own storage, so there is no
        // "null means global" special case. Set by the worker_context
        // constructor and cleared by its destructor; a pool cannot be erased
        // while one of its executors is still registered, so the pointer is
        // stable for the worker's lifetime.
        worker_pool_storage* owner_pool = nullptr;

        // Table slot of `owner_pool` (0..254 user, 255 global). This is what
        // the notification paths and the driver handshake compare, so they
        // never dereference a pool pointer on a hot path.
        uint8_t pool_index = global_pool_index;

        // Idle parking waits on the pool's `work_event` eventcount (signalled
        // by transfer_task on every enqueue) instead of a private futex waiter,
        // which nothing ever notified and which cost 128 bytes of the 1024 byte
        // budget.

        // Number of tasks completed since the last hill-climb sample.
        uint32_t completed_tasks_batch = 0;

        std::exception_ptr ex_ptr;
        task curr_task = nullptr;
        pcg32 rand;
        scheduler::worker_options options{};
        uint32_t registry_slot = UINT32_MAX;

        bool is_task_thread : 1 = false;
        bool context_in_swap : 1 = false;
        bool yield_request : 1 = false;

        struct {
            // Cached registry slot the last steal succeeded on, UINT32_MAX for
            // none. worker_registry_view::try_steal() uses it as the fast path
            // before falling back to a bounded random scan (§2.6).
            uint32_t last_slot = UINT32_MAX;
        } steal_cache;

        struct {
            task pending;
    #if FT_TASK_TRANSFERS_LIMIT > 0
            std::atomic_size_t transfers{(size_t)0};
    #endif
        } transfer_state;

        fast_task::time_point pending_timer = fast_task::time_point::min();

        // Convenience accessor kept so existing call sites stay readable.
        scheduler::preemption_policy& policy = options.policy;

        void reset();

        ~executors_local();
    };

    static_assert(sizeof(executors_local) <= 1024, "executors_local must fit into scheduler::worker_context::data[1024]");
    static_assert(alignof(executors_local) <= 64, "executors_local alignment must fit into scheduler::worker_context::data");

    // Worker-loop entry points, implemented in tasks/scheduler.cpp.
    void FT_API_LOCAL swapCtx();
    void FT_API_LOCAL swapCtxRelock(const mutex_unify& mut0);
    void FT_API_LOCAL swapCtxUnlock(const mutex_unify& mut0);
    bool FT_API_LOCAL checkCancellation() noexcept;
    void FT_API_LOCAL forceCancelCancellation(const task_cancellation& restart);

    void FT_API_LOCAL taskExecutor(bool end_in_task_out = false, bool prevent_naming = false);
    void FT_API_LOCAL bindedTaskExecutor(uint16_t id);

    // Shared with scheduler::worker_context (worker_context.cpp). These were
    // file-static inside scheduler.cpp; worker_context needs the exact same
    // scheduling semantics, so they are declared here instead of duplicated.
    //
    // One function serves both the global and the user pools now that every
    // pool has the same registry view (plans/pool-architecture.md §2.6).
    bool FT_API_LOCAL try_steal_from_registry(worker_registry_view& registry, task_object*& raw_curr_task);
    bool FT_API_LOCAL execute_task(const std::string& old_name);
}

#endif /* FAST_TASK_CORE_WORKER */
