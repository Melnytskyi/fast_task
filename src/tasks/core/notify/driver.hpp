// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_CORE_DRIVER
#define FAST_TASK_CORE_DRIVER

#include <atomic>
#include <cstddef>
#include <cstdint>

#include <fast_task/native/spin_lock.hpp>
#include <fast_task/shared.hpp>
#include <fast_task/task/task.hpp>
#include <tasks/core/runtime/hdi.hpp>

namespace fast_task {
    struct executors_local;

    struct alignas(hardware_destructive_interference_size) FT_API_LOCAL driver_context {
        fast_task::native::spin_lock driver_lock;
        std::atomic<uint32_t> wake_token{0};
        std::atomic<bool> claim_handoff{false};
        alignas(hardware_destructive_interference_size) std::atomic<bool> parked{false};
        std::atomic<uint16_t> parked_pool{UINT16_MAX};
        std::atomic<uint64_t> parked_deadline_ticks{UINT64_MAX};
        void poll(executors_local* loc);
        void park_until(executors_local* loc, fast_task::time_point max_wait, uint32_t token_before, uint32_t work_epoch_before);
        void wake();
        void handoff();
        void ensure_driver();
        void wake_driver_candidate();
    };

    void FT_API_LOCAL notify_driver_of_timer(uint64_t tick) noexcept;

    void FT_API_LOCAL startTimeController();
    void FT_API_LOCAL makeTimeWait(fast_task::time_point t);
    void FT_API_LOCAL makeTimeWait_extern(task, fast_task::time_point time_point);
    void FT_API_LOCAL resetTimeWait();
}

#endif /* FAST_TASK_CORE_DRIVER */
