// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_INCLUDE_FUTEX
#define FAST_TASK_INCLUDE_FUTEX

#include "../task/task.hpp"
#include <chrono>
#include <cstdint>

namespace fast_task::futex {
    void FT_API wait_on_address(void* address, bool (*check_callback)(void*));
    bool FT_API wait_on_address_until(void* address, bool (*check_callback)(void*), std::chrono::high_resolution_clock::time_point time_point);

    void FT_API unlock_and_wait(void* address, bool (*check_callback)(void*), void* lock_address, void (*make_unlock_callback)(void*), bool (*is_unlocked_callback)(void*, bool mark_request));
    bool FT_API unlock_and_wait_until(void* address, bool (*check_callback)(void*), void* lock_address, void (*make_unlock_callback)(void*), bool (*is_unlocked_callback)(void*, bool mark_request), std::chrono::high_resolution_clock::time_point time_point);


    size_t FT_API wake_and_requeue_on_address(void* address, size_t process_count = SIZE_MAX, size_t wake_count = 1);
    size_t FT_API wake_and_requeue_on_address(void* address, void (*pre_release)(void*, size_t to_process, bool has_remaining), size_t process_count = SIZE_MAX, size_t wake_count = 1);


    size_t FT_API wait_items_on(void* address);
    bool FT_API has_waiters(void* address);
    bool FT_API has_waiters_callback(void* address, void (*callback)(void* address, void* data, bool result), void* data);

    inline size_t FT_API wake_on_address(void* address, void (*pre_release)(void*, size_t to_process, bool has_remaining), size_t count = 1) {
        return wake_and_requeue_on_address(address, pre_release, count, SIZE_MAX);
    }

    inline size_t FT_API wake_on_address(void* address, size_t count = 1) {
        return wake_and_requeue_on_address(address, count, SIZE_MAX);
    }

    bool FT_API enter_wait_on_address(const task& task_obj, void* address, bool (*check_callback)(void*), enter_state& state);
    bool FT_API enter_wait_on_address_until(const task& task_obj, void* address, bool (*check_callback)(void*), enter_state& state, std::chrono::high_resolution_clock::time_point time_point);
    bool FT_API enter_unlock_and_wait(const task& task_obj, void* address, bool (*check_callback)(void*), void* lock_address, void (*make_unlock_callback)(void*), bool (*is_unlocked_callback)(void*, bool mark_request), enter_state& state);
    bool FT_API enter_unlock_and_wait_until(const task& task_obj, void* address, bool (*check_callback)(void*), void* lock_address, void (*make_unlock_callback)(void*), bool (*is_unlocked_callback)(void*, bool mark_request), enter_state& state, std::chrono::high_resolution_clock::time_point time_point);

    bool FT_API enter_wait_on_address_lock(const task& task_obj, void* address, bool (*check_callback)(void*), void (*lock_callback)(void*, const task& task_obj), enter_state& state);
    bool FT_API enter_wait_on_address_lock_until(const task& task_obj, void* address, bool (*check_callback)(void*), void (*lock_callback)(void*, const task& task_obj), enter_state& state, std::chrono::high_resolution_clock::time_point time_point);
}

#endif /* FAST_TASK_INCLUDE_TASK_FUTEX */
