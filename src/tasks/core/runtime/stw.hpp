// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_CORE_STW
#define FAST_TASK_CORE_STW

#include <atomic>
#include <cstddef>
#include <functional>

#include <fast_task/native/condition_variable.hpp>
#include <fast_task/native/mutex.hpp>
#include <fast_task/shared.hpp>
#include <tasks/core/runtime/hdi.hpp>

namespace fast_task {
    struct FT_API_LOCAL stw_manager {
        std::atomic<bool> request{false};
        std::atomic<size_t> serving_contexts{0};
        fast_task::native::mutex request_mutex;

        alignas(hardware_destructive_interference_size) std::atomic<size_t> active_workers{0};
        fast_task::native::mutex cv_mutex;
        fast_task::native::condition_variable_any cv;
    };

    struct FT_API_LOCAL stw_active_guard {
        bool held = false;

        stw_active_guard();
        ~stw_active_guard();
        stw_active_guard(const stw_active_guard&) = delete;
        stw_active_guard& operator=(const stw_active_guard&) = delete;

        void reacquire();
        void release();
    };

    void FT_API_LOCAL unsafe_perform_stop_the_world(const std::function<void()>& work);

    template <class Mut>
    void FT_API_LOCAL check_stw(Mut&) {}

    inline void FT_API_LOCAL check_stw() {}
}

#endif /* FAST_TASK_CORE_STW */
