// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <chrono>
#include <mutex>

#include <tasks/core/notify/pool_wake.hpp>
#include <tasks/core/runtime/runtime.hpp>
#include <tasks/core/runtime/stw.hpp>

namespace fast_task {
    stw_active_guard::stw_active_guard() {
        reacquire();
    }

    stw_active_guard::~stw_active_guard() {
        if (held)
            release();
    }

    void stw_active_guard::reacquire() {
        if (held)
            return;
        auto& stw = glob.stw;
        for (;;) {
            stw.active_workers.fetch_add(1, std::memory_order_acq_rel);
            if (!stw.request.load(std::memory_order_acquire)) {
                held = true;
                return;
            }
            stw.active_workers.fetch_sub(1, std::memory_order_acq_rel);
            stw.cv.notify_all();
            fast_task::unique_lock guard(stw.cv_mutex);
            while (stw.request.load(std::memory_order_acquire))
                stw.cv.wait(guard);
        }
    }

    void stw_active_guard::release() {
        if (!held)
            return;
        held = false;
        glob.stw.active_workers.fetch_sub(1, std::memory_order_acq_rel);
        glob.stw.cv.notify_all();
    }

    void unsafe_perform_stop_the_world(const std::function<void()>& work) {
        std::lock_guard lock(glob.stw.request_mutex);
        glob.stw.request.store(true, std::memory_order_seq_cst);
        wake_control(global_storage());

        {
            fast_task::unique_lock guard(glob.stw.cv_mutex);
            while (glob.stw.active_workers.load(std::memory_order_seq_cst) != 0)
                glob.stw.cv.wait_for(guard, std::chrono::milliseconds(1));
        }

        work();
        {
            fast_task::unique_lock guard(glob.stw.cv_mutex);
            glob.stw.request.store(false, std::memory_order_seq_cst);
            glob.stw.cv.notify_all();
        }
    }
}
