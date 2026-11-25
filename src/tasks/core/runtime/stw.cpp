// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <chrono>
#include <mutex>

#include <tasks/core/notify/pool_wake.hpp>
#include <tasks/core/pool/pool_table.hpp>
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
            stw.active_workers.fetch_add(1, std::memory_order_seq_cst);
            if (!stw.request.load(std::memory_order_seq_cst)) {
                held = true;
                return;
            }
            stw.active_workers.fetch_sub(1, std::memory_order_seq_cst);
            stw.cv.notify_all();
            fast_task::unique_lock guard(stw.cv_mutex);
            while (stw.request.load(std::memory_order_seq_cst))
                stw.cv.wait(guard);
        }
    }

    void stw_active_guard::release() {
        if (!held)
            return;
        held = false;
        glob.stw.active_workers.fetch_sub(1, std::memory_order_seq_cst);
        glob.stw.cv.notify_all();
    }

    void unsafe_perform_stop_the_world(const std::function<void()>& work) {
        std::lock_guard lock(glob.stw.request_mutex);
        glob.stw.request.store(true, std::memory_order_seq_cst);

        struct stw_release_guard {
            ~stw_release_guard() {
                fast_task::unique_lock guard(glob.stw.cv_mutex);
                glob.stw.request.store(false, std::memory_order_seq_cst);
                glob.stw.cv.notify_all();
            }
        } release_guard;

        for (uint16_t i = 0; i < pool_table_size; ++i) {
            if (auto pool = acquire_pool_ref(static_cast<uint8_t>(i)))
                wake_control(*pool);
        }

        {
            fast_task::unique_lock guard(glob.stw.cv_mutex);
            while (glob.stw.active_workers.load(std::memory_order_seq_cst) != 0)
                glob.stw.cv.wait_for(guard, std::chrono::milliseconds(1));
        }

        work();
    }
}
