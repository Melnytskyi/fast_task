// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_INCLUDE_TASK_ONCE
#define FAST_TASK_INCLUDE_TASK_ONCE

#include "../internal/futex.hpp"
#include <atomic>
#include <cstdint>
#include <functional>
#include <utility>

namespace fast_task {
    // Task-friendly std::once_flag backed by fast_task::futex.
    // Contending tasks yield their green thread instead of blocking the OS worker.
    class once_flag {
        static constexpr uint8_t UNINIT = 0;
        static constexpr uint8_t RUNNING = 1;
        static constexpr uint8_t RUNNING_WAITERS = 2;
        static constexpr uint8_t DONE = 3;

        std::atomic<uint8_t> state_{UNINIT};

        static bool check_ready(void* addr) noexcept {
            auto& st = *reinterpret_cast<std::atomic<uint8_t>*>(addr);
            uint8_t cur = st.load(std::memory_order_acquire);
            for (;;) {
                if (cur == DONE || cur == UNINIT)
                    return true;
                if (cur == RUNNING_WAITERS)
                    return false;
                if (st.compare_exchange_weak(cur, RUNNING_WAITERS, std::memory_order_acq_rel, std::memory_order_acquire))
                    return false;
            }
        }

        template <class Fn, class... Args>
        friend void call_once(once_flag& flag, Fn&& fn, Args&&... args);

    public:
        constexpr once_flag() noexcept = default;
        once_flag(const once_flag&) = delete;
        once_flag& operator=(const once_flag&) = delete;
        once_flag(once_flag&&) = delete;
        once_flag& operator=(once_flag&&) = delete;

        bool is_done() const noexcept {
            return state_.load(std::memory_order_acquire) == DONE;
        }
    };

    template <class Fn, class... Args>
    void call_once(once_flag& flag, Fn&& fn, Args&&... args) {
        if (flag.state_.load(std::memory_order_acquire) == once_flag::DONE)
            return;

        for (;;) {
            uint8_t expected = once_flag::UNINIT;
            if (flag.state_.compare_exchange_strong(
                    expected, once_flag::RUNNING, std::memory_order_acq_rel, std::memory_order_acquire
                )) {
                struct rollback_guard {
                    std::atomic<uint8_t>& st;
                    bool committed = false;

                    ~rollback_guard() noexcept {
                        if (!committed) {
                            uint8_t prev = st.exchange(once_flag::UNINIT, std::memory_order_acq_rel);
                            if (prev == once_flag::RUNNING_WAITERS)
                                futex::wake_on_address(&st, SIZE_MAX);
                        }
                    }
                } guard{flag.state_};

                std::invoke(std::forward<Fn>(fn), std::forward<Args>(args)...);
                guard.committed = true;
                uint8_t prev = flag.state_.exchange(once_flag::DONE, std::memory_order_acq_rel);
                if (prev == once_flag::RUNNING_WAITERS)
                    futex::wake_on_address(&flag.state_, SIZE_MAX);
                return;
            }

            if (expected == once_flag::DONE)
                return;

            futex::wait_on_address(&flag.state_, &once_flag::check_ready);
        }
    }
}

#endif /* FAST_TASK_INCLUDE_TASK_ONCE */
