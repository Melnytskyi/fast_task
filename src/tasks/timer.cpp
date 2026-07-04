// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <tasks/_internal.hpp>
#include <tasks/util/interrupt.hpp>
#include <tasks/util/light_stack.hpp>
#include <threading.hpp>

namespace fast_task {
#if defined(FT_TIMER_PRECISION) && FT_TIMER_PRECISION == 1 && \
    !defined(FT_HAS_HIRES_TIMER)
    static void hires_spin_sleep(std::chrono::high_resolution_clock::time_point deadline) {
        while (std::chrono::high_resolution_clock::now() < deadline) {
    #if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || \
        defined(_M_IX86)
            __builtin_ia32_pause();
    #elif defined(__aarch64__) || defined(_M_ARM64)
            __yield();
    #else
            std::atomic_signal_fence(std::memory_order_seq_cst);
    #endif
        }
    }
#endif

    static void smart_wait_until(futex_waiter& waiter, std::chrono::high_resolution_clock::time_point deadline) {
        auto now = std::chrono::high_resolution_clock::now();
        if (deadline <= now)
            return;
#if defined(FT_TIMER_PRECISION) && FT_TIMER_PRECISION == 1 && \
    !defined(FT_HAS_HIRES_TIMER)
        auto remaining = deadline - now;
        if (remaining <= std::chrono::microseconds(100)) {
            hires_spin_sleep(deadline);
            return;
        }
#endif
        waiter.wait_until(deadline);
    }

    void taskTimer() {
        _set_name_thread_dbg("task time controller");
        constexpr size_t BATCH = 64;
        task wake_ups[BATCH];
        task cold_wakes[BATCH];
        size_t wake_count = 0;
        size_t cold_count = 0;

        auto flush_wake_ups = [&] {
            for (size_t i = 0; i < wake_count; ++i)
                transfer_task(std::move(wake_ups[i]));
            wake_count = 0;
        };
        auto flush_cold = [&] {
            if (cold_count) {
                {
                    fast_task::shared_lock sg(glob.task_thread_safety);
                    for (size_t i = 0; i < cold_count; ++i)
                        glob.cold_tasks.enqueue(cold_wakes[i].release());
                }
                glob.tasks_notifier.unsafe_notify_all();
                cold_count = 0;
            }
        };

        auto enqueue_wake = [&](task&& t) {
            wake_ups[wake_count++] = std::move(t);
            if (wake_count == BATCH)
                flush_wake_ups();
        };
        auto enqueue_cold = [&](task&& t) {
            cold_wakes[cold_count++] = std::move(t);
            if (cold_count == BATCH)
                flush_cold();
        };

        auto handle_expired = [&](timing& tmng) {
            if (tmng.check_id != get_data(tmng.awake_task).awake_check)
                return;

            if (tmng.is_cold) {
                enqueue_cold(std::move(tmng.awake_task));
            } else {
                fast_task::lock_guard tg(get_data(tmng.awake_task));
                if (get_data(tmng.awake_task).get_awaked())
                    return;
                get_data(tmng.awake_task).set_time_end(true);
                enqueue_wake(std::move(tmng.awake_task));
            }
        };

        while (glob.time_control_enabled.load(std::memory_order_relaxed)) {
            auto current_now = std::chrono::high_resolution_clock::now();

            if (glob.shutdown_requested.load(std::memory_order_acquire)) {
                glob.timed_wheel.clear([&](timing& tmng) {
                    if (tmng.check_id ==
                        get_data(tmng.awake_task).awake_check) {
                        handle_expired(tmng);
                    }
                });
            } else
                glob.timed_wheel.collect_expired(current_now, handle_expired);
            flush_wake_ups();
            flush_cold();

            {
                fast_task::shared_lock sg(glob.task_thread_safety);
                glob.no_tasks_execute_notifier.notify_all();
            }

            check_stw();

            if (!glob.time_control_enabled.load(std::memory_order_relaxed))
                break;

            //glob.timer_waiter.consume_wake();
            auto next_deadline = glob.timed_wheel.next_deadline();

            if (next_deadline == std::chrono::high_resolution_clock::time_point::max())
                glob.timer_waiter.wait();
            else
                smart_wait_until(glob.timer_waiter, next_deadline);
        }

        flush_wake_ups();
        flush_cold();

        fast_task::shared_lock _guard(glob.task_thread_safety);
        get_loc().reset();
        --glob.thread_count;
        glob.executor_shutdown_notifier.notify_all();
    }

    void startTimeController() {
        if (glob.time_control_enabled.load(std::memory_order_acquire))
            return;
        bool expected = false;
        if (glob.time_control_enabled.compare_exchange_strong(expected, true, std::memory_order_acquire)) {
            ++glob.thread_count;
            fast_task::thread(taskTimer).detach();
        }
    }

    inline void put_task_to_wheel(
        hashed_timing_wheel& wheel,
        std::chrono::high_resolution_clock::time_point t,
        task& task
    ) {
        wheel.insert(wheel.to_ticks(t), task, get_data(task).awake_check, !can_be_scheduled_task_to_hot());
    }

    void makeTimeWait_extern(task _task, std::chrono::high_resolution_clock::time_point time_point) {
        startTimeController();
        get_data(_task).set_awaked(false);
        get_data(_task).set_time_end(false);

        put_task_to_wheel(glob.timed_wheel, time_point, _task);
        glob.timer_waiter.notify_one();
    }

    void makeTimeWait(std::chrono::high_resolution_clock::time_point t) {
        startTimeController();
        auto& loc = get_loc();
        get_data(loc.curr_task).set_awaked(false);
        get_data(loc.curr_task).set_time_end(false);

        put_task_to_wheel(glob.timed_wheel, t, loc.curr_task);
        glob.timer_waiter.notify_one();
    }

    void resetTimeWait() {
        auto& loc = get_loc();
        get_data(loc.curr_task).set_awaked(false);
        get_data(loc.curr_task).set_time_end(false);
    }
} // namespace fast_task