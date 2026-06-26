
#include <tasks/_internal.hpp>
#include <tasks/util/interrupt.hpp>
#include <tasks/util/light_stack.hpp>
#include <threading.hpp>

namespace fast_task {
#if defined(FT_TIMER_PRECISION) && FT_TIMER_PRECISION == 1 && !defined(FT_HAS_HIRES_TIMER)
    static void hires_spin_sleep(std::chrono::high_resolution_clock::time_point deadline) {
        while (std::chrono::high_resolution_clock::now() < deadline) {
    #if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
            __builtin_ia32_pause();
    #elif defined(__aarch64__) || defined(_M_ARM64)
            __yield();
    #else
            std::atomic_signal_fence(std::memory_order_seq_cst);
    #endif
        }
    }
#endif
    static void smart_wait_until(fast_task::unique_lock<fast_task::mutex>& guard, std::chrono::high_resolution_clock::time_point deadline) {
        auto now = std::chrono::high_resolution_clock::now();
        if (deadline <= now)
            return;
#if defined(FT_TIMER_PRECISION) && FT_TIMER_PRECISION == 1 && !defined(FT_HAS_HIRES_TIMER)
        auto remaining = deadline - now;
        if (remaining <= std::chrono::microseconds(100)) {
            guard.unlock();
            hires_spin_sleep(deadline);
            guard.lock();
            return;
        }
#endif
        glob.time_notifier.wait_until(guard, deadline);
    }
    void taskTimer() {
        _set_name_thread_dbg("task time controller");

        fast_task::unique_lock guard(glob.task_timer_safety);
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

        while (glob.time_control_enabled) {
            auto current_now = std::chrono::high_resolution_clock::now();

            if (glob.shutdown_requested.load(std::memory_order_acquire)) {
                glob.timed_wheel.clear([&](timing& tmng) {
                    if (tmng.check_id == get_data(tmng.awake_task).awake_check) {
                        fast_task::lock_guard tg(get_data(tmng.awake_task));
                        if (!get_data(tmng.awake_task).get_awaked()) {
                            get_data(tmng.awake_task).set_time_end(true);
                            enqueue_wake(std::move(tmng.awake_task));
                        }
                    }
                });
                glob.cold_timed_wheel.clear([&](timing& tmng) {
                    if (tmng.check_id == get_data(tmng.awake_task).awake_check) {
                        fast_task::lock_guard tg(get_data(tmng.awake_task));
                        if (!get_data(tmng.awake_task).get_awaked()) {
                            get_data(tmng.awake_task).set_time_end(true);
                            enqueue_cold(std::move(tmng.awake_task));
                        }
                    }
                });
            } else {
                glob.timed_wheel.collect_expired(current_now, [&](timing& tmng) {
                    if (tmng.check_id != get_data(tmng.awake_task).awake_check)
                        return;

                    fast_task::lock_guard tg(get_data(tmng.awake_task));
                    if (get_data(tmng.awake_task).get_awaked())
                        return;

                    get_data(tmng.awake_task).set_time_end(true);
                    enqueue_wake(std::move(tmng.awake_task));
                });

                glob.cold_timed_wheel.collect_expired(current_now, [&](timing& tmng) {
                    if (tmng.check_id != get_data(tmng.awake_task).awake_check)
                        return;
                    enqueue_cold(std::move(tmng.awake_task));
                });
            }

            guard.unlock();
            flush_wake_ups();
            flush_cold();

            {
                fast_task::shared_lock sg(glob.task_thread_safety);
                glob.no_tasks_execute_notifier.notify_all();
            }

            check_stw();
            guard.lock();
            if (!glob.time_control_enabled)
                break;

            auto next_hot = glob.timed_wheel.next_deadline();
            auto next_cold = glob.cold_timed_wheel.next_deadline();

            if (next_hot == std::chrono::high_resolution_clock::time_point::max() && next_cold == std::chrono::high_resolution_clock::time_point::max())
                glob.time_notifier.wait(guard);
            else {
                auto deadline = (next_hot == std::chrono::high_resolution_clock::time_point::max())
                                    ? next_cold
                                : (next_cold == std::chrono::high_resolution_clock::time_point::max())
                                    ? next_hot
                                    : std::min(next_hot, next_cold);
                smart_wait_until(guard, deadline);
            }
        }

        guard.unlock();
        flush_wake_ups();
        flush_cold();

        fast_task::shared_lock _guard(glob.task_thread_safety);
        get_loc().reset();
        --glob.thread_count;
        glob.executor_shutdown_notifier.notify_all();
    }

    void startTimeController() {
        fast_task::lock_guard guard(glob.task_timer_safety);
        if (glob.time_control_enabled)
            return;
        ++glob.thread_count;
        glob.time_control_enabled = true;
        fast_task::thread(taskTimer).detach();
    }

    void startTimeController_unsafe() {
        if (glob.time_control_enabled)
            return;
        ++glob.thread_count;
        glob.time_control_enabled = true;
        fast_task::thread(taskTimer).detach();
    }

    void unsafe_put_task_to_timed_queue(hashed_timing_wheel& wheel, std::chrono::high_resolution_clock::time_point t, task& task) {
        wheel.insert(timing(t, task, get_data(task).awake_check));
    }

    void makeTimeWait_extern(task _task, std::chrono::high_resolution_clock::time_point time_point) {
        if (!glob.time_control_enabled)
            startTimeController();
        get_data(_task).set_awaked(false);
        get_data(_task).set_time_end(false);
        fast_task::lock_guard guard(glob.task_timer_safety);
        if (can_be_scheduled_task_to_hot())
            unsafe_put_task_to_timed_queue(glob.timed_wheel, time_point, _task);
        else
            unsafe_put_task_to_timed_queue(glob.cold_timed_wheel, time_point, _task);
        glob.tasks_notifier.notify_one();
    }

    void makeTimeWait(std::chrono::high_resolution_clock::time_point t) {
        if (!glob.time_control_enabled)
            startTimeController();
        auto& loc = get_loc();
        get_data(loc.curr_task).set_awaked(false);
        get_data(loc.curr_task).set_time_end(false);

        fast_task::lock_guard guard(glob.task_timer_safety);
        unsafe_put_task_to_timed_queue(glob.timed_wheel, t, loc.curr_task);
        glob.time_notifier.notify_one();
    }

    void makeTimeWait_unsafe(std::chrono::high_resolution_clock::time_point t) {
        if (!glob.time_control_enabled)
            startTimeController_unsafe();
        auto& loc = get_loc();
        get_data(loc.curr_task).set_awaked(false);
        get_data(loc.curr_task).set_time_end(false);

        unsafe_put_task_to_timed_queue(glob.timed_wheel, t, loc.curr_task);
        glob.time_notifier.notify_one();
    }

    void resetTimeWait() {
        auto& loc = get_loc();
        get_data(loc.curr_task).set_awaked(false);
        get_data(loc.curr_task).set_time_end(false);
    }
}