// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <task.hpp>
#include <tasks/_internal.hpp>
#include <tasks/util/interrupt.hpp>
#include <tasks/util/light_stack.hpp>
#include <threading.hpp>

namespace fast_task {

    size_t task::max_running_tasks = 0;
#ifdef FT_ENABLE_PREEMPTIVE_SCHEDULER
    void timer_reinit() {
        if (loc.policy == scheduler::executor_policy::cooperative_only)
            return;
        std::chrono::nanoseconds interval = next_quantum(get_execution_data(loc.curr_task).priority, get_execution_data(loc.curr_task).current_available_quantum);
        interrupt::itimerval timer;
        timer.it_interval.tv_sec = 0;
        timer.it_interval.tv_usec = 0;
        timer.it_value.tv_sec = interval.count() / 1000000000;
        timer.it_value.tv_usec = (interval.count() % 1000000000) / 1000;
        interrupt::setitimer(&timer, nullptr);
    }

    void swapCtx();

    void interruptTask() {
        if (loc.policy == scheduler::executor_policy::cooperative_only)
            return;
    #ifdef FT_EXCEPTION_POLICY_CHECK
        if (std::uncaught_exceptions())
            return;
    #endif
        if (get_data(loc.curr_task).bind_to_worker_id != (uint16_t)-1) {
            fast_task::unique_lock guard(glob.binded_workers_safety);
            auto& bind_context = glob.binded_workers[get_data(loc.curr_task).bind_to_worker_id];
            guard.unlock();
            if (bind_context.tasks.size_approx() == 0) {
                if (glob.cold_tasks.size_approx() == 0) {
                    timer_reinit();
                    return;
                } else {
                    if (task::max_running_tasks && !can_be_scheduled_task_to_hot()) {
                        timer_reinit();
                        return;
                    }
                }
            }
        } else {
            if (glob.tasks.size_approx() == 0) {
                if (glob.cold_tasks.size_approx() == 0) {
                    timer_reinit();
                    return;
                } else {
                    if (task::max_running_tasks && !can_be_scheduled_task_to_hot()) {
                        timer_reinit();
                        return;
                    }
                }
            }
        }

        ++glob.interrupts;
        ++get_execution_data(loc.curr_task).interrupt_count;
        auto old_relock_0 = get_data(loc.curr_task).relock_0;
        auto old_relock_1 = get_data(loc.curr_task).relock_1;
        auto old_relock_2 = get_data(loc.curr_task).relock_2;
        get_data(loc.curr_task).relock_0 = nullptr;
        get_data(loc.curr_task).relock_1 = nullptr;
        get_data(loc.curr_task).relock_2 = nullptr;
        loc.yield_request = true;
        swapCtx();
        get_data(loc.curr_task).relock_0 = old_relock_0;
        get_data(loc.curr_task).relock_1 = old_relock_1;
        get_data(loc.curr_task).relock_2 = old_relock_2;
    }

    #define set_interruptTask() interrupt::timer_callback(interruptTask);

    #define stop_timer() interrupt::stop_timer()
    #define preserve_interrupt_data get_execution_data(loc.curr_task).interrupt_data = interrupt_unsafe_region::lock_swap(0);
    #define restore_interrupt_data interrupt_unsafe_region::lock_swap(get_execution_data(loc.curr_task).interrupt_data);
    #define flush_interrupt_data interrupt_unsafe_region::lock_swap(0);
#else
    #define timer_reinit()
    #define set_interruptTask()
    #define stop_timer()
    #define preserve_interrupt_data
    #define restore_interrupt_data
    #define flush_interrupt_data
#endif

#pragma optimize("", off)
#if defined(__GNUC__) && !defined(__clang__)
    #pragma GCC push_options
    #pragma GCC optimize("O0")
#endif
#pragma region TaskExecutor

    void swapCtx() {
        if (loc.is_task_thread) {
            stop_timer();
            if (get_data(loc.curr_task).is_on_scheduler)
                throw invalid_context();
            loc.context_in_swap = true;
            ++glob.tasks_in_swap;
            ++get_execution_data(loc.curr_task).context_switch_count;
            preserve_interrupt_data;
#ifdef FT_EXCEPTION_POLICY_CHECK
            if (std::uncaught_exceptions()) {
                assert(false && "Unexpected exception during context switch");
                std::abort();
            }
#elif defined(FT_EXCEPTION_POLICY_PRESERVE)
            if (std::uncaught_exceptions())
                get_execution_data(loc.curr_task).switch_preserve = std::current_exception();
#endif
            try {
                *loc.stack_current_context = std::move(*loc.stack_current_context).resume();
            } catch (const boost::context::detail::forced_unwind&) {
                preserve_interrupt_data;
                --glob.tasks_in_swap;
                loc.context_in_swap = true;
                auto relock_state_0 = get_data(loc.curr_task).relock_0;
                auto relock_state_1 = get_data(loc.curr_task).relock_1;
                auto relock_state_2 = get_data(loc.curr_task).relock_2;
                get_data(loc.curr_task).relock_0 = nullptr;
                get_data(loc.curr_task).relock_1 = nullptr;
                get_data(loc.curr_task).relock_2 = nullptr;
                relock_state_0.relock_end();
                relock_state_1.relock_end();
                relock_state_2.relock_end();
                get_data(loc.curr_task).awake_check++;
                loc.context_in_swap = false;
                throw;
            }
#if defined(FT_EXCEPTION_POLICY_PRESERVE)
            if (get_execution_data(loc.curr_task).switch_preserve)
                std::rethrow_exception(std::move(get_execution_data(loc.curr_task).switch_preserve));
#endif
            preserve_interrupt_data;
            --glob.tasks_in_swap;
            loc.context_in_swap = true;
            auto relock_state_0 = get_data(loc.curr_task).relock_0;
            auto relock_state_1 = get_data(loc.curr_task).relock_1;
            auto relock_state_2 = get_data(loc.curr_task).relock_2;
            get_data(loc.curr_task).relock_0 = nullptr;
            get_data(loc.curr_task).relock_1 = nullptr;
            get_data(loc.curr_task).relock_2 = nullptr;
            relock_state_0.relock_end();
            relock_state_1.relock_end();
            relock_state_2.relock_end();
            get_data(loc.curr_task).awake_check++;
            loc.context_in_swap = false;
            if (get_data(loc.curr_task).invalid_switch_caught) {
                get_data(loc.curr_task).invalid_switch_caught = false;
                throw invalid_switch();
            }
            timer_reinit();
            if (get_data(loc.curr_task).timeout != std::chrono::high_resolution_clock::time_point::min().time_since_epoch().count())
                if (get_data(loc.curr_task).timeout <= std::chrono::high_resolution_clock::now().time_since_epoch().count())
                    throw task_cancellation();
        } else
            throw invalid_context();
    }

    void swapCtxRelock(const mutex_unify& mut0) {
        get_data(loc.curr_task).relock_0 = mut0;
        swapCtx();
    }

    void swapCtxRelock(const mutex_unify& mut0, const mutex_unify& mut1, const mutex_unify& mut2) {
        get_data(loc.curr_task).relock_0 = mut0;
        get_data(loc.curr_task).relock_1 = mut1;
        get_data(loc.curr_task).relock_2 = mut2;
        swapCtx();
    }

    void swapCtxRelock(const mutex_unify& mut0, const mutex_unify& mut1) {
        get_data(loc.curr_task).relock_0 = mut0;
        get_data(loc.curr_task).relock_1 = mut1;
        swapCtx();
    }

    boost::context::continuation context_exec(boost::context::continuation&& sink) {
        *loc.stack_current_context = std::move(sink);
        try {
            if (!checkCancellation()) {
                flush_interrupt_data;
                timer_reinit();
                if (get_data(loc.curr_task).callbacks.on_start_override)
                    get_data(loc.curr_task).callbacks.on_start_override(get_data(loc.curr_task).callbacks);
                else if (get_data(loc.curr_task).callbacks.on_start)
                    get_data(loc.curr_task).callbacks.on_start(get_data(loc.curr_task).callbacks.get_data());
            } else
                this_task::the_coroutine_ended(loc.curr_task);
        } catch (const task_cancellation& cancel) {
            forceCancelCancellation(cancel);
        } catch (const boost::context::detail::forced_unwind&) {
            --glob.in_run_tasks;
            throw;
        } catch (...) {
            loc.ex_ptr = std::current_exception();
        }
        stop_timer();
        flush_interrupt_data;
        fast_task::lock_guard l(get_data(loc.curr_task).no_race);
        --glob.in_run_tasks;
        if (get_data(loc.curr_task).callbacks.is_restartable) {
            get_data(loc.curr_task).started = false;
            return std::move(*loc.stack_current_context);
        }

        if (!loc.ex_ptr) {
            get_data(loc.curr_task).end_of_life = true;
            get_data(loc.curr_task).result_notify.notify_all();
        }
        return std::move(*loc.stack_current_context);
    }

    boost::context::continuation context_ex_handle(boost::context::continuation&& sink) {
        *loc.stack_current_context = std::move(sink);
        try {
            if (!checkCancellation()) {
                flush_interrupt_data;
                timer_reinit();
                if (get_data(loc.curr_task).callbacks.on_exception)
                    get_data(loc.curr_task).callbacks.on_exception(get_data(loc.curr_task).callbacks.get_data(), loc.ex_ptr);
            } else
                this_task::the_coroutine_ended(loc.curr_task);
        } catch (task_cancellation& cancel) {
            forceCancelCancellation(cancel);
        } catch (const boost::context::detail::forced_unwind&) {
            --glob.in_run_tasks;
            throw;
        } catch (...) {
            loc.ex_ptr = std::current_exception();
        }
        stop_timer();
        flush_interrupt_data;
        fast_task::unique_lock l(get_data(loc.curr_task).no_race);
        get_data(loc.curr_task).end_of_life = true;
        get_data(loc.curr_task).result_notify.notify_all();
        --glob.in_run_tasks;
        return std::move(*loc.stack_current_context);
    }

    void in_place_run() {
        ++glob.in_run_tasks;
        try {
            if (!checkCancellation()) {
                if (get_data(loc.curr_task).callbacks.on_start_override)
                    get_data(loc.curr_task).callbacks.on_start_override(get_data(loc.curr_task).callbacks);
                else if (get_data(loc.curr_task).callbacks.on_start)
                    get_data(loc.curr_task).callbacks.on_start(get_data(loc.curr_task).callbacks.get_data());
                get_data(loc.curr_task).relock_0.relock_start();
                get_data(loc.curr_task).relock_1.relock_start();
                get_data(loc.curr_task).relock_2.relock_start();
            } else
                this_task::the_coroutine_ended(loc.curr_task);
            {
                fast_task::lock_guard guard(get_data(loc.curr_task).no_race);
                if (get_data(loc.curr_task).callbacks.is_restartable) {
                    get_data(loc.curr_task).started = false;
                } else {
                    get_data(loc.curr_task).end_of_life = true;
                    get_data(loc.curr_task).result_notify.notify_all();
                }
            }
        } catch (const task_cancellation& cancel) {
            forceCancelCancellation(cancel);
            fast_task::lock_guard guard(get_data(loc.curr_task).no_race);
            get_data(loc.curr_task).end_of_life = true;
            get_data(loc.curr_task).result_notify.notify_all();
        } catch (...) {
            loc.ex_ptr = std::current_exception(); //TODO pass this to the callback
            fast_task::lock_guard guard(get_data(loc.curr_task).no_race);
            get_data(loc.curr_task).end_of_life = true;
            get_data(loc.curr_task).result_notify.notify_all();
        }
        --glob.in_run_tasks;
    }

    void transfer_task(std::shared_ptr<task>&& task) {
        if (get_data(task).is_on_scheduler && get_data(task).relock_0) {
            auto mut = std::move(get_data(task).relock_0);

            get_data(task).relock_0 = nullptr;
            get_data(task).relock_1 = nullptr;
            get_data(task).relock_2 = nullptr;

            if (!mut.enter_wait(task))
                return;
        }

        if (get_data(task).bind_to_worker_id == (uint16_t)-1) {
            if (get_data(task).auto_bind_worker) {
                fast_task::shared_lock global_guard(glob.binded_workers_safety);
                for (auto& [id, context] : glob.binded_workers) {
                    if (context.allow_implicit_start) {
                        if (context.in_close)
                            continue;
                        global_guard.unlock();
                        get_data(task).bind_to_worker_id = id;
                        fast_task::shared_lock guard(context.no_race);
                        context.tasks.enqueue(std::move(task));
                        context.new_task_notifier.notify_one();
                        return;
                    }
                }
            }
            if (loc.binded_id == (uint16_t)-1 && loc.is_task_thread) {
                if (loc.local_tasks->emplace(std::move(task))) {
                    if (loc.local_tasks->size() > 1) //if there only one task the notification not passed to avoid redundant concurency
                        glob.tasks_notifier.unsafe_notify_one();
                    return;
                }
            }

            if (can_be_scheduled_task_to_hot())
                glob.tasks.enqueue(std::move(task));
            else
                glob.cold_tasks.enqueue(std::move(task));
            glob.tasks_notifier.unsafe_notify_one();
        } else {
            fast_task::shared_lock initializer_guard(glob.binded_workers_safety);
            if (!glob.binded_workers.contains(get_data(task).bind_to_worker_id)) {
                initializer_guard.unlock();
                assert("Binded worker context not found");
                std::abort();
            }
            binded_context& extern_context = glob.binded_workers[get_data(task).bind_to_worker_id];
            initializer_guard.unlock();
            if (extern_context.in_close) {
                assert("Binded worker context is closed");
                std::abort();
            }
            if (get_data(task).bind_to_worker_id == loc.binded_id) {
                if (loc.local_tasks->emplace(std::move(task))) {
                    if (loc.local_tasks->size() > 1) //if there only one task the notification not passed to avoid redundant concurency
                        extern_context.new_task_notifier.unsafe_notify_one();
                    return;
                }
            }
            fast_task::shared_lock guard(extern_context.no_race);
            extern_context.tasks.enqueue(std::move(task));
            extern_context.new_task_notifier.notify_one();
        }
    }

    bool loadTask() {
        if (loc.local_tasks->pop(loc.curr_task)) {
            loc.stack_current_context = &get_execution_data(loc.curr_task).context;
            return false;
        }

        constexpr size_t BATCH_SIZE = 32;
        std::shared_ptr<task> temp_tasks[BATCH_SIZE];
        {
            size_t count = glob.tasks.try_dequeue_bulk(temp_tasks, BATCH_SIZE);

            if (count > 0) {
                for (size_t i = 1; i < count; ++i)
                    if (!loc.local_tasks->emplace(std::move(temp_tasks[i])))
                        glob.tasks.enqueue(temp_tasks[i]);
                loc.curr_task = std::move(temp_tasks[0]);
                loc.stack_current_context = &get_execution_data(loc.curr_task).context;
                return false;
            }
        }

        if (can_be_scheduled_task_to_hot()) {
            size_t count = glob.cold_tasks.try_dequeue_bulk(temp_tasks, BATCH_SIZE);

            if (count > 0) {
                for (size_t i = 1; i < count; ++i)
                    if (!loc.local_tasks->emplace(std::move(temp_tasks[i])))
                        glob.cold_tasks.enqueue(temp_tasks[i]);
                loc.curr_task = std::move(temp_tasks[0]);
                loc.stack_current_context = &get_execution_data(loc.curr_task).context;
                return false;
            }
        }

        {
            auto queues = glob.executors_queues.load(std::memory_order_relaxed);
            if (queues) {
                if (!queues->empty()) {
                    auto& engine = get_thread_local_random_engine();
                    size_t size = queues->size();
                    std::uniform_int_distribution<size_t> dist(0, size - 1);

                    size_t start_index = dist(engine);
                    for (size_t i = 0; i < size; ++i) {
                        size_t index = (start_index + i) % size;
                        auto& victim_deque = (*queues)[index];

                        if (victim_deque == loc.local_tasks)
                            continue;

                        if (victim_deque->steal(loc.curr_task)) {
                            loc.stack_current_context = &get_execution_data(loc.curr_task).context;
                            return false;
                        }
                    }
                }
            }
        }

        loc.curr_task = nullptr;
        loc.stack_current_context = nullptr;
        return true;
    }

#define worker_mode_desk(old_name, mode, id) \
    if (task::enable_task_naming)            \
        worker_mode_desk_(old_name, mode, id);

    void worker_mode_desk_(const std::string& old_name, std::string_view mode, size_t id) {
        if (old_name.empty())
            _set_name_thread_dbg("Worker " + std::to_string(_thread_id()) + ": " + std::string(mode) + std::to_string(id));
        else
            _set_name_thread_dbg(old_name + " | (Temporal worker) " + std::to_string(_thread_id()) + ": " + std::string(mode) + std::to_string(id));
    }

    bool execute_task(const std::string& old_name) {
        if (!loc.curr_task)
            return false;
        if (get_data(loc.curr_task).callbacks.on_start == nullptr && get_data(loc.curr_task).callbacks.on_destruct == nullptr) {
            fast_task::lock_guard guard(get_data(loc.curr_task).no_race);
            get_data(loc.curr_task).end_of_life = true;
            loc.curr_task = nullptr;
            return true;
        } else if (!get_data(loc.curr_task).callbacks.on_start) {
            fast_task::lock_guard guard(get_data(loc.curr_task).no_race);
            get_data(loc.curr_task).end_of_life = true;
            get_data(loc.curr_task).result_notify.notify_all();
            goto end_task;
        }

        {
            fast_task::lock_guard guard(get_data(loc.curr_task).no_race);
            if (get_data(loc.curr_task).end_of_life)
                goto end_task;
        }

        loc.is_task_thread = true;

        worker_mode_desk(old_name, "process task - ", this_task::get_id());
        if (*loc.stack_current_context) {
            *loc.stack_current_context = std::move(*loc.stack_current_context).resume();
            get_data(loc.curr_task).relock_0.relock_start();
            get_data(loc.curr_task).relock_1.relock_start();
            get_data(loc.curr_task).relock_2.relock_start();
        } else if (get_data(loc.curr_task).is_on_scheduler) {
            in_place_run();
        } else {
            light_stack stack_alloc(1048576 /*1 mb*/);
            auto ss = stack_alloc.allocate();
#if PLATFORM_LINUX
            get_execution_data(loc.curr_task).stack_ptr = ((char*)ss.sp) - ss.size;
            get_execution_data(loc.curr_task).stack_size = ss.size;
#endif
            ++glob.in_run_tasks;
            *loc.stack_current_context = boost::context::callcc(std::allocator_arg, boost::context::preallocated(ss.sp, ss.size, ss), stack_alloc, context_exec);
            get_data(loc.curr_task).relock_0.relock_start();
            get_data(loc.curr_task).relock_1.relock_start();
            get_data(loc.curr_task).relock_2.relock_start();
        }
        if (loc.ex_ptr) {
            light_stack stack_alloc(1048576 /*1 mb*/);
            auto ss = stack_alloc.allocate();
#if PLATFORM_LINUX
            get_execution_data(loc.curr_task).stack_ptr = ((char*)ss.sp) - ss.size;
            get_execution_data(loc.curr_task).stack_size = ss.size;
#endif
            ++glob.in_run_tasks;
            *loc.stack_current_context = boost::context::callcc(std::allocator_arg, boost::context::preallocated(ss.sp, ss.size, ss), stack_alloc, context_ex_handle);
            get_data(loc.curr_task).relock_0.relock_start();
            get_data(loc.curr_task).relock_1.relock_start();
            get_data(loc.curr_task).relock_2.relock_start();
            loc.ex_ptr = nullptr;
        }
    end_task:
        loc.stack_current_context = nullptr;
        loc.is_task_thread = false;
        bool end_of_life = false;
        {
            fast_task::lock_guard guard(get_data(loc.curr_task).no_race);
            end_of_life = get_data(loc.curr_task).end_of_life;
        }
        if (!end_of_life && loc.curr_task.use_count() == 1 && !loc.yield_request) {
            get_data(loc.curr_task).invalid_switch_caught = true;
            transfer_task(std::move(loc.curr_task));
        } else if (loc.yield_request) {
            transfer_task(std::move(loc.curr_task));
            loc.yield_request = false;
        } else if (end_of_life) {
            --glob.executing_tasks;
            glob.no_tasks_execute_notifier.notify_all();
            fast_task::lock_guard guard(get_data(loc.curr_task).no_race);
            get_data(loc.curr_task).completed = true;
        }


        loc.curr_task = nullptr;
        worker_mode_desk(old_name, "idle ", 0);
        return false;
    }

    void taskExecutor(bool end_in_task_out, bool prevent_naming) {
        set_interruptTask();
        std::string old_name = end_in_task_out && !prevent_naming ? _get_name_thread_dbg(_thread_id()) : "";
        if (!prevent_naming) {
            if (old_name.empty())
                _set_name_thread_dbg("Worker " + std::to_string(_thread_id()));
            else
                _set_name_thread_dbg(old_name + " | (Temporal worker) " + std::to_string(_thread_id()));
        }
        {
            fast_task::unique_lock lock(glob.task_thread_safety);
            auto old_queues_ptr = glob.executors_queues.load();
            auto new_queues = old_queues_ptr ? std::make_shared<std::vector<std::shared_ptr<work_stealing_deque<std::shared_ptr<task>>>>>(*old_queues_ptr)
                                             : std::make_shared<std::vector<std::shared_ptr<work_stealing_deque<std::shared_ptr<task>>>>>();
            new_queues->push_back(loc.local_tasks);
            glob.executors_queues.store(new_queues);
        }
        constexpr size_t max_retrys = 13;
        size_t retrys = 0;
        ++glob.executors;
        while (true) {
            check_stw();
            if (loadTask()) {
                if (end_in_task_out)
                    goto exit_path;
                else if (retrys < max_retrys) {
                    ++retrys;
                } else if (!loc.local_tasks->empty())
                    retrys = 0;
                else {
                    fast_task::unique_lock guard(glob.task_thread_safety);
                    if (glob.tasks.size_approx() == 0 && glob.cold_tasks.size_approx() == 0) {
                        glob.tasks_notifier.wait(guard);
                    }
                }
                continue;
            }
            retrys = 0;
            if (get_data(loc.curr_task).bind_to_worker_id != (uint16_t)-1) {
                transfer_task(std::move(loc.curr_task));
                continue;
            }
            if (execute_task(old_name))
                break;
        }
    exit_path:
        --glob.executors;
        --glob.thread_count;
        glob.executor_shutdown_notifier.notify_all();
        if (!prevent_naming)
            _set_name_thread_dbg(old_name);

        {
            fast_task::lock_guard lock(glob.task_thread_safety);

            auto old_queues_ptr = glob.executors_queues.load();
            auto new_queues = std::make_shared<std::vector<std::shared_ptr<work_stealing_deque<std::shared_ptr<task>>>>>();
            new_queues->reserve(old_queues_ptr->size());

            for (const auto& q_ptr : *old_queues_ptr) {
                if (q_ptr.get() != loc.local_tasks.get())
                    new_queues->push_back(q_ptr);
            }

            glob.executors_queues.store(new_queues);
        }
        while (!loc.local_tasks->empty())
            while (loc.local_tasks->pop(loc.curr_task))
                glob.tasks.enqueue(std::move(loc.curr_task));
        glob.tasks_notifier.unsafe_notify_all();
    }

    bool loadTaskBinded(binded_context& context) {
        while (true) {
            check_stw();
            if (loc.local_tasks->pop(loc.curr_task)) {
                loc.stack_current_context = &get_execution_data(loc.curr_task).context;
                return true;
            }

            constexpr size_t BATCH_SIZE = 8;
            std::shared_ptr<task> temp_tasks[BATCH_SIZE];
            size_t count = context.tasks.try_dequeue_bulk(temp_tasks, BATCH_SIZE);

            if (count > 0) {
                for (size_t i = 1; i < count; ++i)
                    if (!loc.local_tasks->emplace(std::move(temp_tasks[i])))
                        glob.tasks.enqueue(temp_tasks[i]);
                loc.curr_task = std::move(temp_tasks[0]);
                loc.stack_current_context = &get_execution_data(loc.curr_task).context;
                return true;
            }

            {
                auto queue = context.executors_queues.load();
                if (queue) {
                    if (!queue->empty()) {
                        auto& engine = get_thread_local_random_engine();
                        std::uniform_int_distribution<size_t> dist(0, queue->size() - 1);

                        size_t start_index = dist(engine);
                        for (size_t i = 0; i < queue->size(); ++i) {
                            size_t index = (start_index + i) % queue->size();
                            auto& victim_deque = (*queue)[index];

                            if (victim_deque == loc.local_tasks)
                                continue;

                            if (victim_deque->pop(loc.curr_task)) {
                                loc.stack_current_context = &get_execution_data(loc.curr_task).context;
                                return true;
                            }
                        }
                    }
                }
            }


            if (!context.tasks.try_dequeue(loc.curr_task)) {
                fast_task::unique_lock guard(context.no_race);
                if (context.in_close)
                    break;
                if (!context.tasks.try_dequeue(loc.curr_task)) {
                    context.new_task_notifier.wait(guard);
                } else
                    return true;
            } else
                return true;
        }
        return false;
    }

    void bindedTaskExecutor(uint16_t id) {
        set_interruptTask();
        std::string old_name = "Binded";
        fast_task::unique_lock initializer_guard(glob.binded_workers_safety);
        if (!glob.binded_workers.contains(id)) {
            assert("Binded worker context not found");
            std::abort();
        }
        binded_context& context = glob.binded_workers[id];
        loc.policy = context.policy;
        loc.binded_id = id;

        context.completions.emplace_back(0);
        auto& completions = context.completions.back();
        auto completions_remove = --context.completions.end();
        context.executors++;
        initializer_guard.unlock();
        {
            fast_task::unique_lock lock(context.no_race);
            auto old_queues_ptr = context.executors_queues.load();
            auto new_queues = old_queues_ptr ? std::make_shared<std::vector<std::shared_ptr<work_stealing_deque<std::shared_ptr<task>>>>>(*old_queues_ptr)
                                             : std::make_shared<std::vector<std::shared_ptr<work_stealing_deque<std::shared_ptr<task>>>>>();
            new_queues->push_back(loc.local_tasks);
            context.executors_queues.store(new_queues);
        }
        _set_name_thread_dbg("Binded worker " + std::to_string(_thread_id()) + ": " + std::to_string(id));

        while (true) {
            if (!loadTaskBinded(context))
                break;

            if (get_data(loc.curr_task).bind_to_worker_id != (uint16_t)id) {
                transfer_task(std::move(loc.curr_task));
                continue;
            }
            if (execute_task(old_name))
                break;
            completions += 1;
        }

        while (!loc.local_tasks->empty())
            while (loc.local_tasks->pop(loc.curr_task))
                context.tasks.enqueue(std::move(loc.curr_task));

        {
            fast_task::unique_lock guard(context.no_race);
            context.completions.erase(completions_remove);
            auto old_queues_ptr = context.executors_queues.load();
            auto new_queues = std::make_shared<std::vector<std::shared_ptr<work_stealing_deque<std::shared_ptr<task>>>>>();
            new_queues->reserve(old_queues_ptr->size());

            for (const auto& q_ptr : *old_queues_ptr) {
                if (q_ptr.get() != loc.local_tasks.get())
                    new_queues->push_back(q_ptr);
            }

            context.executors_queues.store(new_queues);

            --context.executors;
            if (context.executors == 0) {
                if (context.in_close) {
                    while (context.tasks.size_approx())
                        while (context.tasks.try_dequeue(loc.curr_task)) { //TODO add option to abort if there still tasks in queue
                            get_data(loc.curr_task).bind_to_worker_id = (uint16_t)-1;
                            glob.tasks.enqueue(std::move(loc.curr_task));
                        }
                    glob.tasks_notifier.unsafe_notify_all();
                    context.on_closed_notifier.notify_all();
                    guard.unlock();
                } else {
                    assert(0 && "Caught executor/s death when context is not closed");
                    std::abort();
                }
            }
        }
        --glob.thread_count;
    }

#pragma endregion

    void taskTimer() {
        glob.time_control_enabled = true;
        _set_name_thread_dbg("task time controller");

        fast_task::unique_lock guard(glob.task_timer_safety);
        std::list<std::shared_ptr<task>> cached_wake_ups;
        std::list<std::shared_ptr<task>> cached_cold;
        while (glob.time_control_enabled) {
            if (glob.shutdown_requested.load(std::memory_order_acquire)) {
                while (!glob.timed_tasks.empty()) {
                    timing& tmng = glob.timed_tasks.front();
                    if (tmng.check_id == get_data(tmng.awake_task).awake_check) {
                        fast_task::lock_guard task_guard(get_data(tmng.awake_task).no_race);
                        if (!get_data(tmng.awake_task).awaked) {
                            get_data(tmng.awake_task).time_end_flag = true;
                            cached_wake_ups.push_back(std::move(tmng.awake_task));
                        }
                    }
                    glob.timed_tasks.pop_front();
                }
                while (!glob.cold_timed_tasks.empty()) {
                    timing& tmng = glob.cold_timed_tasks.front();
                    if (tmng.check_id == get_data(tmng.awake_task).awake_check) {
                        fast_task::lock_guard task_guard(get_data(tmng.awake_task).no_race);
                        if (!get_data(tmng.awake_task).awaked) {
                            get_data(tmng.awake_task).time_end_flag = true;
                            cached_cold.push_back(std::move(tmng.awake_task));
                        }
                    }
                    glob.cold_timed_tasks.pop_front();
                }
            } else if (glob.timed_tasks.size()) {
                auto current_now = std::chrono::high_resolution_clock::now();
                while (glob.timed_tasks.front().wait_timepoint <= current_now) {
                    timing& tmng = glob.timed_tasks.front();
                    if (tmng.check_id != get_data(tmng.awake_task).awake_check) {
                        glob.timed_tasks.pop_front();
                        if (glob.timed_tasks.empty())
                            break;
                        else
                            continue;
                    }
                    fast_task::lock_guard task_guard(get_data(tmng.awake_task).no_race);
                    if (get_data(tmng.awake_task).awaked) {
                        glob.timed_tasks.pop_front();
                    } else {
                        get_data(tmng.awake_task).time_end_flag = true;
                        cached_wake_ups.push_back(std::move(tmng.awake_task));
                        glob.timed_tasks.pop_front();
                    }
                    if (glob.timed_tasks.empty())
                        break;
                }
            }
            if (glob.cold_timed_tasks.size()) {
                auto current_now = std::chrono::high_resolution_clock::now();
                while (glob.cold_timed_tasks.front().wait_timepoint <= current_now) {
                    timing& tmng = glob.cold_timed_tasks.front();
                    if (tmng.check_id != get_data(tmng.awake_task).awake_check) {
                        glob.cold_timed_tasks.pop_front();
                        if (glob.cold_timed_tasks.empty())
                            break;
                        else
                            continue;
                    }
                    cached_cold.push_back(std::move(tmng.awake_task));
                    glob.cold_timed_tasks.pop_front();
                    if (glob.cold_timed_tasks.empty())
                        break;
                }
            }
            guard.unlock();
            if (!cached_wake_ups.empty() || !cached_cold.empty()) {
                if (!cached_wake_ups.empty())
                    while (!cached_wake_ups.empty()) {
                        transfer_task(std::move(cached_wake_ups.back()));
                        cached_wake_ups.pop_back();
                    }
                if (!cached_cold.empty()) {
                    fast_task::shared_lock _guard(glob.task_thread_safety);
                    while (!cached_cold.empty()) {
                        glob.cold_tasks.enqueue(std::move(cached_cold.back()));
                        cached_cold.pop_back();
                    }
                    glob.tasks_notifier.unsafe_notify_all();
                }
            }

            glob.no_tasks_execute_notifier.notify_all();

            check_stw();
            guard.lock();
            if (glob.shutdown_requested.load(std::memory_order_acquire))
                glob.time_notifier.wait(guard);
            else if (glob.timed_tasks.empty() && glob.cold_timed_tasks.empty())
                glob.time_notifier.wait(guard);
            else if (glob.timed_tasks.size() && glob.cold_timed_tasks.size()) {
                if (glob.timed_tasks.front().wait_timepoint < glob.cold_timed_tasks.front().wait_timepoint)
                    glob.time_notifier.wait_until(guard, glob.timed_tasks.front().wait_timepoint);
                else
                    glob.time_notifier.wait_until(guard, glob.cold_timed_tasks.front().wait_timepoint);
            } else if (glob.timed_tasks.size())
                glob.time_notifier.wait_until(guard, glob.timed_tasks.front().wait_timepoint);
            else
                glob.time_notifier.wait_until(guard, glob.cold_timed_tasks.front().wait_timepoint);
        }

        --glob.thread_count;
    }

#if defined(__GNUC__) && !defined(__clang__)
    #pragma GCC pop_options
#endif
#pragma optimize("", on)

    void startTimeController() {
        fast_task::lock_guard guard(glob.task_timer_safety);
        if (glob.time_control_enabled)
            return;
        ++glob.thread_count;
        fast_task::thread(taskTimer).detach();
        glob.time_control_enabled = true;
    }

    void startTimeController_unsafe() {
        if (glob.time_control_enabled)
            return;
        ++glob.thread_count;
        fast_task::thread(taskTimer).detach();
        glob.time_control_enabled = true;
    }

    void unsafe_put_task_to_timed_queue(std::deque<timing>& queue, std::chrono::high_resolution_clock::time_point t, std::shared_ptr<task>& task) {
        size_t i = 0;
        auto it = queue.begin();
        auto end = queue.end();
        while (it != end) {
            if (it->wait_timepoint >= t) {
                queue.emplace(it, timing(t, task, get_data(task).awake_check));
                i = (size_t)-1;
                break;
            }
            ++it;
        }
        if (i != (size_t)-1)
            queue.emplace_back(timing(t, task, get_data(task).awake_check));
    }

    void makeTimeWait_extern(std::shared_ptr<task> _task, std::chrono::high_resolution_clock::time_point time_point) {
        if (!glob.time_control_enabled)
            startTimeController();
        get_data(loc.curr_task).awaked = false;
        get_data(loc.curr_task).time_end_flag = false;
        fast_task::lock_guard guard(glob.task_timer_safety);
        if (can_be_scheduled_task_to_hot())
            unsafe_put_task_to_timed_queue(glob.timed_tasks, time_point, _task);
        else
            unsafe_put_task_to_timed_queue(glob.cold_timed_tasks, time_point, _task);
        glob.tasks_notifier.notify_one();
    }

    void makeTimeWait(std::chrono::high_resolution_clock::time_point t) {
        if (!glob.time_control_enabled)
            startTimeController();
        get_data(loc.curr_task).awaked = false;
        get_data(loc.curr_task).time_end_flag = false;

        fast_task::lock_guard guard(glob.task_timer_safety);
        unsafe_put_task_to_timed_queue(glob.timed_tasks, t, loc.curr_task);
        glob.time_notifier.notify_one();
    }

    void makeTimeWait_unsafe(std::chrono::high_resolution_clock::time_point t) {
        if (!glob.time_control_enabled)
            startTimeController_unsafe();
        get_data(loc.curr_task).awaked = false;
        get_data(loc.curr_task).time_end_flag = false;

        unsafe_put_task_to_timed_queue(glob.timed_tasks, t, loc.curr_task);
        glob.time_notifier.notify_one();
    }

    void resetTimeWait() {
        get_data(loc.curr_task).awaked = false;
        get_data(loc.curr_task).time_end_flag = false;
    }
}
