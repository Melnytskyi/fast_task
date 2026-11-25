// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_INCLUDE_TASK_SCHEDULER
#define FAST_TASK_INCLUDE_TASK_SCHEDULER
#include "task.hpp"
#include <chrono>
#include <cstddef>
#include <functional>
#include <list>
#include <span>
#include <string>
#include <variant>
#include <vector>

namespace fast_task {
    namespace scheduler {
        enum class preemption_policy {
            allows_preempt = 0,
            cooperative_only = 1,


            default_policy = allows_preempt,
        };

        enum class worker_balancer {
            none,
            hill_climb,
        };

        enum class queue_policy : uint8_t {
            work_stealing_lifo,
            priority_fifo,
        };

        enum class idle_policy : uint8_t {
            wait,
            busy_spin,
        };

        enum class pool_affinity_mode : uint8_t {
            // Every worker gets the whole list.
            mask,
            // Each worker is pinned to one entry, taken in turn
            round_robin,
        };

        struct worker_affinity_options {
            std::vector<uint32_t> cpus;
            pool_affinity_mode mode = pool_affinity_mode::mask;
        };

        class worker_context;
        class worker_pool;

        struct worker_hooks {
            void (*thread_initializer)(void (*back_callback)(void* callback_data), void* callback_data, void* user_state) = nullptr;
            void (*worker_body)(worker_context& ctx, void* state) = nullptr;
            void* state = nullptr;
        };

        struct worker_pool_options {
            std::string name;

            uint16_t min_workers = 1; // 0 is allowed for host-only pools
            uint16_t max_workers = UINT16_MAX;
            uint16_t initial_workers = 0; // > 0 wins over start_with_worker_per_core
            bool start_with_worker_per_core = true;

            preemption_policy policy = preemption_policy::default_policy;
            worker_balancer balancer = worker_balancer::none;
            bool allow_driver_polling = true;
            bool prevent_thread_naming = false;
            bool abort_tasks_on_shutdown = false;
            bool allow_dormant_sharing = false;
            bool inherit_pool_on_spawn = false;
            bool allow_implicit_start = false;

            queue_policy queue = queue_policy::work_stealing_lifo;
            idle_policy idle = idle_policy::wait;
            worker_affinity_options affinity{};

            worker_hooks hooks{};
        };

        struct worker_pool_stats {
            std::string name;
            uint32_t ordinal = 0;
            bool is_global = false;
            queue_policy queue = queue_policy::work_stealing_lifo;
            idle_policy idle = idle_policy::wait;
            worker_balancer balancer = worker_balancer::none;
            uint16_t min_workers = 0;
            uint16_t max_workers = 0;
            uint16_t target_workers = 0;
            uint16_t active_workers = 0;
            uint16_t foreign_workers = 0;
            uint16_t dormant_workers = 0;
            uint16_t borrowed_in = 0;
            uint16_t borrowed_out = 0;
            uint16_t live_threads = 0;
            size_t queued_tasks_approx = 0;
            size_t executing_tasks = 0;
            size_t in_run_tasks = 0;
            uint64_t completed_tasks = 0;
            uint64_t balance_samples = 0;
            uint32_t affinity_failures = 0;
            bool paused = false;
            bool shutting_down = false;
        };

        struct runtime_stats {
            size_t active_pools = 0;
            size_t total_active_workers = 0;
            size_t total_foreign_workers = 0;
            size_t total_dormant_workers = 0;
            size_t total_live_threads = 0;
            size_t executing_tasks = 0;
            size_t in_run_tasks = 0;
            size_t timers_pending = 0;
            bool shutting_down = false;
            std::vector<worker_pool_stats> pools;
        };

        struct worker_context_options {
            preemption_policy policy = preemption_policy::default_policy;
            bool allow_driver_polling = true; //allows the thread do I/O polling
            bool prevent_thread_naming = false;
        };

        class FT_API worker_context {
            alignas(64) char data[1024];

            friend struct worker_context_impl;

        public:
            explicit worker_context(worker_context_options options = {});
            ~worker_context();
            worker_context(worker_context&&) = delete;
            worker_context(const worker_context&) = delete;
            worker_context& operator=(worker_context&&) = delete;
            worker_context& operator=(const worker_context&) = delete;

            bool is_shut_down() const noexcept;

            bool is_joined() const noexcept;

            bool next();
            bool next_until(fast_task::time_point time_point);

            template <class Dur_resolution, class Dur_type>
            bool next_for(std::chrono::duration<Dur_resolution, Dur_type> duration) {
                return next_until(fast_task::clock::now() + duration);
            }

            size_t poll_all();
            size_t poll_drained();
            size_t poll(size_t count = 1);
            size_t poll_until(fast_task::time_point time_point);
            size_t poll_until(size_t count, fast_task::time_point time_point);

            template <class Dur_resolution, class Dur_type>
            size_t poll_for(std::chrono::duration<Dur_resolution, Dur_type> duration) {
                return poll_until(fast_task::clock::now() + duration);
            }

            template <class Dur_resolution, class Dur_type>
            size_t poll_for(size_t count, std::chrono::duration<Dur_resolution, Dur_type> duration) {
                return poll_until(count, fast_task::clock::now() + duration);
            }
        };

        class FT_API worker_pool {
            static constexpr size_t storage_size = 8192 + 64;
            alignas(64) std::byte storage[storage_size];

            struct global_pool_tag {};

            explicit worker_pool(global_pool_tag);

            friend struct worker_pool_impl;

        public:
            explicit worker_pool(worker_pool_options options = {});
            ~worker_pool();

            worker_pool(const worker_pool&) = delete;
            worker_pool(worker_pool&&) = delete;
            worker_pool& operator=(const worker_pool&) = delete;
            worker_pool& operator=(worker_pool&&) = delete;

            static worker_pool create(worker_pool_options options = {}) {
                return worker_pool(std::move(options));
            }

            static worker_pool& global();
            static void configure_global(worker_pool_options options);

            bool is_global() const noexcept;

            void join_pool(worker_context& ctx);
            void leave_pool(worker_context& ctx) noexcept;

            void bind(const task& t) noexcept;
            void post(task&& t);
            void post(const task& t);
            void post(std::span<const task> tasks);
            void schedule_until(task&& t, fast_task::time_point time_point);
            void schedule_until(const task& t, fast_task::time_point time_point);

            template <class Rep, class Period>
            void schedule(task&& t, std::chrono::duration<Rep, Period> duration) {
                schedule_until(std::move(t), fast_task::clock::now() + duration);
            }

            template <class Rep, class Period>
            void schedule(const task& t, std::chrono::duration<Rep, Period> duration) {
                schedule_until(t, fast_task::clock::now() + duration);
            }

            void request_workers(uint16_t target);
            void add_workers(uint16_t count = 1);
            void remove_workers(uint16_t count = 1);

            void pause();
            void resume();
            bool is_paused() const noexcept;

            void set_min_workers(uint16_t min);
            void set_max_workers(uint16_t max);

            worker_pool_stats stats() const noexcept;
            bool wait_idle(fast_task::time_point deadline);
        };

        void FT_API schedule_until(task&& task, fast_task::time_point time_point);
        void FT_API schedule_until(const task& task, fast_task::time_point time_point);

        template <class Dur_resolution, class Dur_type>
        void schedule(task&& task, std::chrono::duration<Dur_resolution, Dur_type> duration) {
            schedule_until(std::move(task), fast_task::clock::now() + duration);
        }

        template <class Dur_resolution, class Dur_type>
        void schedule(const task& task, std::chrono::duration<Dur_resolution, Dur_type> duration) {
            schedule_until(task, fast_task::clock::now() + duration);
        }

        void FT_API start(task&& lgr_task);
        void FT_API start(std::list<task>& lgr_task);
        void FT_API start(std::vector<task>& lgr_task);
        void FT_API start(const task& lgr_task);

        void FT_API become_task_executor();
        void FT_API await_no_tasks(bool be_worker = false);
        void FT_API await_end_tasks(bool be_worker = false);

        void FT_API explicit_start_timer();
        void FT_API shut_down();

        FT_API const task& current_context_task();


        /**
         * @brief requests stop the world to scheduler and the scheduler would stop its execution 
         *         and including internal threads and then runs the function. 
         *         This means the function is allowed only and only in native threads.
         *         
         *  @note Could be used for GC or debugging purposes
         *  @param func The function to execute when all workers stopped
         *  @throws `invalid_native_context` in task context
         *  @returns nothing
         */
        void FT_API request_stw(const std::function<void()>& func);

        //clean ups the unused memory
        void FT_API clean_up();
        void FT_API local_clean_up();

        bool FT_API preemption_enabled();
        runtime_stats FT_API get_runtime_stats();
    }
}

#endif /* FAST_TASK_INCLUDE_TASK_SCHEDULER */
