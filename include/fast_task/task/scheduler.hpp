// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_INCLUDE_TASK_SCHEDULER
#define FAST_TASK_INCLUDE_TASK_SCHEDULER
#include "task.hpp"
#include <functional>
#include <list>
#include <variant>
#include <vector>

namespace fast_task {
    namespace scheduler {
        enum class preemption_policy {
            allows_preempt = 0,   //if fast_task built with preemptive scheduling disabled it would behave like cooperative_only
            cooperative_only = 1, //forces the scheduler to disable preemption for this worker


            default_policy = allows_preempt,
        };

        enum class worker_balancer {
            none,
            hill_climb,
        };

        // Queue and idle policies (plans/pool-architecture.md §3.1). S2a only
        // needs them as types so the pool storage can record its configuration;
        // the priority queue and the busy-spin policy are added in S3a.
        enum class queue_policy : uint8_t {
            work_stealing_lifo,
            priority_fifo,
        };

        enum class idle_policy : uint8_t {
            wait,
            busy_spin,
        };

        enum class pool_affinity_mode : uint8_t {
            mask,
            round_robin,
        };

        struct worker_affinity_options {
            std::vector<uint32_t> cpus;
            pool_affinity_mode mode = pool_affinity_mode::mask;
        };

        class worker_context;

        struct worker_hooks {
            // callback_data is the scheduler's spawn state; user_state is hooks.state.
            void (*thread_initializer)(void (*back_callback)(void* callback_data), void* callback_data, void* user_state) = nullptr;
            void (*worker_body)(worker_context& ctx, void* state) = nullptr;
            void* state = nullptr;
        };

        // Single configuration struct for a pool (§2.3/§3.1).
        //
        // `allow_implicit_start` is transitional: it keeps the legacy
        // task::set_auto_bind_worker() routing working until S2c deletes that
        // API together with create_bind_only_executor(). It will be replaced by
        // `inherit_pool_on_spawn` semantics.
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
            bool allow_implicit_start = false; // transitional; see the comment above

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

        struct worker_options {
            uint16_t bind_id = static_cast<uint16_t>(-1); //-1 is global pool
            preemption_policy policy = preemption_policy::default_policy;
            bool allow_driver_polling = true; //allows the thread do I/O polling
            bool prevent_thread_naming = false;
        };

        //this class useful for UI/Game loops
        //NOTE for agent:
        /*
        STW (Stop-The-World) Quiescent State for worker_context (Design Note for the Agent):
        A UI thread creates worker_context once before its main loop, then spends 90% of its time outside poll() (e.g., in SwapBuffers() or WaitMessage()). If worker_context increments glob.thread_count for its entire lifetime, request_stw() will deadlock waiting for the UI thread while it's blocked in SwapBuffers().
        Instead, worker_context should only mark itself as "active in scheduler" while inside next*() / poll*(), and remain in a quiescent (pre-paused) state while outside those methods.
        */
        class FT_API worker_context {
            alignas(64) char data[1024];
            // Previous thread name, restored by the destructor. Kept here rather
            // than in executors_local so the 1024-byte budget is unaffected.
            std::string saved_thread_name;

        public:
            explicit worker_context(worker_options options = {}); //the constructor initializes current thread as worker and uses the context from the stack(data[1024]), if thread already has registered context the constructor would throw exception
            ~worker_context();                           //unregisters itself
            worker_context(worker_context&&) = delete;
            worker_context(const worker_context&) = delete;
            worker_context& operator=(worker_context&&) = delete;
            worker_context& operator=(const worker_context&) = delete;

            bool is_shut_down() const noexcept;

            bool next();
            bool next_until(fast_task::time_point time_point);

            template <class Dur_resolution, class Dur_type>
            bool next_for(std::chrono::duration<Dur_resolution, Dur_type> duration) {
                return next_until(fast_task::clock::now() + duration);
            }

            size_t poll_all();
            // Runs tasks until there is nothing left to run, then returns the
            // count. Unlike poll_all() this does not wait for shutdown: it
            // returns as soon as the queues are drained, handing control back to
            // the caller. This is the worker_context equivalent of
            // taskExecutor(end_in_task_out = true).
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

        struct automatic_worker_configuration {
            uint16_t bind_id = static_cast<uint16_t>(-1); //-1 is global pool
            preemption_policy policy = preemption_policy::default_policy;
            worker_balancer balancer = worker_balancer::none;
            bool allow_implicit_start = false;
            bool allow_driver_polling = true;
            bool prevent_thread_naming = false;
            bool start_with_worker_per_core = true;
            bool abort_tasks_on_shutdown = false;
            bool prevent_shut_down = false; //works if configured as global pool
            uint16_t min_workers = 1;
            uint16_t max_workers = UINT16_MAX;

            void (*thread_initializer)(void (*back_callback)(void* data), void* data) = nullptr; //callback to start the thread, back_callback should be called inside the started thread
            void (*worker_body_override)(worker_context& context) = nullptr;                     //called inside the worker thread, the overriden body should use context
        };

        //If global pool is not configured then would be used default configuration
        //if this instance initialized global pool, it would automaticaly call shut_down in destructor(could be disabled in options)
        class FT_API workers_lifecycle {
            void* handle;

        public:
            //if create_binded_worker is true the bind_id in options is ignored and automaticaly assigned
            //could throw if the bind_id is already configured
            workers_lifecycle(automatic_worker_configuration options = {}, bool create_binded_worker = false);
            //destructor shuts the configured workers and calls shut_down() for global pool if not disabled
            ~workers_lifecycle();
            workers_lifecycle(workers_lifecycle&&);
            workers_lifecycle& operator=(workers_lifecycle&&);

            workers_lifecycle(const workers_lifecycle&) = delete;
            workers_lifecycle& operator=(const workers_lifecycle&) = delete;

            uint16_t get_bind_id() const noexcept;

            void suggest_worker_increment(uint16_t count = 1);
            void suggest_worker_decrement(uint16_t count = 1);
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

        uint16_t FT_API create_bind_only_executor(uint16_t fixed_count, bool allow_implicit_start, preemption_policy policy = preemption_policy::default_policy);          /*DEPRECATED prefer workers_lifecycle*/
        void FT_API assign_bind_only_executor(uint16_t id, uint16_t fixed_count, bool allow_implicit_start, preemption_policy policy = preemption_policy::default_policy); /*DEPRECATED prefer workers_lifecycle*/
        void FT_API close_bind_only_executor(uint16_t id, bool abort_tasks = false);                                                                                       /*DEPRECATED prefer workers_lifecycle*/

        void FT_API create_executor(size_t count = 1); //submits command to increase amount of the workers, could be overriden by the hill climber if enabled
        size_t FT_API total_executors();
        void FT_API reduce_executor(size_t count = 1); //submits command to reduce amount of the workers, could be overriden by the hill climber if enabled

        void FT_API become_task_executor(); //enters global pool
        void FT_API await_no_tasks(bool be_worker = false);
        void FT_API await_end_tasks(bool be_worker = false);

        void FT_API explicit_start_timer();
        void FT_API shut_down();

        const task& FT_API current_context_task();


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

        // Aggregate view of every live pool (plans/pool-architecture.md §2.11).
        // Replaces the removed global `executing_tasks`/`in_run_tasks` counters.
        //
        // The accessor cannot be called `runtime_stats()`: a function may not
        // share its name with the `runtime_stats` type in the same scope.
        runtime_stats FT_API get_runtime_stats();
    }
}

#endif /* FAST_TASK_INCLUDE_TASK_SCHEDULER */
