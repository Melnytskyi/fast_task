#ifndef INCLUDE_TASK_TASK
#define INCLUDE_TASK_TASK

#include "../exceptions.hpp"
#include "condition_variable.hpp"
#include "mutex_unify.hpp"
#include <functional>
#include <list>
#include <vector>

namespace fast_task {
    enum class task_priority {
        background,
        low,
        lower,
        normal,
        higher,
        high,
        semi_realtime,
    };

    //The task class has two modes,
    // the normal one allows setting `func` function which would start on ist own stack
    //  on exception it allows to catch using `ex_handle` callback
    // the extended one allows handling on_start, on_await and on_cancel events.
    //  the on_await and on_cancel executed on calling thread and could be used for example, to wrap the sockets in the task interface
    //  the on_start executed on its own stack like normal one and allows using all synchronization primitives
    //    when is_restartable is set the task could be restarted, to disable use this_task::the_coroutine_ended
    //    but when the is_on_scheduler variable is set, the task would be executed on scheduler stack which would reduce the deallocations
    //      and the task should be aware, the scheduler could not interrupt itself, so the task effectively becomes cooperative only,
    //      the task should never consume too much time on scheduler to prevent the task overloading the whole scheduler system
    //      and the task should use async_* methods for synchronization, the regular operations would throw exception
    //      this flag allows to create stackless coroutines like in c++ or other language
    class FT_API task {
        void awaitEnd(fast_task::unique_lock<mutex_unify>& l);
        struct FT_API_LOCAL execution_data;

        struct FT_API_LOCAL data {
            union FT_API_LOCAL callbacks_data {
                bool is_extended_mode : 1 = false;

                struct FT_API_LOCAL normal_mode_t {
                    bool is_extended_mode : 1;
                    std::move_only_function<void(const std::exception_ptr&)> ex_handle;
                    std::move_only_function<void()> func;

                    ~normal_mode_t() = default;
                } normal_mode;

                struct FT_API_LOCAL extended_mode_t {
                    bool is_extended_mode : 1;
                    bool is_restartable : 1;
                    void* data;
                    void (*on_start)(void*);
                    void (*on_await)(void*);
                    void (*on_cancel)(void*);
                    void (*on_destruct)(void*);

                    ~extended_mode_t() = default;
                } extended_mode;

                callbacks_data();

                callbacks_data(callbacks_data&& move) noexcept;
                ~callbacks_data();

                callbacks_data& operator=(callbacks_data&&) = delete;
            } callbacks;

            task_condition_variable result_notify;
            fast_task::spin_lock no_race;
            mutex_unify relock_0;
            mutex_unify relock_1;
            mutex_unify relock_2;
            std::chrono::high_resolution_clock::time_point::rep timeout = std::chrono::high_resolution_clock::time_point::min().time_since_epoch().count();
            uint16_t awake_check = 0;
            uint16_t bind_to_worker_id = (uint16_t)-1;
            bool time_end_flag : 1 = false;
            bool started : 1 = false;
            bool awaked : 1 = false;
            bool end_of_life : 1 = false;
            bool make_cancel : 1 = false;
            bool auto_bind_worker : 1 = false;
            bool invalid_switch_caught : 1 = false;
            bool completed : 1 = false;
            bool is_on_scheduler : 1 = false;
            execution_data* exdata = nullptr;
        } data_;

        friend task::data& get_data(task* task);
        friend task::data& get_data(std::shared_ptr<task>& task);
        friend task::data& get_data(const std::shared_ptr<task>& task);
        friend task::execution_data& get_execution_data(task* task);
        friend task::execution_data& get_execution_data(std::shared_ptr<task>& task);
        friend task::execution_data& get_execution_data(const std::shared_ptr<task>& task);

        void _extended_end();

    public:
        static size_t max_running_tasks;
        static bool enable_task_naming;

        task(void* data, void (*on_start)(void*), void (*on_await)(void*), void (*on_cancel)(void*), void (*on_destruct)(void*), bool is_restartable = false, bool is_on_scheduler = false);
        task(std::move_only_function<void()>&& func, std::move_only_function<void(const std::exception_ptr&)>&& ex_handle = nullptr, std::chrono::high_resolution_clock::time_point timeout = std::chrono::high_resolution_clock::time_point::min(), task_priority priority = task_priority::high, bool is_on_scheduler = false);

        task(task&& mov) noexcept;
        ~task();
        task& operator=(task&&) = delete;

        void set_auto_bind_worker(bool enable = true) noexcept;
        void set_worker_id(uint16_t id) noexcept;
        void set_priority(task_priority) noexcept;
        void set_timeout(std::chrono::high_resolution_clock::time_point timeout) noexcept;
        task_priority get_priority() const noexcept;
        size_t get_counter_interrupt() const noexcept;
        size_t get_counter_context_switch() const noexcept;
        std::chrono::high_resolution_clock::time_point get_timeout() const noexcept;
        bool has_wait_timed_out() const noexcept; // for timed enter_wait_until, allows to check if the operation timed out
        bool is_cancellation_requested() const noexcept;
        bool is_ended() const noexcept;
        void await_task();
        void callback(const std::shared_ptr<task>& task);
        void notify_cancel();
        void await_notify_cancel();

        template <class FN>
        void access_dummy(FN&& fn) {
            if (data_.callbacks.is_extended_mode)
                fn(data_.callbacks.extended_mode.data);
            else
                throw std::runtime_error("This task is not in extended mode");
        };

        template <class FN>
        void end_dummy(FN&& fn) {
            if (data_.callbacks.is_extended_mode) {
                fn(data_.callbacks.extended_mode.data);
                fast_task::lock_guard l(data_.no_race);
                data_.end_of_life = true;
                data_.result_notify.notify_all();
            } else
                throw std::runtime_error("This task is not in extended mode");
        };

        static std::shared_ptr<task> run(std::function<void()>&& func);
        static std::shared_ptr<task> create(std::function<void()>&& func);


        static void await_task(const std::shared_ptr<task>& lgr_task, bool make_start = true);
        static void await_multiple(std::list<std::shared_ptr<task>>& tasks, bool pre_started = false, bool release = false);
        static void await_multiple(std::vector<std::shared_ptr<task>>& tasks, bool pre_started = false, bool release = false);
        static void await_multiple(std::shared_ptr<task>* tasks, size_t len, bool pre_started = false, bool release = false);

        static std::shared_ptr<task> callback_dummy(void* dummy_data, void (*on_start)(void*), void (*on_await)(void*), void (*on_cancel)(void*), void (*on_destruct)(void*), bool is_restartable = false, bool is_on_scheduler = false);
        static std::shared_ptr<task> callback_dummy(void* dummy_data, void (*on_await)(void*), void (*on_cancel)(void*), void (*on_destruct)(void*), bool is_restartable = false, bool is_on_scheduler = false);
    };
}
#endif /* INCLUDE_TASK_TASK */
