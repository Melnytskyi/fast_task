#ifndef INCLUDE_TASK_QUERY
#define INCLUDE_TASK_QUERY
#include "task.hpp"

namespace fast_task {
    class FT_API task_query {
        friend struct debug::_debug_collect;
        struct task_query_handle* handle;
        friend void __TaskQuery_add_task_leave(struct task_query_handle* tqh);

    public:
        task_query(size_t at_execution_max = 1);
        ~task_query();
        void add(std::shared_ptr<task>&);
        void add(std::shared_ptr<task>&&);
        void enable();
        void disable();
        bool in_query(const std::shared_ptr<task>& task);
        void set_max_at_execution(size_t val);
        size_t get_max_at_execution();
        void wait();
        bool wait_until(std::chrono::high_resolution_clock::time_point time_point);

        template <class Rep, class Period>
        bool wait_for(const std::chrono::duration<Rep, Period>& duration) {
            return wait_until(std::chrono::high_resolution_clock::now() + duration);
        }
    };
}


#endif /* INCLUDE_TASK_QUERY */
