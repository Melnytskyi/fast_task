#ifndef SRC_TASKS_CLASSES_SYNCHRONIZATION_INTERNAL_SCHED_NOTIFY
#define SRC_TASKS_CLASSES_SYNCHRONIZATION_INTERNAL_SCHED_NOTIFY
#include "threading.hpp"
#include <task/enter_state.hpp>
#include <task/task.hpp>
#include <task/mutex_unify.hpp>

namespace fast_task {
    namespace debug {
        struct _debug_collect;
    }
    class FT_API_LOCAL internal_sched_cv {
        friend struct debug::_debug_collect;

        struct resume_task {
            class task task;
            uint16_t awake_check = 0;
            fast_task::condition_variable_any* native_cv = nullptr;
            bool* native_check = nullptr;
            resume_task* next = nullptr;
        };

        struct alignas(16) tagged_node {
            resume_task* ptr;
            uint64_t counter;
        };

        std::atomic<tagged_node> node;

        void push_back(resume_task* node);
        resume_task* pop_one();
        resume_task* pop_all();

    public:
        internal_sched_cv();
        ~internal_sched_cv();
        void wait(fast_task::unique_lock<mutex_unify>& lock);
        bool enter_wait(mutex_unify& mut, const task& task, enter_state&);

        void notify_one();
        void notify_all();
    };
}
#endif /* SRC_TASKS_CLASSES_SYNCHRONIZATION_INTERNAL_SCHED_NOTIFY */
