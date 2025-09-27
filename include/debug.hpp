// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_INCLUDE_DEBUG
#define FAST_TASK_INCLUDE_DEBUG

#include "allocator.hpp"
#include "shared.hpp"
#include "task.hpp"
#include <cstdint>

#define FT_DEBUG_OPTIONAL UINTPTR_MAX

namespace fast_task::debug {
    struct FT_API program_state_dump;
    struct FT_API raw_stack_trace;
    /**
     * @brief Captures a raw snapshot of the entire fast_task state.
     *
     * This function initiates a brief "Stop-the-World" pause to ensure a consistent
     * snapshot. It is designed for minimal latency and captures only raw, unresolved
     * data (task IDs, internal states, mutex ownership, and raw stack traces). All 
     * expensive operations like symbol resolution are deferred.
     *
     * @throw invalid_native_context 
     * @note The function could be called only from native thread, if library compiled
     *  without debug api, the dump would be empty
     * 
     * @return A program_state_dump object containing the raw fast_task state.
     */
    program_state_dump FT_API dump_program_state();


    void FT_API save_program_state_dump(const char* path);


    /**
     * @brief Captures the tasks raw stack trace
     *
     * This function initiates a short "Stop-the-World" pause to ensure safe access to
     * the context and joins the context to collect stack and then returns back with
     * the result.
     *
     * @throw invalid_native_context
     * @note The function could be called only from native thread
     * 
     * @return A tasks current stack trace if available
     */
    std::optional<raw_stack_trace> FT_API request_task_stack_trace(const std::shared_ptr<task>&);

    /**
     * @brief Gets the tasks initialization raw stack trace
     *
     * This function locks the debug mutex and then receives the stack trace from
     * internal field and then returns.
     *
     * @note The function could be called only from native thread, if library
     *  compiled without debug api, the trace would never be available
     * 
     * @return A task initialization stack trace if available
     */
    std::optional<raw_stack_trace> FT_API request_task_init_stack_trace(const std::shared_ptr<task>&);
    void FT_API enable_init_stack_trace(bool enable = true);
    bool FT_API is_debug_enabled();

    //helper for shared libraries
    template <class T>
    class FT_API array {
        T* ptr;
        size_t size;

    public:
        array() : ptr(nullptr), size(0) {}

        explicit array(size_t size) : size(size) {
            if (size) {
                ptr = static_cast<T*>(fast_task::allocate(size * sizeof(T)));
                if (!ptr)
                    throw std::bad_alloc();
                size_t constructed_count = 0;
                try {
                    for (; constructed_count < size; ++constructed_count)
                        new (ptr + constructed_count) T();
                } catch (...) {
                    std::destroy(ptr, ptr + constructed_count);
                    fast_task::free(ptr);
                    ptr = nullptr;
                    throw;
                }
            } else
                ptr = nullptr;
        }

        array(const array& copy) : ptr(nullptr), size(copy.size) {
            if (size) {
                ptr = static_cast<T*>(fast_task::allocate(size * sizeof(T)));
                if (!ptr)
                    throw std::bad_alloc();
                size_t constructed_count = 0;
                try {
                    for (; constructed_count < size; ++constructed_count)
                        new (ptr + constructed_count) T(copy[constructed_count]);
                } catch (...) {
                    std::destroy(ptr, ptr + constructed_count);
                    fast_task::free(ptr);
                    ptr = nullptr;
                    throw;
                }
            }
        }

        array& operator=(const array&) = delete;

        array(array&& other) noexcept : ptr(other.ptr), size(other.size) {
            other.ptr = nullptr;
            other.size = 0;
        }

        ~array() {
            if (ptr) {
                std::destroy(ptr, ptr + size);
                fast_task::free(ptr);
            }
        }

        array& operator=(array&& other) noexcept {
            if (this != &other) {
                if (ptr) {
                    std::destroy(ptr, ptr + size);
                    fast_task::free(ptr);
                }
                ptr = other.ptr;
                size = other.size;
                other.ptr = nullptr;
                other.size = 0;
            }
            return *this;
        }

        T& operator[](size_t i) {
            return ptr[i];
        }

        const T& operator[](size_t i) const {
            return ptr[i];
        }

        T* begin() {
            return ptr;
        }

        T* end() {
            return ptr + size;
        }

        const T* begin() const {
            return ptr;
        }

        const T* end() const {
            return ptr + size;
        }
    };

    struct FT_API awake_item {
        uintptr_t id;
        uint16_t awake_check;
        bool native_awake;
    };

    struct FT_API raw_stack_trace {
        struct FT_API entry {
            void* entry_ptr;

            struct FT_API_LOCAL lazy_resolve {
                std::string symbol;
                std::string file;
                int64_t line;
                int64_t column;
                bool is_inline;
            };

            lazy_resolve* dat = nullptr;
            entry() = default;
            ~entry();

            std::string symbol(); //empty = no symbol info
            std::string file();   //empty = no symbol info
            int64_t line();       //-1 = no line
            int64_t column();     //-1 = no column
            bool is_inline();
        };

        array<entry> entries;
    };

    struct FT_API raw_task_info {
        uintptr_t task_id;
        uintptr_t internal_condition_id;

        raw_stack_trace call_stack;
        size_t counter_interrupt;
        size_t counter_context_switch;
        task_priority priority;
        uint16_t awake_check; //if check does not match with check from awake_item the awake is invalid and would be ignored by scheduler. This is intended behavior.
        uint16_t bind_to_worker_id;
        bool time_end_flag : 1;
        bool started : 1;
        bool awaked : 1;
        bool end_of_life : 1;
        bool make_cancel : 1;
        bool auto_bind_worker : 1;
        bool invalid_switch_caught : 1;
        bool completed : 1;

        int64_t timeout_timestamp;
        raw_stack_trace* init_call_stack = nullptr;

        uintptr_t created_by_id;
        bool created_by_is_native; //defines meanin of the created_by_id field, of false the id is the tasks id

        raw_task_info();
        ~raw_task_info();
    };

    struct FT_API raw_mutex_info {
        uintptr_t mutex_id;
        uintptr_t owner_id; //optional
        bool owner_is_native;
        array<awake_item> waiting_tasks_ids;
        raw_stack_trace* init_call_stack = nullptr;

        uintptr_t created_by_id;
        bool created_by_is_native; //defines meanin of the created_by_id field, of false the id is the tasks id

        raw_mutex_info();
        ~raw_mutex_info();
    };

    struct FT_API raw_recursive_mutex_info {
        uintptr_t mutex_id;
        uintptr_t internal_mutex_id;
        uintptr_t recursion_count;
        raw_stack_trace* init_call_stack = nullptr;

        uintptr_t created_by_id;
        bool created_by_is_native; //defines meanin of the created_by_id field, of false the id is the tasks id

        raw_recursive_mutex_info();
        ~raw_recursive_mutex_info();
    };

    struct FT_API raw_rw_mutex_info {
        uintptr_t mutex_id;
        uintptr_t writer_id; //optional //if defined the readers is locked
        bool writer_is_native;
        array<uintptr_t> reader_tasks_ids; //if this defined and `writer_task_id` defined the readers locking the writer
        array<awake_item> wait_tasks_ids;
        raw_stack_trace* init_call_stack = nullptr;

        uintptr_t created_by_id;
        bool created_by_is_native; //defines meanin of the created_by_id field, of false the id is the tasks id

        raw_rw_mutex_info();
        ~raw_rw_mutex_info();
    };

    struct FT_API raw_condition_info {
        uintptr_t condition_id;
        array<awake_item> waiting_tasks_ids;
        raw_stack_trace* init_call_stack = nullptr;

        uintptr_t created_by_id;
        bool created_by_is_native; //defines meanin of the created_by_id field, of false the id is the tasks id

        raw_condition_info();
        ~raw_condition_info();
    };

    struct FT_API raw_semaphore_info {
        uintptr_t semaphore_id;
        array<awake_item> waiting_tasks_ids;
        size_t allow_threshold;
        size_t max_threshold;
        raw_stack_trace* init_call_stack = nullptr;

        uintptr_t created_by_id;
        bool created_by_is_native; //defines meanin of the created_by_id field, of false the id is the tasks id

        raw_semaphore_info();
        ~raw_semaphore_info();
    };

    struct FT_API raw_limiter_info {
        uintptr_t limiter_id;
        array<awake_item> waiting_tasks_ids;
        size_t allow_threshold;
        size_t max_threshold;
        bool locked;
        raw_stack_trace* init_call_stack = nullptr;

        uintptr_t created_by_id;
        bool created_by_is_native; //defines meanin of the created_by_id field, of false the id is the tasks id

        raw_limiter_info();
        ~raw_limiter_info();
    };

    struct FT_API raw_query_info {
        uintptr_t query_id;
        uintptr_t internal_condition_id;
        array<uintptr_t> waiting_tasks_ids;
        size_t current_in_run;
        size_t max_on_execution;
        bool enabled;
        raw_stack_trace* init_call_stack = nullptr;

        uintptr_t created_by_id;
        bool created_by_is_native; //defines meanin of the created_by_id field, of false the id is the tasks id

        raw_query_info();
        ~raw_query_info();
    };

    struct FT_API raw_deadline_timer_info {
        uintptr_t timer_id;
        uintptr_t internal_mutex_id;
        int64_t timestamp;
        array<uintptr_t> canceled_tasks;
        array<uintptr_t> scheduled_tasks;
        bool shutdown;
        raw_stack_trace* init_call_stack = nullptr;

        uintptr_t created_by_id;
        bool created_by_is_native; //defines meanin of the created_by_id field, of false the id is the tasks id

        raw_deadline_timer_info();
        ~raw_deadline_timer_info();
    };

    struct FT_API program_state_dump {
        int64_t start_timestamp;
        int64_t end_timestamp;
        array<raw_task_info> tasks;
        array<raw_mutex_info> mutexes;
        array<raw_recursive_mutex_info> rec_mutexes;
        array<raw_rw_mutex_info> rw_mutexes;
        array<raw_condition_info> condition_variables;
        array<raw_semaphore_info> semaphores;
        array<raw_limiter_info> limiters;
        array<raw_query_info> queries;
        array<raw_deadline_timer_info> deadlines;
    };
}
#endif /* FAST_TASK_INCLUDE_DEBUG */
