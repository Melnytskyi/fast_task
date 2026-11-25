// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_INCLUDE_DEBUG
#define FAST_TASK_INCLUDE_DEBUG

#include "allocator.hpp"
#include "internal/task_object.hpp"
#include "shared.hpp"
#include "task.hpp"
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <new>
#include <optional>
#include <string>
#include <utility>
#include <vector>

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
     * @brief Callback to iterate the task objects.
     *
     * This function is like dump_program_state and save_program_state_dump initiates the STW,
     * and iterates all alive alive task objects, but the only difference is the function still works,
     * even if the library compiled with disabled debug tracking, because the function iterates the areas directly
     * from task object allocator.
     *
     * @throw invalid_native_context 
     * @note The function could be called only from native thread
     */
    void FT_API iterate_task_objects(void (*callback)(const task_object&, void* data), void* data);

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
    std::optional<raw_stack_trace> FT_API request_task_stack_trace(const task&);

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
    std::optional<raw_stack_trace> FT_API request_task_init_stack_trace(const task&);
    void FT_API enable_init_stack_trace(bool enable = true);
    bool FT_API is_debug_enabled();

    //helper for shared libraries
    template <class T>
    class array {
        T* ptr;
        size_t len;

        static T* allocate_elements(size_t count) {
            if (count > std::numeric_limits<size_t>::max() / sizeof(T))
                throw std::bad_array_new_length();
            const size_t bytes = count * sizeof(T);
            void* p = nullptr;
            if constexpr (alignof(T) > alignof(std::max_align_t))
                p = fast_task::allocate_aligned(bytes, alignof(T));
            else
                p = fast_task::allocate(bytes);
            if (!p)
                throw std::bad_alloc();
            return static_cast<T*>(p);
        }

        static void deallocate_elements(T* p) noexcept {
            if constexpr (alignof(T) > alignof(std::max_align_t))
                fast_task::free_aligned(p);
            else
                fast_task::free(p);
        }

    public:
        array() : ptr(nullptr), len(0) {}

        explicit array(size_t size) : ptr(nullptr), len(size) {
            if (len) {
                ptr = allocate_elements(len);
                size_t constructed_count = 0;
                try {
                    for (; constructed_count < len; ++constructed_count)
                        new (ptr + constructed_count) T();
                } catch (...) {
                    std::destroy(ptr, ptr + constructed_count);
                    deallocate_elements(ptr);
                    ptr = nullptr;
                    len = 0;
                    throw;
                }
            }
        }

        array(const array& copy) : ptr(nullptr), len(copy.len) {
            if (len) {
                ptr = allocate_elements(len);
                size_t constructed_count = 0;
                try {
                    for (; constructed_count < len; ++constructed_count)
                        new (ptr + constructed_count) T(copy[constructed_count]);
                } catch (...) {
                    std::destroy(ptr, ptr + constructed_count);
                    deallocate_elements(ptr);
                    ptr = nullptr;
                    len = 0;
                    throw;
                }
            }
        }

        array& operator=(const array& copy) {
            if (this != &copy) {
                array tmp(copy);
                *this = std::move(tmp);
            }
            return *this;
        }

        array(array&& other) noexcept : ptr(other.ptr), len(other.len) {
            other.ptr = nullptr;
            other.len = 0;
        }

        ~array() {
            if (ptr) {
                std::destroy(ptr, ptr + len);
                deallocate_elements(ptr);
            }
        }

        array& operator=(array&& other) noexcept {
            if (this != &other) {
                if (ptr) {
                    std::destroy(ptr, ptr + len);
                    deallocate_elements(ptr);
                }
                ptr = other.ptr;
                len = other.len;
                other.ptr = nullptr;
                other.len = 0;
            }
            return *this;
        }

        size_t size() const noexcept {
            return len;
        }

        bool empty() const noexcept {
            return len == 0;
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
            return ptr + len;
        }

        const T* begin() const {
            return ptr;
        }

        const T* end() const {
            return ptr + len;
        }
    };

    struct FT_API awake_item {
        uintptr_t id = 0;
        uint16_t awake_check = 0;
        bool native_awake = false;
    };

    struct FT_API raw_stack_trace {
        struct FT_API entry {
            void* entry_ptr = nullptr;

            struct FT_API_LOCAL lazy_resolve {
                std::string symbol;
                std::string file;
                int64_t line = -1;
                int64_t column = -1;
                bool is_inline = false;
            };

            lazy_resolve* dat = nullptr;
            entry() = default;
            entry(const entry& other);
            entry(entry&& other) noexcept;
            entry& operator=(const entry& other);
            entry& operator=(entry&& other) noexcept;
            ~entry();

            std::string symbol(); //empty = no symbol info
            std::string file();   //empty = no symbol info
            int64_t line();       //-1 = no line
            int64_t column();     //-1 = no column
            bool is_inline();
        };

        array<entry> entries;
    };

    struct FT_API raw_tls_info {
        //RESERVED
        uint16_t tls_capacity = 0;
    };

    struct FT_API raw_task_info {
        uintptr_t task_id = 0;
        enum class status_e : uint8_t {
            created,
            scheduled,
            running,
            suspending,
            suspended,
            ended,
        };
        status_e status = status_e::created;
        bool is_restartable : 1 = false;
        bool is_on_scheduler : 1 = false;
        bool time_end : 1 = false;
        bool awaked : 1 = false;
        bool pool_assigned : 1 = false;
        bool is_sbo : 1 = false;
        bool spin_lock_locked : 1 = false;
        bool cancellation_requested : 1 = false;
        bool invalid_switch_caught : 1 = false;
        bool completed : 1 = false;
        bool stored_exception : 1 = false;
        uint32_t counter = 0;
        array<awake_item> waiting_tasks_ids;
        raw_tls_info* tls_info = nullptr; //could be nullptr
        int64_t timeout_timestamp = 0;

        raw_stack_trace call_stack;
        size_t counter_interrupt = 0;
        size_t counter_context_switch = 0;
        task_priority priority = task_priority::high;
        uint16_t awake_check = 0; //if check does not match with check from awake_item the awake is invalid and would be ignored by scheduler. This is intended behavior.
        uint8_t pool_slot = 0;    //0..254 user pool, 255 global

        uintptr_t created_by_id = 0;
        bool created_by_is_native = false; //defines meaning of the created_by_id field, if false the id means the task id

        uint64_t current_available_quantum_ns = 0;
        size_t interrupt_data = 0;
        to_start_override* on_start_override = nullptr;
        const task_vtable* vtable = nullptr;
        raw_stack_trace* init_call_stack = nullptr;

        raw_task_info();
        raw_task_info(const raw_task_info& other);
        raw_task_info(raw_task_info&& other) noexcept;
        raw_task_info& operator=(const raw_task_info& other);
        raw_task_info& operator=(raw_task_info&& other) noexcept;
        ~raw_task_info();
    };

    struct FT_API raw_mutex_info {
        uintptr_t mutex_id = 0;
        uintptr_t owner_id = FT_DEBUG_OPTIONAL; //optional
        bool owner_is_native = false;
        array<awake_item> waiting_tasks_ids;
        raw_stack_trace* init_call_stack = nullptr;

        uintptr_t created_by_id = 0;
        bool created_by_is_native = false; //defines meaning of the created_by_id field, if false the id means the task id

        raw_mutex_info();
        raw_mutex_info(const raw_mutex_info& other);
        raw_mutex_info(raw_mutex_info&& other) noexcept;
        raw_mutex_info& operator=(const raw_mutex_info& other);
        raw_mutex_info& operator=(raw_mutex_info&& other) noexcept;
        ~raw_mutex_info();
    };

    struct FT_API raw_recursive_mutex_info {
        uintptr_t mutex_id = 0;
        uintptr_t internal_mutex_id = FT_DEBUG_OPTIONAL;
        uintptr_t recursion_count = 0;
        raw_stack_trace* init_call_stack = nullptr;

        uintptr_t created_by_id = 0;
        bool created_by_is_native = false; //defines meaning of the created_by_id field, if false the id means the task id

        raw_recursive_mutex_info();
        raw_recursive_mutex_info(const raw_recursive_mutex_info& other);
        raw_recursive_mutex_info(raw_recursive_mutex_info&& other) noexcept;
        raw_recursive_mutex_info& operator=(const raw_recursive_mutex_info& other);
        raw_recursive_mutex_info& operator=(raw_recursive_mutex_info&& other) noexcept;
        ~raw_recursive_mutex_info();
    };

    struct FT_API raw_rw_mutex_info {
        uintptr_t mutex_id = 0;
        uintptr_t writer_id = FT_DEBUG_OPTIONAL; //optional //if defined the readers is locked
        bool writer_is_native = false;
        array<uintptr_t> reader_tasks_ids; //if this defined and `writer_task_id` defined the readers locking the writer
        array<awake_item> wait_tasks_ids;
        // For each entry in `wait_tasks_ids`, the futex waiter key that the
        // waiter registered with. For an rw_mutex this distinguishes readers
        // (key 1) from writers (key 0). Same length as `wait_tasks_ids`.
        array<uint8_t> wait_tasks_keys;
        raw_stack_trace* init_call_stack = nullptr;

        uintptr_t created_by_id = 0;
        bool created_by_is_native = false; //defines meaning of the created_by_id field, if false the id means the task id

        raw_rw_mutex_info();
        raw_rw_mutex_info(const raw_rw_mutex_info& other);
        raw_rw_mutex_info(raw_rw_mutex_info&& other) noexcept;
        raw_rw_mutex_info& operator=(const raw_rw_mutex_info& other);
        raw_rw_mutex_info& operator=(raw_rw_mutex_info&& other) noexcept;
        ~raw_rw_mutex_info();
    };

    struct FT_API raw_condition_info {
        uintptr_t condition_id = 0;
        array<awake_item> waiting_tasks_ids;
        raw_stack_trace* init_call_stack = nullptr;

        uintptr_t created_by_id = 0;
        bool created_by_is_native = false; //defines meaning of the created_by_id field, if false the id means the task id

        raw_condition_info();
        raw_condition_info(const raw_condition_info& other);
        raw_condition_info(raw_condition_info&& other) noexcept;
        raw_condition_info& operator=(const raw_condition_info& other);
        raw_condition_info& operator=(raw_condition_info&& other) noexcept;
        ~raw_condition_info();
    };

    struct FT_API raw_semaphore_info {
        uintptr_t semaphore_id = 0;
        array<awake_item> waiting_tasks_ids;
        size_t allow_threshold = 0;
        size_t max_threshold = 0;
        raw_stack_trace* init_call_stack = nullptr;

        uintptr_t created_by_id = 0;
        bool created_by_is_native = false; //defines meaning of the created_by_id field, if false the id means the task id

        raw_semaphore_info();
        raw_semaphore_info(const raw_semaphore_info& other);
        raw_semaphore_info(raw_semaphore_info&& other) noexcept;
        raw_semaphore_info& operator=(const raw_semaphore_info& other);
        raw_semaphore_info& operator=(raw_semaphore_info&& other) noexcept;
        ~raw_semaphore_info();
    };

    struct FT_API raw_limiter_info {
        uintptr_t limiter_id = 0;
        array<awake_item> waiting_tasks_ids;
        size_t allow_threshold = 0;
        size_t max_threshold = 0;
        bool locked = false;
        raw_stack_trace* init_call_stack = nullptr;

        uintptr_t created_by_id = 0;
        bool created_by_is_native = false; //defines meaning of the created_by_id field, if false the id means the task id

        raw_limiter_info();
        raw_limiter_info(const raw_limiter_info& other);
        raw_limiter_info(raw_limiter_info&& other) noexcept;
        raw_limiter_info& operator=(const raw_limiter_info& other);
        raw_limiter_info& operator=(raw_limiter_info&& other) noexcept;
        ~raw_limiter_info();
    };

    struct FT_API raw_queue_info {
        uintptr_t queue_id = 0;
        uintptr_t internal_condition_id = FT_DEBUG_OPTIONAL;
        array<uintptr_t> waiting_tasks_ids;
        size_t current_in_run = 0;
        size_t max_on_execution = 0;
        bool enabled = false;
        raw_stack_trace* init_call_stack = nullptr;

        uintptr_t created_by_id = 0;
        bool created_by_is_native = false; //defines meaning of the created_by_id field, if false the id means the task id

        raw_queue_info();
        raw_queue_info(const raw_queue_info& other);
        raw_queue_info(raw_queue_info&& other) noexcept;
        raw_queue_info& operator=(const raw_queue_info& other);
        raw_queue_info& operator=(raw_queue_info&& other) noexcept;
        ~raw_queue_info();
    };

    struct FT_API raw_deadline_timer_info {
        uintptr_t timer_id = 0;
        uintptr_t internal_mutex_id = FT_DEBUG_OPTIONAL;
        int64_t timestamp = 0;
        array<uintptr_t> canceled_tasks;
        array<uintptr_t> scheduled_tasks;
        bool shutdown = false;
        raw_stack_trace* init_call_stack = nullptr;

        uintptr_t created_by_id = 0;
        bool created_by_is_native = false; //defines meaning of the created_by_id field, if false the id means the task id

        raw_deadline_timer_info();
        raw_deadline_timer_info(const raw_deadline_timer_info& other);
        raw_deadline_timer_info(raw_deadline_timer_info&& other) noexcept;
        raw_deadline_timer_info& operator=(const raw_deadline_timer_info& other);
        raw_deadline_timer_info& operator=(raw_deadline_timer_info&& other) noexcept;
        ~raw_deadline_timer_info();
    };

    struct FT_API program_state_dump {
        int64_t start_timestamp = 0;
        int64_t end_timestamp = 0;
        array<raw_task_info> tasks;
        array<raw_mutex_info> mutexes;
        array<raw_recursive_mutex_info> rec_mutexes;
        array<raw_rw_mutex_info> rw_mutexes;
        array<raw_condition_info> condition_variables;
        array<raw_semaphore_info> semaphores;
        array<raw_limiter_info> limiters;
        array<raw_queue_info> queries;
        array<raw_deadline_timer_info> deadlines;
    };
}

/** 
 * @brief helpers for debuggers with functionality to call functions for debug state, obviously is not safe for use in programs
 */
std::vector<fast_task::task_object*> FT_API collect_task_objects(); //available in all settings

#endif /* FAST_TASK_INCLUDE_DEBUG */
