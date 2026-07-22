#ifndef INCLUDE_INTERNAL_TASK_OBJECT
#define INCLUDE_INTERNAL_TASK_OBJECT
#include "../shared.hpp"
#include <atomic>
#include <task/mutex_unify.hpp>
#include <task/task.hpp>

namespace fast_task {
    class to_start_override {
    public:
        virtual void callback(task_object*) = 0;
        virtual void on_destruct(to_start_override*) = 0; //called when task is destructed and requires to_start_override to be freed

        virtual ~to_start_override() = default;
    };

    struct alignas(64) FT_API_LOCAL task_object {
        struct FT_API_LOCAL wait_item;
        struct FT_API_LOCAL execution_data;
        enum class status_e : uint8_t {
            released, //internal, used for allocation
            created,
            scheduled,
            running,
            suspending,
            suspended,
            ended,
        };

        struct state_f {
            enum f : uint16_t {
                is_restartable = 0x1,
                is_on_scheduler = 0x2,
                time_end = 0x4,
                awaked = 0x8,
                auto_bind = 0x10,
                is_sbo = 0x20,
                spin_lock_locked = 0x40,
                cancellation_requested = 0x80,
                invalid_switch_caught = 0x100,
                completed = 0x200,
            };
        };

        enum class execution_mode : uint8_t { //uses state_f
            stackfull = 0x0,
            _stackfull_reserved = 0x01,
            stackless_callback = 0x02,
            as_coroutine = 0x03,
        };

        std::atomic<wait_item*> on_wait;     // 8[also re-used in allocator for linked list of free task_object items]
        std::atomic<uint32_t> link_counter;  // 4
        std::atomic<state_f::f> state;       // 2
        std::atomic<status_e> status;        // 1
        uint8_t relock_type;                 // 1
        std::atomic<void*> tls_data;         // 8
        std::atomic<execution_data*> exdata; // 8
        const task_vtable* vtable;           // 8
        void* relock;                        // 8
        uint16_t bind_to_worker_id;          // 2
        uint16_t tls_capacity;               // 2
        uint16_t awake_check;                // 2
        uint16_t arena_offset_pages;         // 2[also used for allocator, do not modify!]
        to_start_override* on_start_override;

        alignas(std::max_align_t) std::byte sbo_buffer[64];

        bool get_time_end() const noexcept;
        void set_time_end(bool state) noexcept;
        bool get_awaked() const noexcept;
        void set_awaked(bool state) noexcept;
        bool get_auto_bind() const noexcept;
        void set_auto_bind(bool state) noexcept;
        bool get_is_restartable() const noexcept;
        void set_is_restartable(bool state) noexcept;
        bool get_is_on_scheduler() const noexcept;
        void set_is_on_scheduler(bool state) noexcept;
        bool get_is_sbo() const noexcept;
        void set_is_sbo(bool state) noexcept;
        bool get_cancellation_requested() const noexcept;
        void set_cancellation_requested(bool state) noexcept;
        bool get_invalid_switch_caught() const noexcept;
        void set_invalid_switch_caught(bool state) noexcept;
        bool get_completed() const noexcept;
        void set_completed(bool state) noexcept;
        execution_mode get_execution_mode() const noexcept;

        void set_status(status_e) noexcept;

        bool is_scheduled() const noexcept; // status != created
        bool is_created() const noexcept;   // status == created
        bool is_running() const noexcept;   // status == running
        bool is_suspended() const noexcept; // status == suspended
        bool is_ended() const noexcept;     // status == ended
        bool is_released() const noexcept;  // status == released

        void* user_data() const noexcept;
        void end_of_life_notify();

        void lock() noexcept;
        void unlock() noexcept;

        void wait();
        void wait_until(std::chrono::high_resolution_clock::time_point);
        void cancel();

        bool enter_wait(const task&, enter_state& state);
        bool enter_wait_until(const task&, enter_state& state, std::chrono::high_resolution_clock::time_point);
        bool enter_cancel(const task&, enter_state& state);

        mutex_unify get_relock() const noexcept;
        void set_relock(mutex_unify) noexcept;

        static task_object* alloc();
        static task_object* use(task_object*) noexcept;
        static void free(task_object* obj);

        mutex_unify get_self_unify() noexcept;
        size_t get_id() const noexcept;
    };
}

#endif /* INCLUDE_INTERNAL_TASK_OBJECT */
