// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)
//
// Event layer: the futex hash table, the per-`deadline_timer` wake handle and
// the eventcount (`scheduler_event`) the worker idle paths wait on. Split out
// of tasks/_internal.hpp by S0b (plans/pool-architecture.md §4); S1 replaced
// the shared condition variables with two eventcounts per pool (§2.8).

#ifndef FAST_TASK_CORE_EVENT
#define FAST_TASK_CORE_EVENT

#include <atomic>
#include <cstdint>
#include <list>
#include <new>
#include <unordered_set>

#include <fast_task/clock.hpp>
#include <fast_task/internal/futex.hpp>
#include <fast_task/shared.hpp>
#include <fast_task/task.hpp>

// The deque header owns this constant; mirror its guarded definition so this
// header stays self-contained without redefining it in a combined include.
#ifndef FAST_TASK_HDI_SIZE
    #define FAST_TASK_HDI_SIZE
    #ifdef __cpp_lib_hardware_interference_size
constexpr std::size_t hardware_destructive_interference_size = std::hardware_destructive_interference_size;
    #else
constexpr std::size_t hardware_destructive_interference_size = 64;
    #endif
#endif

namespace fast_task {
    // Raw wait/wake on a single 32-bit word, implemented in tasks/futex.cpp.
    // They are the only wait primitives usable from a native (non-task) thread
    // that neither allocate a futex waiter node nor take a global lock, which
    // is exactly what the eventcount below needs.
    bool native_futex_wait_until(std::atomic<uint32_t>* address, uint32_t expected_value, fast_task::time_point time_point);
    void native_futex_wake(std::atomic_uint32_t* address, uint32_t count);

    // Eventcount (plans/pool-architecture.md §2.8): a monotonic epoch that a
    // consumer samples *before* evaluating its predicate, plus a sleeper count
    // so a notifier can skip the wake syscall when nobody is parked.
    //
    // This replaces the process-wide `tasks_notifier` condition variable: a
    // notify no longer has to take glob.task_thread_safety, so publishing one
    // task wakes exactly one worker instead of serialising every worker
    // through the same mutex.
    //
    // A wake cannot be lost: the epoch only ever moves forward, so a consumer
    // that sampled the epoch, checked its predicate and then parked will either
    // (a) observe a changed epoch and loop, or (b) have its futex compare fail
    // because the word already changed. Locking rules: pred() must not block,
    // and can be called several times per wait().
    class FT_API_LOCAL scheduler_event {
        alignas(hardware_destructive_interference_size) std::atomic<uint32_t> epoch{0};
        alignas(hardware_destructive_interference_size) std::atomic<uint32_t> sleepers{0};

    public:
        scheduler_event() = default;
        scheduler_event(const scheduler_event&) = delete;
        scheduler_event& operator=(const scheduler_event&) = delete;

        // Wake one parked consumer, if there is one.
        //
        // This is the hot enqueue notification, so it is written as Vyukov's
        // eventcount "notify": the caller's payload store must be ordered before
        // the sleeper sample, and the epoch -- and the system call -- are only
        // paid when somebody is actually parked.
        //
        // The early-out is what makes an enqueue-bound workload fast. A worker
        // that is running tasks, or one that is looking for work before it
        // parks, sees the payload by itself: its predicate is re-evaluated after
        // its own seq_cst sleeper increment, so waking it would cost a coherence
        // miss per task and buy nothing. Measured on the 1M empty-task stream:
        // gating the epoch on `sleepers` took the publish path from one futex
        // wake per task to a few thousand per million.
        //
        // Returns true when a parked waiter was woken, false when nobody was
        // parked (the publisher then has to consider the driver, which waits in
        // the multiplexer rather than here).
        bool notify_one() noexcept {
            //
            // The fence is required on a weakly ordered machine (ARM): without
            // it the publisher's payload store may still be sitting in its
            // store buffer when it samples `sleepers`, and a consumer that
            // incremented `sleepers` immediately afterwards would go to sleep
            // without seeing the payload. On x86 the hardware already forbids
            // that reordering (TSO orders every load after a preceding store,
            // and both sides of the handshake use locked RMWs), and the fence
            // would emit an `mfence` that has to drain a store buffer still full
            // of the enqueue -- measured at ~650 cycles per publish on the 1M
            // empty-task stream, i.e. twice the cost of the enqueue itself.
#if !defined(__x86_64__) && !defined(__i386__) && !defined(_M_X64) && !defined(_M_IX86)
            std::atomic_thread_fence(std::memory_order_seq_cst);
#endif
            if (sleepers.load(std::memory_order_seq_cst) == 0)
                return false;
            epoch.fetch_add(1, std::memory_order_seq_cst);
            native_futex_wake(&epoch, 1);
            return true;
        }

        void notify_all() noexcept {
            std::atomic_thread_fence(std::memory_order_seq_cst);
            epoch.fetch_add(1, std::memory_order_release);
            if (sleepers.load(std::memory_order_seq_cst) != 0)
                native_futex_wake(&epoch, UINT32_MAX);
        }

        // Blocks until pred() is true or `deadline` is reached, and returns
        // pred(). fast_task::time_point::max() waits without a timeout.
        template <class Pred>
        bool wait(Pred&& pred, fast_task::time_point deadline) noexcept {
            // The deadline kind is loop-invariant, so it is decided once: an
            // unbounded park must never read the clock on the way in.
            const bool bounded = deadline != fast_task::time_point::max();
            for (;;) {
                uint32_t observed = epoch.load(std::memory_order_acquire);
                if (pred())
                    return true;
                if (bounded && fast_task::clock::now() >= deadline)
                    return pred();

                sleepers.fetch_add(1, std::memory_order_seq_cst);
                // Re-check under the sleeper count: a notify that ran between
                // the first check and the increment must not be lost.
                if (pred() || epoch.load(std::memory_order_acquire) != observed) {
                    sleepers.fetch_sub(1, std::memory_order_relaxed);
                    continue;
                }
                native_futex_wait_until(&epoch, observed, deadline);
                sleepers.fetch_sub(1, std::memory_order_relaxed);
            }
        }

        // Sampled by a worker before it parks as the driver: a change means
        // something was published for its pool while it was not looking.
        uint32_t current_epoch() const noexcept {
            return epoch.load(std::memory_order_acquire);
        }

        bool has_sleepers() const noexcept {
            return sleepers.load(std::memory_order_relaxed) != 0;
        }
    };

    struct FT_API_LOCAL futex_global_t {
        enum class node_type : uint8_t {
            wait,
            unlock_and_wait,
            enter_wait_and_lock
        };

        struct wait_node {
            wait_node* next_addr = nullptr;
            wait_node* prev_addr = nullptr;

            wait_node* next_waiter = nullptr;
            wait_node* prev_waiter = nullptr;

            wait_node* tail_waiter = nullptr;
            void* wait_address;
            node_type type;
            bool needs_awake_check : 1 = false;
            bool in_bucket : 1 = false;
            uint8_t node_data : 6;
            uint16_t awake_check = 0;
            std::atomic_uint32_t native_wake;
            task waiter;
            void* next_wait_addr;

            union {
                bool (*next_wait_addr_check_callback)(void*, bool mark_request);
                void (*lock_callback)(void*, const task& task_obj, futex::node_data);
            };
        };

        struct alignas(hardware_destructive_interference_size) bucket {
            fast_task::native::spin_lock lock;
            wait_node* addresses = nullptr;
        };

        bucket buckets[4096];

        inline bucket& get_bucket(void* addr) {
            size_t h = reinterpret_cast<size_t>(addr);
            h ^= (h >> 20) ^ (h >> 12);
            return buckets[(h ^ (h >> 7) ^ (h >> 4)) & 0xFFF];
        }
    };

    struct deadline_timer::handle {
        std::atomic_size_t usage_count{1}; // The reference counter
        mutex no_race;
        fast_task::time_point time_point;
        std::unordered_set<size_t> canceled_tasks; //fast_task::task
        std::list<task> scheduled_tasks;           // tasks registered via async_wait(task)
        std::list<task> sleeping_tasks;            // tasks blocked in wait()
        bool shutdown = false;

        static handle* create() {
            return new handle{};
        }

        handle* acquire() {
            usage_count.fetch_add(1, std::memory_order_relaxed);
            return this;
        }

        void release() {
            if (usage_count.fetch_sub(1, std::memory_order_release) == 1) {
                std::atomic_thread_fence(std::memory_order_acquire);
                delete this;
            }
        }
    };
}

#endif /* FAST_TASK_CORE_EVENT */
