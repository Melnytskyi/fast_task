// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_INCLUDE_TASK_MUTEX
#define FAST_TASK_INCLUDE_TASK_MUTEX
#include "../native/spin_lock.hpp"
#include "enter_state.hpp"
#include "fwd.hpp"
#include <list>


#if __cplusplus >= 202002
    #include "../coroutine/core.hpp"
    #include "../coroutine/detail/lock_misc.hpp"
#endif

namespace fast_task {
    class FT_API mutex {
        friend class recursive_mutex;
        friend struct debug::_debug_collect;
        friend class mutex_unify;
        friend class condition_variable;

        std::atomic_size_t state;

        void transfer_ownership(size_t to_owner);
        void mark_has_wait();
        void set_unlocked(bool has_remaining);

    public:
        mutex();
        ~mutex();

        void lock();
        bool try_lock();
        bool try_lock_until(fast_task::time_point time_point);
        void unlock();
        bool is_locked();
        void lifecycle_lock(task&& task);
        bool is_own();


        bool enter_wait(const task&, enter_state& task);
        bool enter_wait_until(const task&, enter_state& task, fast_task::time_point);

        template <class Rep, class Period>
        bool try_lock_for(const std::chrono::duration<Rep, Period>& duration) {
            return try_lock_until(fast_task::clock::now() + duration);
        }

#if __cplusplus >= 202002
        [[nodiscard]] auto async_lock() {
            return detail::async_lock(*this);
        }

        [[nodiscard]] auto async_try_lock_until(fast_task::time_point time_point) {
            return detail::async_try_lock_until(*this, time_point);
        }

        template <class Rep, class Period>
        [[nodiscard]] auto async_try_lock_for(const std::chrono::duration<Rep, Period>& duration) {
            return detail::async_try_lock_until(*this, fast_task::clock::now() + duration);
        }
#endif
    };

    using timed_mutex = mutex;

    class FT_API recursive_mutex {
        friend struct debug::_debug_collect;
        friend class mutex_unify;
        mutex mut;
        std::atomic<uint32_t> recursive_count{0};

    public:
        recursive_mutex();
        ~recursive_mutex();

        void lock();
        bool try_lock();
        bool try_lock_until(fast_task::time_point time_point);
        void unlock();
        bool is_locked();
        void lifecycle_lock(task&& task);
        bool is_own();


        bool enter_wait(const task&, enter_state& task);
        bool enter_wait_until(const task&, enter_state& task, fast_task::time_point);

        template <class Rep, class Period>
        bool try_lock_for(const std::chrono::duration<Rep, Period>& duration) {
            return try_lock_until(fast_task::clock::now() + duration);
        }

#if __cplusplus >= 202002
        [[nodiscard]] auto async_lock() {
            return detail::async_lock(*this);
        }

        [[nodiscard]] auto async_try_lock_until(fast_task::time_point time_point) {
            return detail::async_try_lock_until(*this, time_point);
        }

        template <class Rep, class Period>
        [[nodiscard]] auto async_try_lock_for(const std::chrono::duration<Rep, Period>& duration) {
            return detail::async_try_lock_until(*this, fast_task::clock::now() + duration);
        }
#endif
    };

    class FT_API rw_mutex {
        friend struct debug::_debug_collect;
        friend class mutex_unify;

        struct FT_API_LOCAL private_values {
            static constexpr inline uint64_t READER_ONE = 1;
            static constexpr inline uint64_t HAS_READER_WAITERS = uint64_t(1) << 61;
            static constexpr inline uint64_t HAS_WRITER_WAITERS = uint64_t(1) << 62;
            static constexpr inline uint64_t WRITER_LOCKED = uint64_t(1) << 63;
            static constexpr inline uint64_t READER_COUNT_MASK = HAS_READER_WAITERS - 1;
            static constexpr inline uint64_t OWNERSHIP_MASK = WRITER_LOCKED | READER_COUNT_MASK;

            static constexpr inline uint8_t READER_KEY = 1;
            static constexpr inline uint8_t WRITER_KEY = 0;
            static constexpr inline size_t cache_line_size = 64;

            alignas(cache_line_size) std::atomic<uint64_t> state{0};
            std::atomic<size_t> writer_owner{0};
        };

        private_values values;

        inline size_t debug_writer_owner() const noexcept {
            if ((values.state.load(std::memory_order_relaxed) & private_values::WRITER_LOCKED) == 0)
                return 0;
            return values.writer_owner.load(std::memory_order_relaxed);
        }

        inline size_t debug_reader_count() const noexcept {
            return size_t(values.state.load(std::memory_order_relaxed) & private_values::READER_COUNT_MASK);
        }

        static rw_mutex::private_values& values_of(void* state_address) {
            return *reinterpret_cast<rw_mutex::private_values*>(reinterpret_cast<char*>(state_address) - offsetof(rw_mutex::private_values, state));
        }

        static bool reader_can_acquire(uint64_t state) {
            return (state & (private_values::WRITER_LOCKED | private_values::HAS_WRITER_WAITERS)) == 0;
        }

        static bool writer_can_acquire(uint64_t state) {
            return (state & private_values::OWNERSHIP_MASK) == 0;
        }

        static bool read_probe(void* state_address) noexcept;
        static bool write_probe(void* state_address) noexcept;

        static size_t wake_writers(private_values& values, size_t count);
        static size_t wake_readers(private_values& values);
        static void reader_left(private_values& values, uint64_t state) noexcept;


    public:
        using read_write_mutex = void;
        rw_mutex();
        ~rw_mutex();
        void read_lock();
        bool try_read_lock();
        bool try_read_lock_until(fast_task::time_point time_point);
        void read_unlock();
        bool is_read_locked();
        void lifecycle_read_lock(task&& task);

        void write_lock();
        bool try_write_lock();
        bool try_write_lock_until(fast_task::time_point time_point);
        void write_unlock();
        bool is_write_locked();
        void lifecycle_write_lock(task&& task);

        void lock() {
            write_lock();
        }

        void unlock() {
            write_unlock();
        }

        bool try_lock() {
            return try_write_lock();
        }

        void lock_shared() {
            read_lock();
        }

        void unlock_shared() {
            read_unlock();
        }

        bool try_lock_shared() {
            return try_read_lock();
        }

        bool is_own();


        bool enter_read_wait(const task&, enter_state& task);
        bool enter_read_wait_until(const task&, enter_state& task, fast_task::time_point);

        bool enter_write_wait(const task&, enter_state& task);
        bool enter_write_wait_until(const task&, enter_state& task, fast_task::time_point);

        template <class Rep, class Period>
        bool try_read_lock_for(const std::chrono::duration<Rep, Period>& duration) {
            return try_read_lock_until(fast_task::clock::now() + duration);
        }

        template <class Rep, class Period>
        bool try_write_lock_for(const std::chrono::duration<Rep, Period>& duration) {
            return try_write_lock_until(fast_task::clock::now() + duration);
        }
#if __cplusplus >= 202002
    private:
        struct read_lock_awaiter {
            enter_state state;
            rw_mutex& mutex;

            bool await_ready() noexcept {
                return mutex.try_read_lock();
            }

            template <std::derived_from<task_promise_base> Promise>
            bool await_suspend(std::coroutine_handle<Promise> h) {
                return !mutex.enter_read_wait(h.promise().task_object, state);
            }

            void await_resume() noexcept {}
        };

        struct write_lock_awaiter {
            enter_state state;
            rw_mutex& mutex;

            bool await_ready() noexcept {
                return mutex.try_write_lock();
            }

            template <std::derived_from<task_promise_base> Promise>
            bool await_suspend(std::coroutine_handle<Promise> h) {
                return !mutex.enter_write_wait(h.promise().task_object, state);
            }

            void await_resume() noexcept {}
        };

        struct try_read_lock_until_awaiter {
            enter_state state;
            rw_mutex& mutex;
            fast_task::time_point time_point;
            fast_task::task task_obj;
            bool successful = false;

            bool await_ready() noexcept {
                if (mutex.try_read_lock()) {
                    successful = true;
                    return true;
                }
                return false;
            }

            template <std::derived_from<task_promise_base> Promise>
            bool await_suspend(std::coroutine_handle<Promise> h) {
                task_obj = h.promise().task_object;
                if (mutex.enter_read_wait_until(task_obj, state, time_point)) {
                    successful = !task_obj.has_wait_timed_out();
                    return false;
                }
                return true;
            }

            bool await_resume() noexcept {
                if (successful)
                    return true;
                successful = !task_obj.has_wait_timed_out();
                return successful;
            }
        };

        struct try_write_lock_until_awaiter {
            enter_state state;
            rw_mutex& mutex;
            fast_task::time_point time_point;
            fast_task::task task_obj;
            bool successful = false;

            bool await_ready() noexcept {
                if (mutex.try_write_lock()) {
                    successful = true;
                    return true;
                }
                return false;
            }

            template <std::derived_from<task_promise_base> Promise>
            bool await_suspend(std::coroutine_handle<Promise> h) {
                task_obj = h.promise().task_object;
                if (mutex.enter_write_wait_until(task_obj, state, time_point)) {
                    successful = !task_obj.has_wait_timed_out();
                    return false;
                }
                return true;
            }

            bool await_resume() noexcept {
                if (successful)
                    return true;
                successful = !task_obj.has_wait_timed_out();
                return successful;
            }
        };

    public:
        [[nodiscard]] auto async_read_lock() {
            return read_lock_awaiter{{}, *this};
        }

        [[nodiscard]] auto async_write_lock() {
            return write_lock_awaiter{{}, *this};
        }

        [[nodiscard]] auto async_try_read_lock_until(fast_task::time_point time_point) {
            return try_read_lock_until_awaiter{{}, *this, time_point, {}};
        }

        template <class Rep, class Period>
        [[nodiscard]] auto async_try_read_lock_for(const std::chrono::duration<Rep, Period>& duration) {
            return async_try_read_lock_until(fast_task::clock::now() + duration);
        }

        [[nodiscard]] auto async_try_write_lock_until(fast_task::time_point time_point) {
            return try_write_lock_until_awaiter{{}, *this, time_point, {}};
        }

        template <class Rep, class Period>
        [[nodiscard]] auto async_try_write_lock_for(const std::chrono::duration<Rep, Period>& duration) {
            return async_try_write_lock_until(fast_task::clock::now() + duration);
        }
#endif
    };

    class FT_API read_lock {
        rw_mutex& mutex;

    public:
        read_lock(rw_mutex& mutex)
            : mutex(mutex) {
            mutex.read_lock();
        }

        ~read_lock() {
            mutex.read_unlock();
        }
    };

    class FT_API write_lock {
        rw_mutex& mutex;

    public:
        write_lock(rw_mutex& mutex)
            : mutex(mutex) {
            mutex.write_lock();
        }

        ~write_lock() {
            mutex.write_unlock();
        }
    };

    //stackfull or native tasks only
    template <class T, class mutex_t = rw_mutex>
    class protected_value {
        T value;

    public:
        mutable mutex_t mutex;

        template <class... Args>
        protected_value(Args&&... args)
            : value(std::forward<Args>(args)...) {}

        protected_value(protected_value&& move)
            : value(std::move(move.value)) {}

        protected_value& operator=(protected_value&& move) = delete;

        template <class _Accessor>
        decltype(auto) get(_Accessor&& accessor) const {
            shared_lock lock(mutex);
            return accessor(value);
        }

        template <class _Accessor>
        decltype(auto) set(_Accessor&& accessor) {
            unique_lock lock(mutex);
            return accessor(value);
        }
    };
}


#endif /* FAST_TASK_INCLUDE_TASK_MUTEX */
