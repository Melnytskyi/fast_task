// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_INCLUDE_TASK_SEMAPHORE
#define FAST_TASK_INCLUDE_TASK_SEMAPHORE

#include "../native.hpp"
#include "enter_state.hpp"
#include "fwd.hpp"
#include <array>
#include <atomic>
#include <vector>

#if __cplusplus >= 202002
    #include "../coroutine/core.hpp"
    #include "../coroutine/detail/lock_misc.hpp"
#endif

namespace fast_task {
    class FT_API semaphore {
        friend struct debug::_debug_collect;

        struct private_values {
            std::atomic_size_t state;
            std::atomic_size_t max_threshold;
        } values;

    public:
        semaphore();
        ~semaphore();

        void set_max_threshold(size_t val);
        void lock();
        bool try_lock();
        bool try_lock_until(fast_task::time_point time_point);
        void release();
        void release_all();
        bool is_locked();

        bool enter_wait(const task&, enter_state& task);
        bool enter_wait_until(const task&, enter_state& task, fast_task::time_point);

        template <class Rep, class Period>
        bool try_lock_for(const std::chrono::duration<Rep, Period>& duration) {
            return try_lock_until(fast_task::clock::now() + duration);
        }

#if __cplusplus >= 202002
        [[nodiscard]] inline auto async_lock() {
            return detail::async_lock(*this);
        }

        [[nodiscard]] inline auto async_try_lock_until(fast_task::time_point time_point) {
            return detail::async_try_lock_until(*this, time_point);
        }

        template <class Rep, class Period>
        [[nodiscard]] inline auto async_try_lock_for(const std::chrono::duration<Rep, Period>& duration) {
            return detail::async_try_lock_until(*this, fast_task::clock::now() + duration);
        }
#endif
    };

    //same as semaphore but with checks
    class FT_API limiter {
        friend struct debug::_debug_collect;
        friend class mutex_unify;

        struct holder_set {
            static constexpr size_t inline_capacity = 32;
            static constexpr size_t npos = size_t(-1);

            size_t at(size_t index) const noexcept {
                return index < inline_capacity ? inline_holders[index] : spilled[index - inline_capacity];
            }

            size_t& at(size_t index) noexcept {
                return index < inline_capacity ? inline_holders[index] : spilled[index - inline_capacity];
            }

            size_t find(size_t id) const noexcept {
                for (size_t i = 0; i < count; ++i)
                    if (at(i) == id)
                        return i;
                return npos;
            }

            void push(size_t id) {
                if (count < inline_capacity)
                    inline_holders[count] = id;
                else
                    spilled.push_back(id);
                ++count;
            }

            void erase(size_t index) {
                size_t last = count - 1;
                if (index != last)
                    at(index) = at(last);
                if (last >= inline_capacity)
                    spilled.pop_back();
                --count;
            }

            std::array<size_t, inline_capacity> inline_holders{};
            std::vector<size_t> spilled;
            size_t count = 0;
        };

        struct private_values {
            holder_set lock_check;
            fast_task::native::spin_lock lock_check_lock;
            std::atomic_size_t state;
            std::atomic_size_t max_threshold;
        } values;

        void unchecked_unlock();
        void check_deadlock(size_t lock_id);
        static ptrdiff_t state_to_limiter_offset(const limiter* self = nullptr) noexcept;
        static limiter* from_state_addr(void* addr) noexcept;

    public:
        limiter();
        ~limiter();

        void set_max_threshold(size_t val);
        void lock();
        bool try_lock();
        bool try_lock_until(fast_task::time_point time_point);
        void unlock();
        bool is_locked();

        bool enter_wait(const task&, enter_state& task);
        bool enter_wait_until(const task&, enter_state& task, fast_task::time_point);

        template <class Rep, class Period>
        bool try_lock_for(const std::chrono::duration<Rep, Period>& duration) {
            return try_lock_until(fast_task::clock::now() + duration);
        }
#if __cplusplus >= 202002
        [[nodiscard]] inline auto async_lock() {
            return detail::async_lock(*this);
        }

        [[nodiscard]] inline auto async_try_lock_until(fast_task::time_point time_point) {
            return detail::async_try_lock_until(*this, time_point);
        }

        template <class Rep, class Period>
        [[nodiscard]] inline auto async_try_lock_for(const std::chrono::duration<Rep, Period>& duration) {
            return detail::async_try_lock_until(*this, fast_task::clock::now() + duration);
        }
#endif
    };
}

#endif /* FAST_TASK_INCLUDE_TASK_SEMAPHORE */
