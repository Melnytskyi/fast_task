// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <fast_task/task.hpp>
#include <tasks/_internal.hpp>

namespace fast_task {
    multiply_mutex::multiply_mutex(const std::initializer_list<mutex_unify>& muts)
        : value{muts} {}

    void multiply_mutex::lock() {
        size_t locked_count = 0;
        try {
            for (auto& mut : value.mu) {
                mut.lock();
                ++locked_count;
            }
        } catch (...) {
            while (locked_count != 0) {
                --locked_count;
                value.mu[locked_count].unlock();
            }
            throw;
        }
    }

    bool multiply_mutex::try_lock() {
        size_t locked_count = 0;
        try {
            for (auto& mut : value.mu) {
                if (mut.try_lock())
                    ++locked_count;
                else {
                    while (locked_count != 0) {
                        --locked_count;
                        value.mu[locked_count].unlock();
                    }
                    return false;
                }
            }
            return true;
        } catch (...) {
            while (locked_count != 0) {
                --locked_count;
                value.mu[locked_count].unlock();
            }
            throw;
        }
    }

    bool multiply_mutex::try_lock_until(fast_task::time_point time_point) {
        size_t locked_count = 0;
        try {
            for (auto& mut : value.mu) {
                if (mut.try_lock_until(time_point))
                    ++locked_count;
                else {
                    while (locked_count != 0) {
                        --locked_count;
                        value.mu[locked_count].unlock();
                    }
                    return false;
                }
            }
            return true;
        } catch (...) {
            while (locked_count != 0) {
                --locked_count;
                value.mu[locked_count].unlock();
            }
            throw;
        }
    }

    void multiply_mutex::unlock() {
        size_t i = value.mu.size();
        while (i != 0) {
            value.mu[i - 1].unlock();
            --i;
        }
    }

    bool multiply_mutex::enter_wait(const task& parent_coro, enter_state&) {
        if (try_lock()) {
            donate_ownership(const_cast<task*>(&parent_coro));
            return true;
        }

        task::run([this, parent_coro = parent_coro]() mutable {
            this->lock();
            for (auto& mut : this->value.mu)
                mut.donate_ownership(&parent_coro);

            bool should_transfer = true;
            {
                fast_task::lock_guard guard(get_data(parent_coro));
                if (get_data(parent_coro).is_suspending()) {
                    get_data(parent_coro).set_resume_requested(true);
                    should_transfer = false;
                }
            }
            if (should_transfer)
                transfer_task(std::move(parent_coro));
        });

        return false;
    }

    bool multiply_mutex::enter_wait_until(const task& parent_coro, enter_state&, fast_task::time_point time_point) {
        if (try_lock()) {
            donate_ownership(const_cast<task*>(&parent_coro));
            get_data(parent_coro).set_time_end(false);
            return true;
        }

        task::run([this, parent_coro = parent_coro, time_point]() mutable {
            bool acquired = this->try_lock_until(time_point);
            if (acquired) {
                for (auto& mut : this->value.mu)
                    mut.donate_ownership(&parent_coro);
            }

            bool should_transfer = true;
            {
                fast_task::lock_guard guard(get_data(parent_coro));
                get_data(parent_coro).set_time_end(!acquired);
                if (get_data(parent_coro).is_suspending()) {
                    get_data(parent_coro).set_resume_requested(true);
                    should_transfer = false;
                }
            }
            if (should_transfer)
                transfer_task(std::move(parent_coro));
        });

        return false;
    }

    void multiply_mutex::donate_ownership(fast_task::task* target_owner) {
        for (auto& mut : value.mu)
            mut.donate_ownership(target_owner);
    }
}
