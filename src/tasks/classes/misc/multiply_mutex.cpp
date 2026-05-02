// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <task.hpp>
#include <tasks/_internal.hpp>

namespace fast_task {
    multiply_mutex::multiply_mutex(const std::initializer_list<mutex_unify>& muts)
        : value{muts} {}

    void multiply_mutex::lock() {
        for (auto& mut : value.mu)
            mut.lock();
    }

    bool multiply_mutex::try_lock() {
        std::vector<mutex_unify> locked;
        locked.reserve(value.mu.size());
        for (auto& mut : value.mu) {
            if (mut.try_lock())
                locked.push_back(mut);
            else
                goto fail;
        }
        return true;
    fail:
        size_t i = locked.size();
        while (i != 0) {
            locked[i - 1].unlock();
            --i;
        }
        return false;
    }

    bool multiply_mutex::try_lock_until(std::chrono::high_resolution_clock::time_point time_point) {
        std::vector<mutex_unify> locked;
        for (auto& mut : value.mu) {
            if (mut.try_lock_until(time_point))
                locked.push_back(mut);
            else
                goto fail;
        }
        return true;
    fail:
        size_t i = locked.size();
        while (i != 0) {
            locked[i - 1].unlock();
            --i;
        }
        return false;
    }

    void multiply_mutex::unlock() {
        size_t i = value.mu.size();
        while (i != 0) {
            value.mu[i - 1].unlock();
            --i;
        }
    }

    bool multiply_mutex::enter_wait(const std::shared_ptr<task>& parent_coro) {
        if (try_lock())
            return true;

        task::run([this, parent_coro = parent_coro]() mutable {
            this->lock();
            for (auto& mut : this->value.mu)
                mut.donate_ownership(parent_coro.get());

            transfer_task(std::move(parent_coro));
        });

        return false;
    }

    bool multiply_mutex::enter_wait_until(const std::shared_ptr<task>& parent_coro, std::chrono::high_resolution_clock::time_point time_point) {
        if (try_lock())
            return true;

        task::run([this, parent_coro = parent_coro, time_point]() mutable {
            if (this->try_lock_until(time_point)) {
                for (auto& mut : this->value.mu) {
                    mut.donate_ownership(parent_coro.get());
                }
            } else
                get_data(parent_coro).time_end_flag = true;

            transfer_task(std::move(parent_coro));
        });

        return false;
    }

    void multiply_mutex::donate_ownership(fast_task::task* target_owner) {
        for (auto& mut : value.mu)
            mut.donate_ownership(target_owner);
    }
}
