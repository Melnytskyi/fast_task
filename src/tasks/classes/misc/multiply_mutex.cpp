// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <task.hpp>

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

    bool multiply_mutex::try_lock_for(size_t milliseconds) {
        std::vector<mutex_unify> locked;
        for (auto& mut : value.mu) {
            if (mut.try_lock_for(milliseconds))
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
}
