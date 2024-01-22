// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <tasks.hpp>

namespace fast_task {
    multiply_mutex::multiply_mutex(const std::initializer_list<mutex_unify>& muts)
        : mu(muts) {}

    void multiply_mutex::lock() {
        for (auto& mut : mu)
            mut.lock();
    }

    bool multiply_mutex::try_lock() {
        std::vector<mutex_unify> locked;
        locked.reserve(mu.size());
        for (auto& mut : mu) {
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
        for (auto& mut : mu) {
            if (mut.type != mutex_unify_type::nrec) {
                if (mut.try_lock_for(milliseconds))
                    locked.push_back(mut);
                else
                    goto fail;
            } else {
                if (mut.try_lock())
                    locked.push_back(mut);
                else
                    goto fail;
            }
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
        for (auto& mut : mu) {
            if (mut.type != mutex_unify_type::nrec) {
                if (mut.try_lock_until(time_point))
                    locked.push_back(mut);
                else
                    goto fail;
            } else {
                if (mut.try_lock())
                    locked.push_back(mut);
                else
                    goto fail;
            }
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
        size_t i = mu.size();
        while (i != 0) {
            mu[i - 1].unlock();
            --i;
        }
    }
}
