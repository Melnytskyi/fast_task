// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_INCLUDE_TASK_GROUP
#define FAST_TASK_INCLUDE_TASK_GROUP

#include "mutex.hpp"
#include "scheduler.hpp"
#include "task.hpp"
#include <utility>
#include <vector>

namespace fast_task {
    // Structured-concurrency scope: guarantees all child tasks complete
    // before the group is destroyed (cancelling and awaiting any remaining tasks).
    class task_group {
        mutable mutex mut_;
        std::vector<task> tasks_;

    public:
        task_group() = default;
        task_group(const task_group&) = delete;
        task_group& operator=(const task_group&) = delete;
        task_group(task_group&&) = delete;
        task_group& operator=(task_group&&) = delete;

        ~task_group() {
            cancel();
            wait();
        }

        template <class Fn>
        void run(Fn&& fn, task_priority priority = task_priority::normal) {
            task t = task::run(std::forward<Fn>(fn), nullptr, no_deadline, priority);
            fast_task::lock_guard<mutex> guard(mut_);
            tasks_.push_back(std::move(t));
        }

        template <class Fn>
        void run(scheduler::worker_pool& pool, Fn&& fn, task_priority priority = task_priority::normal) {
            task t = task::create(std::forward<Fn>(fn), nullptr, no_deadline, priority);
            pool.post(t);
            fast_task::lock_guard<mutex> guard(mut_);
            tasks_.push_back(std::move(t));
        }

        void add(task t) {
            if (!t)
                return;
            fast_task::lock_guard<mutex> guard(mut_);
            tasks_.push_back(std::move(t));
        }

        void cancel() {
            std::vector<task> snapshot;
            {
                fast_task::lock_guard<mutex> guard(mut_);
                snapshot = tasks_;
            }
            for (auto& t : snapshot)
                t.notify_cancel();
        }

        void wait() {
            std::vector<task> to_wait;
            {
                fast_task::lock_guard<mutex> guard(mut_);
                to_wait.swap(tasks_);
            }
            if (!to_wait.empty())
                task::await_multiple(to_wait, true);
        }

        size_t size() const {
            fast_task::lock_guard<mutex> guard(mut_);
            return tasks_.size();
        }

        bool empty() const {
            fast_task::lock_guard<mutex> guard(mut_);
            return tasks_.empty();
        }
    };
}

#endif /* FAST_TASK_INCLUDE_TASK_GROUP */
