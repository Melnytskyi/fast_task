// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <tasks/_internal.hpp>
#include <tasks/classes/synchronization/internal_sched_cv.hpp>

namespace fast_task {
    void internal_sched_cv::push_back(resume_task* item) {
        tagged_node old = node.load(std::memory_order_acquire);
        while (true) {
            item->next = old.ptr;
            tagged_node desired{item, old.counter + 1};
            if (node.compare_exchange_weak(old, desired, std::memory_order_release, std::memory_order_acquire))
                break;
        }
    }

    internal_sched_cv::resume_task* internal_sched_cv::pop_one() {
        tagged_node old = node.load(std::memory_order_acquire);
        while (true) {
            tagged_node desired{old.ptr ? old.ptr->next : nullptr, old.counter + 1};
            if (node.compare_exchange_weak(old, desired, std::memory_order_release, std::memory_order_acquire))
                break;
        }
        if (old.ptr)
            old.ptr->next = nullptr;
        return old.ptr;
    }

    internal_sched_cv::resume_task* internal_sched_cv::pop_all() {
        tagged_node old = node.load(std::memory_order_acquire);
        while (true) {
            tagged_node desired{nullptr, old.counter + 1};
            if (node.compare_exchange_weak(old, desired, std::memory_order_release, std::memory_order_acquire))
                break;
        }
        return old.ptr;
    }

    internal_sched_cv::internal_sched_cv() {
        node = {nullptr, 0};
    }

    internal_sched_cv::~internal_sched_cv() {
    }

    void internal_sched_cv::wait(fast_task::unique_lock<mutex_unify>& lock) {
        resume_task node;
        if (get_loc().is_task_thread) {
            node.task = get_loc().curr_task;
            node.awake_check = get_data(get_loc().curr_task).awake_check;
            push_back(&node);
            swapCtxRelock(*lock.mutex());
        } else {
            fast_task::condition_variable_any cd;
            bool has_res = false;
            node.task = nullptr;
            node.awake_check = 0;
            node.native_cv = &cd;
            node.native_check = &has_res;

            push_back(&node);
            while (!has_res)
                cd.wait(lock);
        }
    }

    bool internal_sched_cv::enter_wait(mutex_unify& mut, const task& task, enter_state& st) {
        get_data(task).set_relock(mut);
        auto node = st.template use<resume_task>();
        node->task = task;
        node->awake_check = get_data(task).awake_check;
        push_back(node);
        return false;
    }

    void internal_sched_cv::notify_one() {
        resume_task* popped_node = pop_one();
        if (!popped_node)
            return;
        if (popped_node->task == nullptr) {
            if (popped_node->native_cv != nullptr) {
                *popped_node->native_check = true;
                popped_node->native_cv->notify_all();
            }
        } else {
            fast_task::lock_guard guard_loc(get_data(popped_node->task));
            get_data(popped_node->task).set_awaked(true);
            transfer_task(std::move(popped_node->task), reinterpret_cast<enter_state*>(popped_node));
        }
    }

    void internal_sched_cv::notify_all() {
        resume_task* popped_node = pop_all();
        while (popped_node) {
            if (popped_node->task == nullptr) {
                if (popped_node->native_cv != nullptr) {
                    *popped_node->native_check = true;
                    popped_node->native_cv->notify_all();
                }
            } else {
                fast_task::lock_guard guard_loc(get_data(popped_node->task));
                get_data(popped_node->task).set_awaked(true);
                transfer_task(std::move(popped_node->task), reinterpret_cast<enter_state*>(popped_node));
            }
            popped_node = popped_node->next;
        }
    }
}