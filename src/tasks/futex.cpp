// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <atomic>
#include <fast_task/internal/futex.hpp>
#include <tasks/_internal.hpp>
#include <thread>

#ifdef PLATFORM_LINUX
    #include <linux/futex.h>
    #include <sys/syscall.h>
    #include <unistd.h>

namespace fast_task {
    void native_futex_wait(std::atomic_uint32_t* address, uint32_t expected_value) {
        syscall(SYS_futex, address, FUTEX_WAIT_PRIVATE, expected_value, nullptr, nullptr, 0);
    }

    bool native_futex_wait_until(std::atomic<uint32_t>* address, uint32_t expected_value, fast_task::time_point time_point) {
        struct timespec ts;
        const struct timespec* timeout = nullptr;
        if (time_point != fast_task::time_point::max()) {
            auto now = fast_task::clock::now();
            if (now >= time_point)
                return false;

            auto sec = std::chrono::time_point_cast<std::chrono::seconds>(time_point);
            auto nsec = std::chrono::duration_cast<std::chrono::nanoseconds>(time_point - sec);

            ts.tv_sec = static_cast<time_t>(sec.time_since_epoch().count());
            ts.tv_nsec = static_cast<long>(nsec.count());

            if (ts.tv_nsec < 0) {
                ts.tv_sec -= 1;
                ts.tv_nsec += 1000000000L;
            }
            timeout = &ts;
        }

        long ret = syscall(
            SYS_futex,
            address,
            FUTEX_WAIT_BITSET_PRIVATE,
            expected_value,
            timeout,
            nullptr,
            FUTEX_BITSET_MATCH_ANY
        );
        if (ret == -1 && errno == ETIMEDOUT)
            return false;
        return true;
    }

    void native_futex_wake(std::atomic_uint32_t* address, uint32_t count) {
        const long wake_count = count > static_cast<uint32_t>(INT32_MAX)
                                    ? static_cast<long>(INT32_MAX)
                                    : static_cast<long>(count);
        syscall(SYS_futex, address, FUTEX_WAKE_PRIVATE, wake_count, nullptr, nullptr, 0);
    }
}
#elif defined(PLATFORM_WINDOWS)
    #include <windows.h>
    #pragma comment(lib, "Synchronization.lib")

namespace fast_task {
    void native_futex_wait(std::atomic_uint32_t* address, uint32_t expected_value) {
        WaitOnAddress(address, &expected_value, sizeof(uint32_t), INFINITE);
    }

    bool native_futex_wait_until(std::atomic<uint32_t>* address, uint32_t expected_value, fast_task::time_point time_point) {
        for (;;) {
            auto now = fast_task::clock::now();
            if (now >= time_point)
                return false;

            DWORD wait_ms = INFINITE;
            bool clamped = false;
            if (time_point != fast_task::time_point::max()) {
                auto ms = std::chrono::ceil<std::chrono::milliseconds>(time_point - now);
                if (ms.count() > 0x7FFFFFFF) {
                    wait_ms = 0x7FFFFFFF;
                    clamped = true;
                } else if (ms.count() > 0) {
                    wait_ms = static_cast<DWORD>(ms.count());
                } else {
                    wait_ms = 0;
                }
            }

            BOOL res = WaitOnAddress(address, &expected_value, sizeof(uint32_t), wait_ms);

            if (!res && GetLastError() == ERROR_TIMEOUT) {
                if (clamped && fast_task::clock::now() < time_point)
                    continue;
                return false;
            }
            return true;
        }
    }

    void native_futex_wake(std::atomic_uint32_t* address, uint32_t count) {
        if (count == 1) {
            WakeByAddressSingle(address);
        } else
            WakeByAddressAll(address);
    }
}
#endif

namespace fast_task::futex {
    using bucket_t = futex_global_t::bucket;
    using wait_node_t = futex_global_t::wait_node;
    using node_type = futex_global_t::node_type;

    struct two_bucket_guard {
        bucket_t& first;
        bucket_t& second;
        bool is_the_same;
        bool order;
        bool is_first_locked = false;
        bool is_second_locked = false;

        two_bucket_guard(bucket_t& b0, bucket_t& b1)
            : first(&b0 < &b1 ? b1 : b0), second(&b1 < &b0 ? b1 : b0), is_the_same(&b0 == &b1), order(&b0 >= &b1) {
            first.lock.lock();
            is_first_locked = true;
            if (!is_the_same) {
                second.lock.lock();
                is_second_locked = true;
            }
        }

        ~two_bucket_guard() {
            if (is_first_locked)
                first.lock.unlock();
            if (!is_the_same && is_second_locked)
                second.lock.unlock();
        }

        void unlock_0() {
            if (is_first_locked) {
                is_first_locked = false;
                first.lock.unlock();
            }
        }

        void unlock_1() {
            if (is_second_locked) {
                is_second_locked = false;
                second.lock.unlock();
            }
        }

        void lock_0() {
            first.lock.lock();
            is_first_locked = true;
        }

        void lock_1() {
            second.lock.lock();
            is_second_locked = true;
        }

        auto release_0() {
            is_first_locked = false;
            return &first.lock;
        }

        auto release_1() {
            is_second_locked = false;
            return &second.lock;
        }

        void unlock_b0() {
            if (is_the_same || order)
                unlock_0();
            else
                unlock_1();
        }

        void unlock_b1() {
            if (is_the_same)
                return;
            if (order)
                unlock_1();
            else
                unlock_0();
        }

        void lock_b0() {
            if (is_the_same || order)
                lock_0();
            else
                lock_1();
        }

        void lock_b1() {
            if (is_the_same)
                return;
            if (order)
                lock_1();
            else
                lock_0();
        }

        auto release_b0() {
            if (is_the_same || order)
                return release_0();
            else
                return release_1();
        }

        auto release_b1() {
            if (is_the_same)
                return release_0();
            if (order)
                return release_1();
            else
                return release_0();
        }
    };

    size_t extract_waiters(bucket_t& bucket, wait_node_t*& curr, size_t count, wait_node_t*& out_head, wait_node_t*& out_tail) {
        size_t extracted = 0;
        out_head = nullptr;
        out_tail = nullptr;

        while (curr && extracted < count) {
            wait_node_t* w = curr;
            wait_node_t* next_w = w->next_waiter;
            w->in_bucket = false;

            if (next_w) {
                next_w->next_addr = w->next_addr;
                next_w->prev_addr = w->prev_addr;

                if (w->next_addr)
                    w->next_addr->prev_addr = next_w;
                if (w->prev_addr)
                    w->prev_addr->next_addr = next_w;
                else
                    bucket.addresses = next_w;

                next_w->tail_waiter = (w->tail_waiter == w) ? next_w : w->tail_waiter;
                next_w->prev_waiter = nullptr;
                curr = next_w;
            } else {
                if (w->next_addr)
                    w->next_addr->prev_addr = w->prev_addr;
                if (w->prev_addr)
                    w->prev_addr->next_addr = w->next_addr;
                else
                    bucket.addresses = w->next_addr;
                curr = nullptr;
            }

            w->next_addr = nullptr;
            w->prev_addr = nullptr;
            w->next_waiter = nullptr;
            w->prev_waiter = nullptr;

            if (!out_head)
                out_head = w;
            else {
                out_tail->next_waiter = w;
                w->prev_waiter = out_tail;
            }
            out_tail = w;
            extracted++;
        }
        return extracted;
    }

    size_t extract_waiters_selected(bucket_t& bucket, wait_node_t*& curr, size_t max_count, bool (*select_callback)(void* address, node_data data, bool first), wait_node_t*& out_head, wait_node_t*& out_tail) {
        size_t extracted = 0;
        out_head = nullptr;
        out_tail = nullptr;
        bool first = true;

        while (curr && extracted < max_count) {
            wait_node_t* w = curr;
            wait_node_t* next_w = w->next_waiter;

            if (!select_callback(w->wait_address, {w->node_data}, first)) {
                curr = next_w;
                continue;
            }

            first = false;
            w->in_bucket = false;

            if (!w->prev_waiter) {
                if (next_w) {
                    next_w->next_addr = w->next_addr;
                    next_w->prev_addr = w->prev_addr;

                    if (w->next_addr)
                        w->next_addr->prev_addr = next_w;
                    if (w->prev_addr)
                        w->prev_addr->next_addr = next_w;
                    else
                        bucket.addresses = next_w;

                    next_w->tail_waiter = (w->tail_waiter == w) ? next_w : w->tail_waiter;
                    next_w->prev_waiter = nullptr;
                } else {
                    if (w->next_addr)
                        w->next_addr->prev_addr = w->prev_addr;
                    if (w->prev_addr)
                        w->prev_addr->next_addr = w->next_addr;
                    else
                        bucket.addresses = w->next_addr;
                }
            } else {
                wait_node_t* p = w->prev_waiter;
                p->next_waiter = next_w;
                if (next_w) {
                    next_w->prev_waiter = p;
                } else {
                    wait_node_t* head = p;
                    while (head->prev_waiter)
                        head = head->prev_waiter;
                    head->tail_waiter = p;
                }
            }

            curr = next_w;

            w->next_addr = nullptr;
            w->prev_addr = nullptr;
            w->next_waiter = nullptr;
            w->prev_waiter = nullptr;

            if (!out_head)
                out_head = w;
            else {
                out_tail->next_waiter = w;
                w->prev_waiter = out_tail;
            }
            out_tail = w;
            extracted++;
        }
        return extracted;
    }

    bool more_than_selector(wait_node_t* curr, size_t check_count, node_data key) {
        size_t found = 0;

        while (curr) {
            if (curr->node_data == key.data) {
                found++;
                if (found > check_count)
                    return true;
            }
            curr = curr->next_waiter;
        }
        return false;
    }

    void make_wait(bucket_t& bucket, wait_node_t* item) {
        item->in_bucket = true;
        item->next_addr = nullptr;
        item->prev_addr = nullptr;
        item->next_waiter = nullptr;
        item->prev_waiter = nullptr;
        item->tail_waiter = item;

        wait_node_t* curr = bucket.addresses;
        while (curr && curr->wait_address != item->wait_address)
            curr = curr->next_addr;

        if (curr) {
            item->prev_waiter = curr->tail_waiter;
            curr->tail_waiter->next_waiter = item;
            curr->tail_waiter = item;
        } else {
            item->next_addr = bucket.addresses;
            if (bucket.addresses)
                bucket.addresses->prev_addr = item;
            bucket.addresses = item;
        }
    }

    void wake_item_and_lock(wait_node_t* item) {
        if (item->waiter) {
            task waiter = std::move(item->waiter);
            auto& wd = get_data(waiter);
            bool should_transfer = false;
            {
                fast_task::lock_guard guard(wd);
                if (item->needs_awake_check) {
                    if (wd.awake_check == item->awake_check && !wd.get_time_end()) {
                        item->lock_callback(item->wait_address, waiter, {item->node_data});
                        wd.set_awaked(true);
                        should_transfer = true;
                    }
                } else {
                    item->lock_callback(item->wait_address, waiter, {item->node_data});
                    should_transfer = true;
                }
            }
            item->native_wake.store(1, std::memory_order_release);
            if (should_transfer)
                transfer_task(std::move(waiter), reinterpret_cast<enter_state*>(item));
        } else {
            item->lock_callback(item->wait_address, item->waiter, {item->node_data});
            auto* wake_addr = &item->native_wake;
            wake_addr->store(1, std::memory_order_release);
            native_futex_wake(wake_addr, 1);
        }
    }

    void wake_item(wait_node_t* item) {
        if (item->type == node_type::enter_wait_and_lock && item->lock_callback) {
            wake_item_and_lock(item);
            return;
        }
        if (item->waiter) {
            task waiter = std::move(item->waiter);
            auto& wd = get_data(waiter);
            bool should_transfer = false;
            {
                fast_task::lock_guard guard(wd);
                if (item->needs_awake_check) {
                    if (wd.awake_check == item->awake_check && !wd.get_time_end()) {
                        wd.set_awaked(true);
                        should_transfer = true;
                    }
                } else {
                    should_transfer = true;
                }
            }
            item->native_wake.store(1, std::memory_order_release);
            if (should_transfer)
                transfer_task(std::move(waiter), reinterpret_cast<enter_state*>(item));
        } else {
            auto* wake_addr = &item->native_wake;
            wake_addr->store(1, std::memory_order_release);
            native_futex_wake(wake_addr, 1);
        }
    }

    void process_unlock_and_wait(wait_node_t* head, size_t& wake_ups) {
        if (wake_ups) {
            --wake_ups;
            if (head->next_wait_addr_check_callback(head->next_wait_addr, false)) {
                wake_item(head);
                return;
            }
        }
        void* next_addr = head->next_wait_addr;
        bucket_t& bucket = glob.futex_global.get_bucket(next_addr);
        std::unique_lock guard(bucket.lock);
        std::atomic_ref<void*>(head->wait_address).store(next_addr, std::memory_order_release);
        head->type = node_type::wait;
        if (head->next_wait_addr_check_callback(next_addr, true)) {
            guard.unlock();
            wake_item(head);
        } else {
            make_wait(bucket, head);
            head->native_wake.store(2, std::memory_order_release);
        }
    }

    size_t process_wakeups(wait_node_t* head, size_t wake_ups) {
        size_t count = 0;
        while (head) {
            wait_node_t* next = head->next_waiter;
            if (head->type == node_type::unlock_and_wait)
                process_unlock_and_wait(head, wake_ups);
            else
                wake_item(head);

            head = next;
            ++count;
        }
        return count;
    }

    void remove_waiter(bucket_t& bucket, wait_node_t* w) {
        if (!w->in_bucket)
            return;
        w->in_bucket = false;
        if (!w->prev_waiter) {
            wait_node_t* next_w = w->next_waiter;
            if (next_w) {
                next_w->next_addr = w->next_addr;
                next_w->prev_addr = w->prev_addr;
                if (w->next_addr)
                    w->next_addr->prev_addr = next_w;
                if (w->prev_addr)
                    w->prev_addr->next_addr = next_w;
                else
                    bucket.addresses = next_w;
                next_w->tail_waiter = (w->tail_waiter == w) ? next_w : w->tail_waiter;
                next_w->prev_waiter = nullptr;
            } else {
                if (w->next_addr)
                    w->next_addr->prev_addr = w->prev_addr;
                if (w->prev_addr)
                    w->prev_addr->next_addr = w->next_addr;
                else
                    bucket.addresses = w->next_addr;
            }
        } else {
            wait_node_t* p = w->prev_waiter;
            wait_node_t* n = w->next_waiter;
            p->next_waiter = n;

            if (n) {
                n->prev_waiter = p;
            } else {
                wait_node_t* head = p;
                while (head->prev_waiter)
                    head = head->prev_waiter;
                head->tail_waiter = p;
            }
        }

        w->next_addr = nullptr;
        w->prev_addr = nullptr;
        w->next_waiter = nullptr;
        w->prev_waiter = nullptr;
    }

    bool ___more_wait_items_on(bucket_t& bucket, void* address, size_t check_count) {
        wait_node_t* curr = bucket.addresses;
        while (curr && curr->wait_address != address)
            curr = curr->next_addr;

        if (!curr)
            return false;

        size_t count = 0;

        while (curr) {
            curr = curr->next_waiter;
            count++;
            if (count > check_count)
                return true;
        }
        return false;
    }

    //returns one node and true if there's more
    wait_node_t* extract_one(bucket_t& bucket, void* address) {
        wait_node_t* curr = bucket.addresses;
        while (curr && curr->wait_address != address)
            curr = curr->next_addr;

        wait_node_t *to_wake_head = nullptr, *to_wake_tail = nullptr;
        if (!curr)
            return nullptr;

        extract_waiters(bucket, curr, 1, to_wake_head, to_wake_tail);

        return to_wake_head;
    }

    bool cancel_or_wait_node(wait_node_t& me) {
        if (me.native_wake.load(std::memory_order_acquire) == 1)
            return true;

        bool checked_after_requeue = false;
        for (;;) {
            void* addr = std::atomic_ref<void*>(me.wait_address).load(std::memory_order_acquire);
            bucket_t& my_bucket = glob.futex_global.get_bucket(addr);
            std::unique_lock my_guard(my_bucket.lock);
            void* cur_addr = std::atomic_ref<void*>(me.wait_address).load(std::memory_order_acquire);
            if (cur_addr != addr)
                continue;

            if (me.in_bucket) {
                remove_waiter(my_bucket, &me);
                return false;
            }
            my_guard.unlock();

            uint32_t state = me.native_wake.load(std::memory_order_acquire);
            if (state == 1)
                return true;
            if (state == 2) {
                if (!checked_after_requeue) {
                    checked_after_requeue = true;
                    continue;
                }
                while (me.native_wake.load(std::memory_order_acquire) != 1)
                    std::this_thread::yield();
                return true;
            }
            while ((state = me.native_wake.load(std::memory_order_acquire)) == 0)
                std::this_thread::yield();
            if (state == 1)
                return true;
            checked_after_requeue = true;
        }
    }

    struct wait_node_cleanup_guard {
        wait_node_t& node;
        bool active = true;

        void dismiss() noexcept { active = false; }

        ~wait_node_cleanup_guard() {
            if (active)
                cancel_or_wait_node(node);
        }
    };

    struct self_remove : wait_node_t {
        ~self_remove() {
            cancel_or_wait_node(*this);
        }
    };

    void FT_API wait_on_address(void* address, bool (*check_callback)(void*), node_data data) {
        bucket_t& bucket = glob.futex_global.get_bucket(address);
        std::unique_lock guard(bucket.lock);

        if (check_callback(address))
            return;

        wait_node_t me;
        me.wait_address = address;
        me.type = node_type::wait;
        me.native_wake.store(0, std::memory_order_relaxed);
        me.node_data = data.data;
        make_wait(bucket, &me);
        auto loc = get_loc();
        if (loc && loc->is_task_thread && loc->curr_task) {
            me.waiter = loc->curr_task;
            wait_node_cleanup_guard cleanup{me};
            swapCtxUnlock(*guard.release());
            cleanup.dismiss();
        } else {
            guard.unlock();

            for (uint32_t cur = me.native_wake.load(std::memory_order_acquire); cur != 1; cur = me.native_wake.load(std::memory_order_acquire))
                native_futex_wait(&me.native_wake, cur);
        }
    }

    bool FT_API wait_on_address_until(void* address, bool (*check_callback)(void*), fast_task::time_point time_point, node_data data) {
        bucket_t& bucket = glob.futex_global.get_bucket(address);
        std::unique_lock guard(bucket.lock);

        if (check_callback(address))
            return true;

        if (fast_task::is_no_deadline(time_point) || fast_task::clock::now() >= time_point)
            return false;

        wait_node_t me;
        me.wait_address = address;
        me.type = node_type::wait;
        me.native_wake.store(0, std::memory_order_relaxed);
        me.node_data = data.data;
        make_wait(bucket, &me);

        auto loc = get_loc();
        if (loc && loc->is_task_thread && loc->curr_task) {
            me.waiter = loc->curr_task;
            me.needs_awake_check = true;
            me.awake_check = get_data(loc->curr_task).awake_check;

            loc->pending_timer = time_point;
            wait_node_cleanup_guard cleanup{me};
            swapCtxUnlock(*guard.release());
            cleanup.dismiss();

            if (get_loc()->curr_task.has_wait_timed_out())
                return cancel_or_wait_node(me);
            return true;
        } else {
            guard.unlock();

            for (uint32_t cur = me.native_wake.load(std::memory_order_acquire); cur != 1; cur = me.native_wake.load(std::memory_order_acquire)) {
                if (!native_futex_wait_until(&me.native_wake, cur, time_point))
                    return cancel_or_wait_node(me);
            }
            return true;
        }
    }

    void FT_API unlock_and_wait(
        void* address,
        void (*mark_up_callback)(void* address),
        bool (*check_callback)(void*),
        void* lock_address,
        bool (*make_unlock_callback)(void*, bool more_waiters_present),
        bool (*is_unlocked_callback)(void*, bool),
        node_data data
    ) {
        bucket_t& bucket = glob.futex_global.get_bucket(address);
        bucket_t& lock_bucket = glob.futex_global.get_bucket(lock_address);
        two_bucket_guard guard(bucket, lock_bucket);
        mark_up_callback(address);
        if (make_unlock_callback(lock_address, ___more_wait_items_on(lock_bucket, lock_address, 1))) {
            auto waiting_node = extract_one(lock_bucket, lock_address);
            guard.unlock_b1();
            process_wakeups(waiting_node, 1);
        } else
            guard.unlock_b1();

        if (check_callback(address))
            return;

        wait_node_t me;
        me.wait_address = address;
        me.next_wait_addr = lock_address;
        me.next_wait_addr_check_callback = is_unlocked_callback;
        me.type = node_type::unlock_and_wait;
        me.native_wake.store(0, std::memory_order_relaxed);
        me.node_data = data.data;
        make_wait(bucket, &me);

        auto loc = get_loc();
        if (loc && loc->is_task_thread && loc->curr_task) {
            me.waiter = loc->curr_task;
            wait_node_cleanup_guard cleanup{me};
            swapCtxUnlock(*guard.release_b0());
            cleanup.dismiss();
        } else {
            guard.unlock_b0();

            for (uint32_t cur = me.native_wake.load(std::memory_order_acquire); cur != 1; cur = me.native_wake.load(std::memory_order_acquire))
                native_futex_wait(&me.native_wake, cur);
        }
    }

    bool FT_API unlock_and_wait_until(
        void* address,
        void (*mark_up_callback)(void* address),
        bool (*check_callback)(void*),
        void* lock_address,
        bool (*make_unlock_callback)(void*, bool more_waiters_present),
        bool (*is_unlocked_callback)(void*, bool),
        fast_task::time_point time_point,
        node_data data
    ) {
        bucket_t& bucket = glob.futex_global.get_bucket(address);
        bucket_t& lock_bucket = glob.futex_global.get_bucket(lock_address);
        two_bucket_guard guard(bucket, lock_bucket);
        mark_up_callback(address);
        if (make_unlock_callback(lock_address, ___more_wait_items_on(lock_bucket, lock_address, 1))) {
            auto waiting_node = extract_one(lock_bucket, lock_address);
            guard.unlock_b1();
            process_wakeups(waiting_node, 1);
        } else
            guard.unlock_b1();

        if (check_callback(address))
            return true;

        if (fast_task::is_no_deadline(time_point) || fast_task::clock::now() >= time_point)
            return false;

        wait_node_t me;
        me.wait_address = address;
        me.next_wait_addr = lock_address;
        me.next_wait_addr_check_callback = is_unlocked_callback;
        me.type = node_type::unlock_and_wait;
        me.native_wake.store(0, std::memory_order_relaxed);
        me.node_data = data.data;
        make_wait(bucket, &me);

        auto loc = get_loc();
        if (loc && loc->is_task_thread && loc->curr_task) {
            me.waiter = loc->curr_task;
            me.needs_awake_check = true;
            me.awake_check = get_data(loc->curr_task).awake_check;

            loc->pending_timer = time_point;
            wait_node_cleanup_guard cleanup{me};
            swapCtxUnlock(*guard.release_b0());
            cleanup.dismiss();

            if (get_loc()->curr_task.has_wait_timed_out())
                return cancel_or_wait_node(me);
            return true;
        } else {
            guard.unlock_b0();

            for (uint32_t cur = me.native_wake.load(std::memory_order_acquire); cur != 1; cur = me.native_wake.load(std::memory_order_acquire)) {
                if (!native_futex_wait_until(&me.native_wake, cur, time_point))
                    return cancel_or_wait_node(me);
            }
            return true;
        }
    }

    bool FT_API enter_wait_on_address(
        const task& task_obj,
        void* address,
        bool (*check_callback)(void*),
        enter_state& state,
        node_data data
    ) {
        bucket_t& bucket = glob.futex_global.get_bucket(address);
        std::lock_guard guard(bucket.lock);

        if (check_callback(address))
            return true;

        wait_node_t* me = state.template use<wait_node_t>();
        me->wait_address = address;
        me->waiter = task_obj;
        me->type = node_type::wait;
        me->native_wake.store(0, std::memory_order_relaxed);
        me->node_data = data.data;
        make_wait(bucket, me);
        return false;
    }

    bool FT_API enter_wait_on_address_until(
        const task& task_obj,
        void* address,
        bool (*check_callback)(void*),
        enter_state& state,
        fast_task::time_point time_point,
        node_data data
    ) {
        bucket_t& bucket = glob.futex_global.get_bucket(address);
        std::lock_guard guard(bucket.lock);

        if (check_callback(address))
            return true;

        if (fast_task::is_no_deadline(time_point) || fast_task::clock::now() >= time_point) {
            get_data(task_obj).set_time_end(true);
            return true;
        }

        wait_node_t* me = state.template use<self_remove>();
        me->wait_address = address;
        me->waiter = task_obj;
        me->needs_awake_check = true;
        me->awake_check = get_data(task_obj).awake_check;
        me->type = node_type::wait;
        me->native_wake.store(0, std::memory_order_relaxed);
        me->node_data = data.data;
        make_wait(bucket, me);

        fast_task::makeTimeWait_extern(task_obj, time_point);

        return false;
    }

    bool FT_API enter_unlock_and_wait(
        const task& task_obj,
        void* address,
        void (*mark_up_callback)(void* address),
        bool (*check_callback)(void*),
        void* lock_address,
        bool (*make_unlock_callback)(void*, bool more_waiters_present),
        bool (*is_unlocked_callback)(void*, bool),
        enter_state& state,
        node_data data
    ) {
        bucket_t& bucket = glob.futex_global.get_bucket(address);
        bucket_t& lock_bucket = glob.futex_global.get_bucket(lock_address);
        two_bucket_guard guard(bucket, lock_bucket);
        mark_up_callback(address);
        if (make_unlock_callback(lock_address, ___more_wait_items_on(lock_bucket, lock_address, 1))) {

            auto waiting_node = extract_one(lock_bucket, lock_address);
            guard.unlock_b1();
            process_wakeups(waiting_node, 1);
        } else
            guard.unlock_b1();
        if (check_callback(address))
            return true;

        wait_node_t* me = state.template use<wait_node_t>();
        me->wait_address = address;
        me->next_wait_addr = lock_address;
        me->next_wait_addr_check_callback = is_unlocked_callback;
        me->waiter = task_obj;
        me->type = node_type::unlock_and_wait;
        me->native_wake.store(0, std::memory_order_relaxed);
        me->node_data = data.data;
        make_wait(bucket, me);
        return false;
    }

    bool FT_API enter_unlock_and_wait_until(
        const task& task_obj,
        void* address,
        void (*mark_up_callback)(void* address),
        bool (*check_callback)(void*),
        void* lock_address,
        bool (*make_unlock_callback)(void*, bool more_waiters_present),
        bool (*is_unlocked_callback)(void*, bool mark_request),
        enter_state& state,
        fast_task::time_point time_point,
        node_data data
    ) {
        bucket_t& bucket = glob.futex_global.get_bucket(address);
        bucket_t& lock_bucket = glob.futex_global.get_bucket(lock_address);
        two_bucket_guard guard(bucket, lock_bucket);
        mark_up_callback(address);
        if (make_unlock_callback(lock_address, ___more_wait_items_on(lock_bucket, lock_address, 1))) {
            auto waiting_node = extract_one(lock_bucket, lock_address);
            guard.unlock_b1();
            process_wakeups(waiting_node, 1);
        } else
            guard.unlock_b1();
        if (check_callback(address))
            return true;

        if (fast_task::is_no_deadline(time_point) || fast_task::clock::now() >= time_point) {
            get_data(task_obj).set_time_end(true);
            return true;
        }

        wait_node_t* me = state.template use<self_remove>();
        me->wait_address = address;
        me->next_wait_addr = lock_address;
        me->next_wait_addr_check_callback = is_unlocked_callback;
        me->waiter = task_obj;
        me->needs_awake_check = true;
        me->awake_check = get_data(task_obj).awake_check;
        me->type = node_type::unlock_and_wait;
        me->native_wake.store(0, std::memory_order_relaxed);
        me->node_data = data.data;
        make_wait(bucket, me);

        fast_task::makeTimeWait_extern(task_obj, time_point);

        return false;
    }

    bool FT_API enter_wait_on_address_lock(
        const task& task_obj,
        void* address,
        bool (*check_callback)(void*),
        void (*lock_callback)(void*, const task& task_obj, node_data),
        enter_state& state,
        node_data data
    ) {
        bucket_t& bucket = glob.futex_global.get_bucket(address);
        std::unique_lock guard(bucket.lock);

        if (check_callback(address)) {
            lock_callback(address, task_obj, data);
            return true;
        }

        wait_node_t* me = state.template use<wait_node_t>();
        me->wait_address = address;
        me->lock_callback = lock_callback;
        me->waiter = task_obj;
        me->type = node_type::enter_wait_and_lock;
        me->native_wake.store(0, std::memory_order_relaxed);
        me->node_data = data.data;
        make_wait(bucket, me);
        return false;
    }

    bool FT_API enter_wait_on_address_lock_until(
        const task& task_obj,
        void* address,
        bool (*check_callback)(void*),
        void (*lock_callback)(void*, const task& task_obj, node_data),
        enter_state& state,
        fast_task::time_point time_point,
        node_data data
    ) {
        bucket_t& bucket = glob.futex_global.get_bucket(address);
        std::unique_lock guard(bucket.lock);

        if (check_callback(address)) {
            lock_callback(address, task_obj, data);
            return true;
        }

        if (fast_task::is_no_deadline(time_point) || fast_task::clock::now() >= time_point) {
            get_data(task_obj).set_time_end(true);
            return true;
        }

        wait_node_t* me = state.template use<self_remove>();
        me->wait_address = address;
        me->lock_callback = lock_callback;
        me->waiter = task_obj;
        me->needs_awake_check = true;
        me->awake_check = get_data(task_obj).awake_check;
        me->type = node_type::enter_wait_and_lock;
        me->native_wake.store(0, std::memory_order_relaxed);
        me->node_data = data.data;
        make_wait(bucket, me);

        fast_task::makeTimeWait_extern(task_obj, time_point);

        return false;
    }

    size_t FT_API wake_and_requeue_on_address(void* address, size_t process_count, size_t wake_count) {
        if (process_count == 0)
            return 0;

        bucket_t& bucket = glob.futex_global.get_bucket(address);
        fast_task::unique_lock guard(bucket.lock);

        wait_node_t* curr = bucket.addresses;
        while (curr && curr->wait_address != address)
            curr = curr->next_addr;

        if (!curr)
            return 0;


        wait_node_t *to_wake_head, *to_wake_tail;
        extract_waiters(bucket, curr, process_count, to_wake_head, to_wake_tail);

        guard.unlock();

        return process_wakeups(to_wake_head, wake_count);
    }

    size_t FT_API wake_and_requeue_on_address(void* address, void (*pre_release)(void*, size_t, bool has_remaining), size_t process_count, size_t wake_count) {
        bucket_t& bucket = glob.futex_global.get_bucket(address);
        fast_task::unique_lock guard(bucket.lock);

        wait_node_t* curr = bucket.addresses;
        while (curr && curr->wait_address != address)
            curr = curr->next_addr;

        if (!curr) {
            pre_release(address, 0, false);
            return 0;
        }


        wait_node_t *to_wake_head, *to_wake_tail;
        size_t extracted = extract_waiters(bucket, curr, process_count, to_wake_head, to_wake_tail);
        bool has_remaining = (curr != nullptr);

        pre_release(address, extracted, has_remaining);

        guard.unlock();

        return process_wakeups(to_wake_head, wake_count);
    }

    size_t FT_API wake_and_requeue_on_address_select(void* address, void (*pre_release)(void*, size_t, bool has_remaining), bool (*select_callback)(void* address, node_data data, bool first), size_t process_count, size_t wake_count) {
        bucket_t& bucket = glob.futex_global.get_bucket(address);
        fast_task::unique_lock guard(bucket.lock);

        wait_node_t* curr = bucket.addresses;
        while (curr && curr->wait_address != address)
            curr = curr->next_addr;

        if (!curr) {
            pre_release(address, 0, false);
            return 0;
        }

        wait_node_t *to_wake_head, *to_wake_tail;
        size_t extracted = extract_waiters_selected(bucket, curr, process_count, select_callback, to_wake_head, to_wake_tail);

        bool has_remaining = false;
        for (wait_node_t* it = bucket.addresses; it; it = it->next_addr) {
            if (it->wait_address != address)
                continue;
            for (wait_node_t* w = it; w; w = w->next_waiter) {
                if (select_callback(w->wait_address, {w->node_data}, false)) {
                    has_remaining = true;
                    break;
                }
            }
            break;
        }

        pre_release(address, extracted, has_remaining);

        guard.unlock();
        return process_wakeups(to_wake_head, wake_count);
    }

    size_t FT_API wait_items_on(void* address, node_data key) {
        bucket_t& bucket = glob.futex_global.get_bucket(address);
        fast_task::lock_guard guard(bucket.lock);

        wait_node_t* curr = bucket.addresses;
        while (curr && curr->wait_address != address)
            curr = curr->next_addr;

        if (!curr)
            return 0;

        size_t count = 0;

        while (curr) {
            if (curr->node_data == key.data)
                count++;
            curr = curr->next_waiter;
        }
        return count;
    }

    bool FT_API more_wait_items_on(void* address, size_t check_count, node_data key) {
        bucket_t& bucket = glob.futex_global.get_bucket(address);
        fast_task::lock_guard guard(bucket.lock);
        wait_node_t* curr = bucket.addresses;
        while (curr && curr->wait_address != address)
            curr = curr->next_addr;
        return more_than_selector(curr, check_count, key);
    }

    size_t FT_API wait_items_on(void* address, void (*callback)(void* address, void* data, size_t result), void* data, node_data key) {
        bucket_t& bucket = glob.futex_global.get_bucket(address);
        fast_task::lock_guard guard(bucket.lock);

        wait_node_t* curr = bucket.addresses;
        while (curr && curr->wait_address != address)
            curr = curr->next_addr;

        if (!curr) {
            callback(address, data, 0);
            return false;
        }

        size_t count = 0;

        while (curr) {
            if (curr->node_data == key.data)
                count++;
            curr = curr->next_waiter;
        }
        callback(address, data, count);
        return count;
    }

    bool FT_API more_wait_items_on(void* address, size_t check_count, void (*callback)(void* address, void* data, bool result), void* data, node_data key) {
        bucket_t& bucket = glob.futex_global.get_bucket(address);
        fast_task::lock_guard guard(bucket.lock);

        wait_node_t* curr = bucket.addresses;
        while (curr && curr->wait_address != address)
            curr = curr->next_addr;

        if (!curr) {
            callback(address, data, false);
            return false;
        }

        size_t count = 0;

        while (curr) {
            if (curr->node_data == key.data) {
                count++;
                if (count > check_count) {
                    callback(address, data, true);
                    return true;
                }
            }
            curr = curr->next_waiter;
        }
        callback(address, data, false);
        return false;
    }

    bool FT_API has_waiters(void* address) {
        bucket_t& bucket = glob.futex_global.get_bucket(address);
        fast_task::lock_guard guard(bucket.lock);

        wait_node_t* curr = bucket.addresses;
        while (curr && curr->wait_address != address)
            curr = curr->next_addr;

        return curr != nullptr;
    }

    bool FT_API has_waiters(void* address, node_data key) {
        bucket_t& bucket = glob.futex_global.get_bucket(address);
        fast_task::lock_guard guard(bucket.lock);

        wait_node_t* curr = bucket.addresses;
        while (curr && curr->wait_address != address)
            curr = curr->next_addr;

        return more_than_selector(curr, 0, key);
    }

    bool FT_API has_waiters(void* address, void (*callback)(void* address, void* data, bool result), void* data, node_data key) {
        bucket_t& bucket = glob.futex_global.get_bucket(address);
        fast_task::lock_guard guard(bucket.lock);

        wait_node_t* curr = bucket.addresses;
        while (curr && curr->wait_address != address)
            curr = curr->next_addr;
        auto res = more_than_selector(curr, 0, key);
        callback(address, data, res);
        return res;
    }

    size_t FT_API wait_items_on(void* address) {
        bucket_t& bucket = glob.futex_global.get_bucket(address);
        fast_task::lock_guard guard(bucket.lock);

        wait_node_t* curr = bucket.addresses;
        while (curr && curr->wait_address != address)
            curr = curr->next_addr;

        if (!curr)
            return 0;

        size_t count = 0;

        while (curr) {
            curr = curr->next_waiter;
            count++;
        }
        return count;
    }

    bool FT_API more_wait_items_on(void* address, size_t check_count) {
        bucket_t& bucket = glob.futex_global.get_bucket(address);
        fast_task::lock_guard guard(bucket.lock);
        wait_node_t* curr = bucket.addresses;
        while (curr && curr->wait_address != address)
            curr = curr->next_addr;
        return ___more_wait_items_on(bucket, address, check_count);
    }

    size_t FT_API wait_items_on(void* address, void (*callback)(void* address, void* data, size_t result), void* data) {
        bucket_t& bucket = glob.futex_global.get_bucket(address);
        fast_task::lock_guard guard(bucket.lock);

        wait_node_t* curr = bucket.addresses;
        while (curr && curr->wait_address != address)
            curr = curr->next_addr;

        if (!curr) {
            callback(address, data, 0);
            return false;
        }

        size_t count = 0;

        while (curr) {
            curr = curr->next_waiter;
            count++;
        }
        callback(address, data, count);
        return count;
    }

    bool FT_API more_wait_items_on(void* address, size_t check_count, void (*callback)(void* address, void* data, bool result), void* data) {
        bucket_t& bucket = glob.futex_global.get_bucket(address);
        fast_task::lock_guard guard(bucket.lock);

        wait_node_t* curr = bucket.addresses;
        while (curr && curr->wait_address != address)
            curr = curr->next_addr;

        if (!curr) {
            callback(address, data, false);
            return false;
        }

        size_t count = 0;

        while (curr) {
            count++;
            if (count > check_count) {
                callback(address, data, true);
                return true;
            }
            curr = curr->next_waiter;
        }
        callback(address, data, false);
        return false;
    }

    bool FT_API has_waiters(void* address, void (*callback)(void* address, void* data, bool result), void* data) {
        bucket_t& bucket = glob.futex_global.get_bucket(address);
        fast_task::lock_guard guard(bucket.lock);

        wait_node_t* curr = bucket.addresses;
        while (curr && curr->wait_address != address)
            curr = curr->next_addr;
        auto res = curr != nullptr;
        callback(address, data, res);
        return res;
    }

    size_t FT_API iterate_waiters(void* address, void (*callback)(void* address, void* data, const waiter_info& info), void* data) {
        bucket_t& bucket = glob.futex_global.get_bucket(address);
        fast_task::lock_guard guard(bucket.lock);

        wait_node_t* curr = bucket.addresses;
        while (curr && curr->wait_address != address)
            curr = curr->next_addr;

        if (!curr)
            return 0;

        size_t count = 0;
        while (curr) {
            size_t id = curr->waiter ? curr->waiter.get_id() : 0;
            waiter_info info{
                .task_id = id,
                .key = node_data{curr->node_data},
                .is_native = !curr->waiter
            };
            callback(address, data, info);
            ++count;
            curr = curr->next_waiter;
        }
        return count;
    }

    size_t FT_API iterate_waiters(void* address, void (*callback)(void* address, void* data, const waiter_info& info), void* data, node_data key) {
        bucket_t& bucket = glob.futex_global.get_bucket(address);
        fast_task::lock_guard guard(bucket.lock);

        wait_node_t* curr = bucket.addresses;
        while (curr && curr->wait_address != address)
            curr = curr->next_addr;

        if (!curr)
            return 0;

        size_t count = 0;
        while (curr) {
            if (curr->node_data == key.data) {
                size_t id = curr->waiter ? curr->waiter.get_id() : 0;
                waiter_info info{
                    .task_id = id,
                    .key = node_data{curr->node_data},
                    .is_native = !curr->waiter
                };
                callback(address, data, info);
                ++count;
            }
            curr = curr->next_waiter;
        }
        return count;
    }
}
