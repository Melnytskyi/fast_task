// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <experimental/futex.hpp>
#include <tasks/_internal.hpp>

#ifdef PLATFORM_LINUX
    #include <linux/futex.h>
    #include <sys/syscall.h>
    #include <unistd.h>

namespace fast_task {
    void native_futex_wait(std::atomic_uint32_t* address, uint32_t expected_value) {
        syscall(SYS_futex, address, FUTEX_WAIT_PRIVATE, expected_value, nullptr, nullptr, 0);
    }

    bool native_futex_wait_until(std::atomic<uint32_t>* address, uint32_t expected_value, std::chrono::high_resolution_clock::time_point time_point) {
        auto now = std::chrono::high_resolution_clock::now();
        if (now >= time_point)
            return false;

        auto sec = std::chrono::time_point_cast<std::chrono::seconds>(time_point);
        auto nsec = std::chrono::duration_cast<std::chrono::nanoseconds>(time_point - sec);

        struct timespec ts;
        ts.tv_sec = static_cast<time_t>(sec.time_since_epoch().count());
        ts.tv_nsec = static_cast<long>(nsec.count());

        if (ts.tv_nsec < 0) {
            ts.tv_sec -= 1;
            ts.tv_nsec += 1000000000L;
        }

        long ret = syscall(
            SYS_futex,
            address,
            FUTEX_WAIT_BITSET_PRIVATE | FUTEX_CLOCK_REALTIME,
            expected_value,
            &ts,
            nullptr,
            FUTEX_BITSET_MATCH_ANY
        );
        if (ret == -1 && errno == ETIMEDOUT)
            return false;
        return true;
    }

    void native_futex_wake(std::atomic_uint32_t* address, uint32_t count) {
        syscall(SYS_futex, address, FUTEX_WAKE_PRIVATE, count, nullptr, nullptr, 0);
    }
}
#elif defined(PLATFORM_WINDOWS)
    #include <windows.h>
    #pragma comment(lib, "Synchronization.lib")

namespace fast_task {
    void native_futex_wait(std::atomic_uint32_t* address, uint32_t expected_value) {
        WaitOnAddress(address, &expected_value, sizeof(uint32_t), INFINITE);
    }

    bool native_futex_wait_until(std::atomic<uint32_t>* address, uint32_t expected_value, std::chrono::high_resolution_clock::time_point time_point) {
        auto now = std::chrono::high_resolution_clock::now();
        if (now >= time_point)
            return false;

        auto dur = time_point - now;
        auto ms = std::chrono::ceil<std::chrono::milliseconds>(dur);

        BOOL res = WaitOnAddress(address, &expected_value, sizeof(uint32_t), static_cast<DWORD>(ms.count()));

        if (!res && GetLastError() == ERROR_TIMEOUT)
            return false;
        return true;
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
            : first(&b0 < &b1 ? b1 : b0), second(&b1 < &b0 ? b1 : b0), is_the_same(&b0 == &b1), order(&b0 > &b1) {
            first.lock.lock();
            is_first_locked = true;
            if (!is_the_same)
                second.lock.lock();
            is_second_locked = true;
        }

        ~two_bucket_guard() {
            if (is_first_locked)
                first.lock.unlock();
            if (!is_the_same && is_second_locked)
                second.lock.unlock();
        }

        void unlock_0() {
            first.lock.unlock();
            is_first_locked = false;
        }

        void unlock_1() {
            second.lock.unlock();
            is_second_locked = false;
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
            if (order)
                unlock_0();
            else
                unlock_1();
        }

        void unlock_b1() {
            if (order)
                unlock_1();
            else
                unlock_0();
        }

        void lock_b0() {
            if (order)
                lock_0();
            else
                lock_1();
        }

        void lock_b1() {
            if (order)
                lock_1();
            else
                lock_0();
        }

        auto release_b0() {
            if (order)
                return release_0();
            else
                return release_1();
        }

        auto release_b1() {
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
            auto& wd = get_data(item->waiter);
            fast_task::lock_guard guard(wd);
            if (item->needs_awake_check) {
                if (wd.awake_check == item->awake_check && !wd.get_time_end()) {
                    item->lock_callback(item->wait_address, item->waiter);
                    wd.set_awaked(true);
                    transfer_task(std::move(item->waiter), reinterpret_cast<enter_state*>(item)); //enter_state used only for coroutines in transfer_task, so by enter_* functions contract, wait_node_t is always in enter_state so I could re-use it
                }
            } else {
                item->lock_callback(item->wait_address, item->waiter);
                transfer_task(std::move(item->waiter), reinterpret_cast<enter_state*>(item));
            }
        } else {
            item->lock_callback(item->wait_address, item->waiter);
            item->native_wake.store(1, std::memory_order_release);
            native_futex_wake(&item->native_wake, 1);
        }
    }

    void wake_item(wait_node_t* item) {
        if (item->type == node_type::enter_wait_and_lock && item->lock_callback) {
            wake_item_and_lock(item);
            return;
        }
        if (item->waiter) {
            auto& wd = get_data(item->waiter);
            fast_task::lock_guard guard(wd);
            if (item->needs_awake_check) {
                if (wd.awake_check == item->awake_check && !wd.get_time_end()) {
                    wd.set_awaked(true);
                    transfer_task(std::move(item->waiter), reinterpret_cast<enter_state*>(item)); //enter_state used only for coroutines in transfer_task, so by enter_* functions contract, wait_node_t is always in enter_state so I could re-use it
                }
            } else
                transfer_task(std::move(item->waiter), reinterpret_cast<enter_state*>(item));
        } else {
            auto* wake_addr = &item->native_wake;
            wake_addr->store(1, std::memory_order_release);
            native_futex_wake(wake_addr, 1);
        }
    }

    void process_unlock_and_wait(wait_node_t* head, size_t& wake_ups) {
        if (wake_ups) {
            --wake_ups;
            if (head->next_wait_addr_check_callback(head->next_wait_addr, false))
                wake_item(head);
            else {
                head->wait_address = head->next_wait_addr;
                head->type = node_type::wait;
                bucket_t& bucket = glob.futex_global.get_bucket(head->wait_address);
                std::unique_lock guard(bucket.lock);
                if (head->next_wait_addr_check_callback(head->next_wait_addr, true)) {
                    guard.unlock();
                    wake_item(head);
                } else
                    make_wait(bucket, head);
            }
        } else {
            head->wait_address = head->next_wait_addr;
            head->type = node_type::wait;
            bucket_t& bucket = glob.futex_global.get_bucket(head->wait_address);
            std::unique_lock guard(bucket.lock);
            if (head->next_wait_addr_check_callback(head->next_wait_addr, true)) {
                guard.unlock();
                wake_item(head);
            } else
                make_wait(bucket, head);
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
                next_w->tail_waiter = w->tail_waiter;
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

    struct self_remove : wait_node_t {
        ~self_remove() {
            bucket_t& bucket = glob.futex_global.get_bucket(wait_address);
            std::unique_lock guard(bucket.lock);
            remove_waiter(bucket, this);
        }
    };

    void FT_API wait_on_address(void* address, bool (*check_callback)(void*)) {
        bucket_t& bucket = glob.futex_global.get_bucket(address);
        std::unique_lock guard(bucket.lock);

        if (check_callback(address))
            return;

        wait_node_t me;
        me.wait_address = address;
        me.type = node_type::wait;
        me.native_wake.store(0, std::memory_order_relaxed);
        make_wait(bucket, &me);
        auto& loc = get_loc();
        if (loc.is_task_thread && loc.curr_task) {
            me.waiter = loc.curr_task;
            swapCtxUnlock(*guard.release());
        } else {
            guard.unlock();

            uint32_t expected = 0;
            while (me.native_wake.load(std::memory_order_acquire) == 0)
                native_futex_wait(&me.native_wake, expected);
        }
    }

    bool FT_API wait_on_address_until(void* address, bool (*check_callback)(void*), std::chrono::high_resolution_clock::time_point time_point) {
        bucket_t& bucket = glob.futex_global.get_bucket(address);
        std::unique_lock guard(bucket.lock);

        if (check_callback(address))
            return true;

        wait_node_t me;
        me.wait_address = address;
        me.type = node_type::wait;
        me.native_wake.store(0, std::memory_order_relaxed);
        make_wait(bucket, &me);

        auto& loc = get_loc();
        if (loc.is_task_thread && loc.curr_task) {
            me.waiter = loc.curr_task;
            me.needs_awake_check = true;
            me.awake_check = get_data(loc.curr_task).awake_check;

            loc.pending_timer = time_point;
            swapCtxUnlock(*guard.release());

            if (get_loc().curr_task.has_wait_timed_out()) {
                auto& my_bucket = glob.futex_global.get_bucket(me.wait_address);
                std::unique_lock my_guard(my_bucket.lock);
                remove_waiter(my_bucket, &me);
                return false;
            }
            return true;
        } else {
            guard.unlock();

            uint32_t expected = 0;
            while (me.native_wake.load(std::memory_order_acquire) == 0) {
                if (!native_futex_wait_until(&me.native_wake, expected, time_point)) {
                    auto& my_bucket = glob.futex_global.get_bucket(me.wait_address);
                    std::unique_lock my_guard(my_bucket.lock);
                    if (me.in_bucket) {
                        remove_waiter(my_bucket, &me);
                        return false;
                    }
                    my_guard.unlock();

                    while (me.native_wake.load(std::memory_order_acquire) == 0)
                        native_futex_wait(&me.native_wake, 0);
                    return false;
                }
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
        bool (*is_unlocked_callback)(void*, bool)
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
        make_wait(bucket, &me);

        auto& loc = get_loc();
        if (loc.is_task_thread && loc.curr_task) {
            me.waiter = loc.curr_task;
            swapCtxUnlock(*guard.release_b0());
        } else {
            guard.unlock_b0();

            uint32_t expected = 0;
            while (me.native_wake.load(std::memory_order_acquire) == 0)
                native_futex_wait(&me.native_wake, expected);
        }
    }

    bool FT_API unlock_and_wait_until(
        void* address,
        void (*mark_up_callback)(void* address),
        bool (*check_callback)(void*),
        void* lock_address,
        bool (*make_unlock_callback)(void*, bool more_waiters_present),
        bool (*is_unlocked_callback)(void*, bool),
        std::chrono::high_resolution_clock::time_point time_point
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

        wait_node_t me;
        me.wait_address = address;
        me.next_wait_addr = lock_address;
        me.next_wait_addr_check_callback = is_unlocked_callback;
        me.type = node_type::unlock_and_wait;
        me.native_wake.store(0, std::memory_order_relaxed);
        make_wait(bucket, &me);

        auto& loc = get_loc();
        if (loc.is_task_thread && loc.curr_task) {
            me.waiter = loc.curr_task;
            me.needs_awake_check = true;
            me.awake_check = get_data(loc.curr_task).awake_check;

            loc.pending_timer = time_point;
            swapCtxUnlock(*guard.release_b0());

            if (get_loc().curr_task.has_wait_timed_out()) {
                auto& my_bucket = glob.futex_global.get_bucket(me.wait_address);
                std::unique_lock my_guard(my_bucket.lock);
                remove_waiter(my_bucket, &me);
                return false;
            }
            return true;
        } else {
            guard.unlock_b0();

            uint32_t expected = 0;
            while (me.native_wake.load(std::memory_order_acquire) == 0) {
                if (!native_futex_wait_until(&me.native_wake, expected, time_point)) {
                    auto& my_bucket = glob.futex_global.get_bucket(me.wait_address);
                    std::unique_lock my_guard(my_bucket.lock);
                    if (me.in_bucket) {
                        remove_waiter(my_bucket, &me);
                        return false;
                    }
                    my_guard.unlock();

                    while (me.native_wake.load(std::memory_order_acquire) == 0)
                        native_futex_wait(&me.native_wake, 0);
                    return false;
                }
            }
            return true;
        }
    }

    bool FT_API enter_wait_on_address(const task& task_obj, void* address, bool (*check_callback)(void*), enter_state& state) {
        bucket_t& bucket = glob.futex_global.get_bucket(address);
        std::lock_guard guard(bucket.lock);

        if (check_callback(address))
            return true;

        wait_node_t* me = state.template use<wait_node_t>();
        me->wait_address = address;
        me->waiter = task_obj;
        me->type = node_type::wait;
        make_wait(bucket, me);
        return false;
    }

    bool FT_API enter_wait_on_address_until(const task& task_obj, void* address, bool (*check_callback)(void*), enter_state& state, std::chrono::high_resolution_clock::time_point time_point) {
        bucket_t& bucket = glob.futex_global.get_bucket(address);
        std::lock_guard guard(bucket.lock);

        if (check_callback(address))
            return true;

        wait_node_t* me = state.template use<self_remove>();
        me->wait_address = address;
        me->waiter = task_obj;
        me->needs_awake_check = true;
        me->awake_check = get_data(task_obj).awake_check;
        me->type = node_type::wait;
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
        enter_state& state
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
        std::chrono::high_resolution_clock::time_point time_point
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

        wait_node_t* me = state.template use<self_remove>();
        me->wait_address = address;
        me->next_wait_addr = lock_address;
        me->next_wait_addr_check_callback = is_unlocked_callback;
        me->waiter = task_obj;
        me->needs_awake_check = true;
        me->awake_check = get_data(task_obj).awake_check;
        me->type = node_type::unlock_and_wait;
        make_wait(bucket, me);

        fast_task::makeTimeWait_extern(task_obj, time_point);

        return false;
    }

    bool FT_API enter_wait_on_address_lock(const task& task_obj, void* address, bool (*check_callback)(void*), void (*lock_callback)(void*, const task& task_obj), enter_state& state) {
        bucket_t& bucket = glob.futex_global.get_bucket(address);
        std::unique_lock guard(bucket.lock);

        if (check_callback(address)) {
            lock_callback(address, task_obj);
            return true;
        }

        wait_node_t* me = state.template use<wait_node_t>();
        me->wait_address = address;
        me->lock_callback = lock_callback;
        me->waiter = task_obj;
        me->type = node_type::enter_wait_and_lock;
        make_wait(bucket, me);
        return false;
    }

    bool FT_API enter_wait_on_address_lock_until(const task& task_obj, void* address, bool (*check_callback)(void*), void (*lock_callback)(void*, const task& task_obj), enter_state& state, std::chrono::high_resolution_clock::time_point time_point) {
        bucket_t& bucket = glob.futex_global.get_bucket(address);
        std::unique_lock guard(bucket.lock);

        if (check_callback(address)) {
            lock_callback(address, task_obj);
            return true;
        }

        wait_node_t* me = state.template use<self_remove>();
        me->wait_address = address;
        me->lock_callback = lock_callback;
        me->waiter = task_obj;
        me->needs_awake_check = true;
        me->awake_check = get_data(task_obj).awake_check;
        me->type = node_type::enter_wait_and_lock;
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
            curr = curr->next_waiter;
            count++;
            if (count > check_count) {
                callback(address, data, true);
                return true;
            }
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
}
