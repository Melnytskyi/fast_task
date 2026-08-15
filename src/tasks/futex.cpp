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

    size_t extract_waiters(bucket_t& bucket, wait_node_t*& curr, size_t count, wait_node_t*& out_head, wait_node_t*& out_tail) {
        size_t extracted = 0;
        out_head = nullptr;
        out_tail = nullptr;

        while (curr && extracted < count) {
            wait_node_t* w = curr;
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
            w->wait_address = nullptr;

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

    void wake_item(wait_node_t* item) {
        if (item->type == node_type::enter_wait_and_lock)
            if (item->lock_callback)
                item->lock_callback(item->wait_address, item->waiter);
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
            item->native_wake.store(1, std::memory_order_release);
            native_futex_wake(&item->native_wake, 1);
        }
    }

    size_t process_wakeups(wait_node_t* head, size_t wake_ups) {
        size_t count = 0;
        while (head) {
            wait_node_t* next = head->next_waiter;
            if (wake_ups) {
                --wake_ups;
                if (head->type == node_type::unlock_and_wait) {
                    if (head->next_wait_addr_check_callback(head->next_wait_addr, false))
                        wake_item(head);
                    else {
                        head->wait_address = head->next_wait_addr;
                        head->type = node_type::wait;
                        bucket_t& bucket = glob.futex_global.get_bucket(head->wait_address);
                        std::unique_lock guard(bucket.lock);
                        head->next_wait_addr_check_callback(head->next_wait_addr, true);
                        make_wait(bucket, head);
                    }
                } else
                    wake_item(head);
            } else {
                if (head->type == node_type::unlock_and_wait) {
                    head->wait_address = head->next_wait_addr;
                    head->type = node_type::wait;
                    bucket_t& bucket = glob.futex_global.get_bucket(head->wait_address);
                    std::unique_lock guard(bucket.lock);
                    head->next_wait_addr_check_callback(head->next_wait_addr, true);
                    make_wait(bucket, head);
                } else
                    wake_item(head);
            }
            head = next;
            ++count;
        }
        return count;
    }

    void remove_waiter(bucket_t& bucket, wait_node_t* w) {
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
        make_wait(bucket, &me);
        auto& loc = get_loc();
        if (loc.is_task_thread && loc.curr_task) {
            me.waiter = loc.curr_task;
            swapCtxUnlock(bucket.lock);
        } else {
            me.native_wake.store(0, std::memory_order_relaxed);
            guard.unlock();

            uint32_t expected = 0;
            while (me.native_wake.load(std::memory_order_acquire) == 0)
                native_futex_wait(&me.native_wake, expected);
        }
    }

    bool FT_API wait_on_address_until(void* address, bool (*check_callback)(void*), std::chrono::high_resolution_clock::time_point time_point) {
        if (time_point <= std::chrono::high_resolution_clock::now())
            return false;
        bucket_t& bucket = glob.futex_global.get_bucket(address);
        std::unique_lock guard(bucket.lock);

        if (check_callback(address))
            return true;

        wait_node_t me;
        me.wait_address = address;
        me.type = node_type::wait;
        make_wait(bucket, &me);

        auto& loc = get_loc();
        if (loc.is_task_thread && loc.curr_task) {
            me.waiter = loc.curr_task;
            me.needs_awake_check = true;
            me.awake_check = get_data(loc.curr_task).awake_check;

            loc.pending_timer = time_point;
            swapCtxUnlock(bucket.lock);

            if (get_loc().curr_task.has_wait_timed_out()) {
                bucket.lock.lock();
                remove_waiter(bucket, &me);
                return false;
            }
            guard.release();
            return true;
        } else {
            me.native_wake.store(0, std::memory_order_relaxed);

            guard.unlock();

            uint32_t expected = 0;
            while (me.native_wake.load(std::memory_order_acquire) == 0) {
                if (!native_futex_wait_until(&me.native_wake, expected, time_point)) {
                    guard.lock();
                    if (me.wait_address) {
                        remove_waiter(bucket, &me);
                        return false;
                    }
                    guard.unlock();

                    while (me.native_wake.load(std::memory_order_acquire) == 0)
                        native_futex_wait(&me.native_wake, 0);
                    return false;
                }
            }
            return true;
        }
    }

    void FT_API unlock_and_wait(void* address, bool (*check_callback)(void*), void* lock_address, void (*make_unlock_callback)(void*), bool (*is_unlocked_callback)(void*, bool)) {
        bucket_t& bucket = glob.futex_global.get_bucket(address);
        std::unique_lock guard(bucket.lock);
        make_unlock_callback(lock_address);

        if (check_callback(address))
            return;

        wait_node_t me;
        me.wait_address = address;
        me.next_wait_addr = lock_address;
        me.next_wait_addr_check_callback = is_unlocked_callback;
        me.type = node_type::unlock_and_wait;
        make_wait(bucket, &me);

        auto& loc = get_loc();
        if (loc.is_task_thread && loc.curr_task) {
            me.waiter = loc.curr_task;
            swapCtxUnlock(bucket.lock);
        } else {
            me.native_wake.store(0, std::memory_order_relaxed);
            guard.unlock();

            uint32_t expected = 0;
            while (me.native_wake.load(std::memory_order_acquire) == 0)
                native_futex_wait(&me.native_wake, expected);
        }
    }

    bool FT_API unlock_and_wait_until(void* address, bool (*check_callback)(void*), void* lock_address, void (*make_unlock_callback)(void*), bool (*is_unlocked_callback)(void*, bool), std::chrono::high_resolution_clock::time_point time_point) {
        if (time_point <= std::chrono::high_resolution_clock::now())
            return false;
        bucket_t& bucket = glob.futex_global.get_bucket(address);
        std::unique_lock guard(bucket.lock);
        make_unlock_callback(lock_address);

        if (check_callback(address))
            return true;

        wait_node_t me;
        me.wait_address = address;
        me.next_wait_addr = lock_address;
        me.next_wait_addr_check_callback = is_unlocked_callback;
        me.type = node_type::unlock_and_wait;
        make_wait(bucket, &me);

        auto& loc = get_loc();
        if (loc.is_task_thread && loc.curr_task) {
            me.waiter = loc.curr_task;
            me.needs_awake_check = true;
            me.awake_check = get_data(loc.curr_task).awake_check;

            loc.pending_timer = time_point;
            swapCtxUnlock(bucket.lock);

            if (get_loc().curr_task.has_wait_timed_out()) {
                bucket.lock.lock();
                remove_waiter(bucket, &me);
                return false;
            }
            guard.release();
            return true;
        } else {
            me.native_wake.store(0, std::memory_order_relaxed);

            guard.unlock();

            uint32_t expected = 0;
            while (me.native_wake.load(std::memory_order_acquire) == 0) {
                if (!native_futex_wait_until(&me.native_wake, expected, time_point)) {
                    guard.lock();
                    if (me.wait_address) {
                        remove_waiter(bucket, &me);
                        return false;
                    }
                    guard.unlock();

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
        if (time_point <= std::chrono::high_resolution_clock::now()) {
            get_data(task_obj).set_time_end(true);
            return true;
        }
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

    bool FT_API enter_unlock_and_wait(const task& task_obj, void* address, bool (*check_callback)(void*), void* lock_address, void (*make_unlock_callback)(void*), bool (*is_unlocked_callback)(void*, bool), enter_state& state) {
        bucket_t& bucket = glob.futex_global.get_bucket(address);
        std::unique_lock guard(bucket.lock);

        make_unlock_callback(lock_address);
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

    bool FT_API enter_unlock_and_wait_until(const task& task_obj, void* address, bool (*check_callback)(void*), void* lock_address, void (*make_unlock_callback)(void*), bool (*is_unlocked_callback)(void*, bool mark_request), enter_state& state, std::chrono::high_resolution_clock::time_point time_point) {
        if (time_point <= std::chrono::high_resolution_clock::now()) {
            get_data(task_obj).set_time_end(true);
            return true;
        }
        bucket_t& bucket = glob.futex_global.get_bucket(address);
        std::lock_guard guard(bucket.lock);

        make_unlock_callback(lock_address);
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

        if (check_callback(address))
            return true;

        wait_node_t* me = state.template use<wait_node_t>();
        me->wait_address = address;
        me->lock_callback = lock_callback;
        me->waiter = task_obj;
        me->type = node_type::enter_wait_and_lock;
        make_wait(bucket, me);
        return false;
    }

    bool FT_API enter_wait_on_address_lock_until(const task& task_obj, void* address, bool (*check_callback)(void*), void (*lock_callback)(void*, const task& task_obj), enter_state& state, std::chrono::high_resolution_clock::time_point time_point) {
        if (time_point <= std::chrono::high_resolution_clock::now()) {
            get_data(task_obj).set_time_end(true);
            return true;
        }
        bucket_t& bucket = glob.futex_global.get_bucket(address);
        std::unique_lock guard(bucket.lock);

        if (check_callback(address))
            return true;

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

    size_t FT_API wake_and_requeue_on_address(void* address, void (*pre_release)(void*, size_t), size_t process_count, size_t wake_count) {
        bucket_t& bucket = glob.futex_global.get_bucket(address);
        fast_task::unique_lock guard(bucket.lock);

        wait_node_t* curr = bucket.addresses;
        while (curr && curr->wait_address != address)
            curr = curr->next_addr;

        if (!curr) {
            pre_release(address, 0);
            return 0;
        }


        wait_node_t *to_wake_head, *to_wake_tail;

        pre_release(address, extract_waiters(bucket, curr, process_count, to_wake_head, to_wake_tail));

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

    bool FT_API has_waiters(void* address) {
        bucket_t& bucket = glob.futex_global.get_bucket(address);
        fast_task::lock_guard guard(bucket.lock);

        wait_node_t* curr = bucket.addresses;
        while (curr && curr->wait_address != address)
            curr = curr->next_addr;

        return curr != nullptr;
    }

    bool FT_API has_waiters_callback(void* address, void (*callback)(void* address, void* data, bool result), void* data) {
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
