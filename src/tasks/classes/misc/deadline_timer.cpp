
#include <list>
#include <unordered_set>

#include <fast_task/task.hpp>
#include <tasks/_internal.hpp>

namespace fast_task {
    struct deadline_timer::handle {
        std::atomic_size_t usage_count{1};
        mutex no_race;
        condition_variable wait_cv;
        std::atomic_size_t waiting_count{0};
        uint64_t wait_epoch = 0;
        fast_task::time_point time_point{};
        std::unordered_set<size_t> canceled_tasks;
        std::list<task> scheduled_tasks;
        std::list<task> sleeping_tasks;
        bool shutdown = false;

        static handle* create() {
            return new handle{};
        }

        handle* acquire() {
            usage_count.fetch_add(1, std::memory_order_relaxed);
            return this;
        }

        void release() {
            if (usage_count.fetch_sub(1, std::memory_order_acq_rel) == 1) {
                delete this;
            }
        }
    };

    template <class T>
    struct holder {
        T* res;

        holder(T* res) : res(res ? res->acquire() : nullptr) {}

        holder(const holder& copy) : res(copy.res ? copy.res->acquire() : nullptr) {}

        holder(holder&& mov) : res(mov.res) {
            mov.res = nullptr;
        }

        holder& operator=(holder&& mov) {
            if (this == &mov)
                return *this;
            if (res)
                res->release();
            res = mov.res;
            mov.res = nullptr;
            return *this;
        }

        holder& operator=(const holder& copy) {
            if (this == &copy)
                return *this;
            T* old = res;
            res = copy.res ? copy.res->acquire() : nullptr;
            if (old)
                old->release();
            return *this;
        }

        ~holder() {
            if (res)
                res->release();
        }

        T* operator->() {
            return res;
        }
    };

    deadline_timer::deadline_timer() : hh(handle::create()) {
        FT_DEBUG_ONLY(register_object(this));
    }

    deadline_timer::deadline_timer(fast_task::clock::duration dur) : deadline_timer() {
        expires_from_now(dur);
    }

    deadline_timer::deadline_timer(fast_task::time_point point) : deadline_timer() {
        expires_at(point);
    }

    deadline_timer::deadline_timer(deadline_timer&& mov) : hh(std::move(mov.hh)) {
        FT_DEBUG_ONLY(register_object(this));
        mov.hh = nullptr;
    }

    deadline_timer::~deadline_timer() {
        FT_DEBUG_ONLY(unregister_object(this));
        if (hh) {
            {
                fast_task::unique_lock lock(hh->no_race);
                hh->shutdown = true;
            }
            cancel();
            hh->release();
            hh = nullptr;
        }
    }

    size_t deadline_timer::cancel() {
        if (!hh)
            return 0;
        fast_task::unique_lock lock(hh->no_race);
        if (hh->shutdown || hh->time_point > fast_task::clock::now()) {
            size_t res = hh->scheduled_tasks.size() + hh->sleeping_tasks.size() + hh->waiting_count.load(std::memory_order_acquire);
            // cancel async_wait registrations
            for (auto& t : hh->scheduled_tasks)
                hh->canceled_tasks.insert(t.get_id());
            hh->scheduled_tasks.clear();
            // wake up tasks sleeping in enter_wait()
            for (auto& t : hh->sleeping_tasks) {
                hh->canceled_tasks.insert(t.get_id());
                bool should_transfer = false;
                {
                    fast_task::lock_guard task_guard(get_data(t));
                    if (!get_data(t).get_time_end() && !get_data(t).get_awaked()) {
                        get_data(t).set_awaked(true);
                        should_transfer = true;
                    }
                }
                if (should_transfer)
                    transfer_task(std::move(t));
            }
            hh->sleeping_tasks.clear();
            // wake up tasks and native threads sleeping in wait()
            ++hh->wait_epoch;
            hh->wait_cv.notify_all();
            return res;
        } else
            return 0;
    }

    bool deadline_timer::cancel_one() {
        if (!hh)
            return false;
        fast_task::unique_lock lock(hh->no_race);
        if (hh->shutdown || hh->time_point > fast_task::clock::now()) {
            if (hh->waiting_count.load(std::memory_order_acquire) > 0) {
                hh->wait_cv.notify_one();
                return true;
            }
            while (!hh->sleeping_tasks.empty()) {
                auto t = std::move(hh->sleeping_tasks.front());
                hh->sleeping_tasks.pop_front();
                hh->canceled_tasks.insert(t.get_id());
                bool should_transfer = false;
                {
                    fast_task::lock_guard task_guard(get_data(t));
                    if (!get_data(t).get_time_end() && !get_data(t).get_awaked()) {
                        get_data(t).set_awaked(true);
                        should_transfer = true;
                    }
                }
                if (should_transfer) {
                    transfer_task(std::move(t));
                    return true;
                }
            }
            if (!hh->scheduled_tasks.empty()) {
                hh->canceled_tasks.insert(hh->scheduled_tasks.front().get_id());
                hh->scheduled_tasks.pop_front();
                return true;
            }
        }
        return false;
    }

    void deadline_timer::async_wait(const task& t) {
        if (!hh)
            return;
        fast_task::unique_lock lock(hh->no_race);
        if (hh->shutdown)
            return;
        if (hh->time_point <= fast_task::clock::now()) {
            lock.unlock();
            scheduler::start(t);
        } else {
            auto timeout_time = hh->time_point;
            hh->scheduled_tasks.push_back(t);
            scheduler::schedule_until(
                task::create([hh = holder(hh), t, timeout_time]() mutable {
                    bool should_start = false;
                    {
                        fast_task::unique_lock lock(hh->no_race);
                        auto& st = hh->scheduled_tasks;
                        auto sit = std::find(st.begin(), st.end(), t);
                        if (sit != st.end())
                            st.erase(sit);
                        auto& ct = hh->canceled_tasks;
                        auto cit = ct.find(t.get_id());
                        if (cit == ct.end()) {
                            if (!hh->shutdown && hh->time_point == timeout_time)
                                should_start = true;
                        } else
                            ct.erase(cit);
                    }
                    if (should_start)
                        scheduler::start(t);
                }),
                timeout_time
            );
        }
    }

    //true if got timeout
    void deadline_timer::async_wait(std::function<void(status)>&& callback) {
        if (!hh)
            return;
        fast_task::unique_lock lock(hh->no_race);
        if (hh->shutdown) {
            lock.unlock();
            callback(status::shutdown);
            return;
        }
        if (hh->time_point <= fast_task::clock::now()) {
            lock.unlock();
            callback(status::timeouted);
            return;
        }
        auto timeout_time = hh->time_point;
        auto scheduled = task::create([hh = holder(hh), callback = std::move(callback), timeout_time]() mutable {
            status result = status::canceled;
            {
                fast_task::unique_lock lock(hh->no_race);
                auto curr_task = get_loc() ? get_loc()->curr_task : task{};
                if (curr_task) {
                    auto& st = hh->scheduled_tasks;
                    auto sit = std::find(st.begin(), st.end(), curr_task);
                    if (sit != st.end())
                        st.erase(sit);
                }
                auto& ct = hh->canceled_tasks;
                bool was_canceled = false;
                if (curr_task) {
                    auto cit = ct.find(curr_task.get_id());
                    if (cit != ct.end()) {
                        was_canceled = true;
                        ct.erase(cit);
                    }
                }
                if (hh->shutdown)
                    result = status::shutdown;
                else if (!was_canceled && hh->time_point == timeout_time)
                    result = status::timeouted;
                else
                    result = status::canceled;
            }
            callback(result);
        });
        hh->scheduled_tasks.push_back(scheduled);
        scheduler::schedule_until(std::move(scheduled), timeout_time);
    }

    //true if got timeout
    void deadline_timer::async_wait(const std::function<void(status)>& cc) {
        async_wait(std::function(cc));
    }

    size_t deadline_timer::expires_at(fast_task::time_point point) {
        if (!hh)
            return 0;
        fast_task::unique_lock lock(hh->no_race);
        hh->time_point = point;
        hh->canceled_tasks.clear();
        ++hh->wait_epoch;
        size_t count = hh->scheduled_tasks.size() + hh->sleeping_tasks.size() + hh->waiting_count.load(std::memory_order_acquire);
        hh->wait_cv.notify_all();
        return count;
    }

    deadline_timer::status deadline_timer::wait() {
        if (!hh)
            return status::shutdown;
        holder h(hh);
        fast_task::unique_lock lock(h->no_race);
        if (h->shutdown)
            return status::shutdown;
        auto timeout_time = h->time_point;
        if (timeout_time <= fast_task::clock::now())
            return status::timeouted;

        auto epoch = h->wait_epoch;
        h->waiting_count.fetch_add(1, std::memory_order_relaxed);
        struct waiting_guard {
            std::atomic_size_t& count;
            ~waiting_guard() {
                count.fetch_sub(1, std::memory_order_acq_rel);
            }
        } wguard{h->waiting_count};

        bool woken = h->wait_cv.wait_until(lock, timeout_time);
        if (h->shutdown)
            return status::shutdown;
        if (woken)
            return status::canceled;
        if (h->wait_epoch != epoch || h->time_point != timeout_time)
            return status::canceled;
        return status::timeouted;
    }

    deadline_timer::status deadline_timer::wait(fast_task::unique_lock<mutex_unify>& lock) {
        fast_task::relock_guard relock(lock);
        return wait();
    }

    deadline_timer::status deadline_timer::wait(std::unique_lock<mutex_unify>& lock) {
        fast_task::relock_guard relock(lock);
        return wait();
    }

    bool deadline_timer::timed_out() {
        if (!hh)
            return false;
        fast_task::unique_lock lock(hh->no_race);
        return hh->time_point <= fast_task::clock::now();
    }

    bool deadline_timer::enter_wait(const task& task, enter_state&, fast_task::time_point& out_time) {
        if (!hh)
            return true;
        fast_task::lock_guard lock(hh->no_race);
        out_time = hh->time_point;
        if (hh->shutdown || hh->time_point <= fast_task::clock::now()) {
            return true;
        } else {
            hh->sleeping_tasks.push_back(task);
            fast_task::makeTimeWait_extern(task, hh->time_point);
            return false;
        }
    }

    bool deadline_timer::enter_wait(mutex_unify& mut, const task& task, enter_state&, fast_task::time_point& out_time) {
        if (!hh)
            return true;
        fast_task::lock_guard lock(hh->no_race);
        out_time = hh->time_point;
        if (hh->shutdown || hh->time_point <= fast_task::clock::now()) {
            return true;
        } else {
            get_data(task).set_unlock(mut);
            hh->sleeping_tasks.push_back(task);
            fast_task::makeTimeWait_extern(task, hh->time_point);
            return false;
        }
    }

    deadline_timer::status deadline_timer::get_status(const task& task, fast_task::time_point timeout_time) {
        if (!hh)
            return status::shutdown;
        fast_task::lock_guard lock(hh->no_race);
        auto& st = hh->sleeping_tasks;
        auto sit = std::find(st.begin(), st.end(), task);
        if (sit != st.end())
            st.erase(sit);
        auto& ct = hh->canceled_tasks;
        auto cit = ct.find(task.get_id());
        bool was_canceled = false;
        if (cit != ct.end()) {
            was_canceled = true;
            ct.erase(cit);
        }
        if (hh->shutdown)
            return status::shutdown;
        if (!was_canceled && hh->time_point == timeout_time)
            return status::timeouted;
        return status::canceled;
    }
}