
#include <task.hpp>
#include <tasks/_internal.hpp>

namespace fast_task {
    template <class T>
    struct holder {
        T* res;

        holder(T* res) : res(res->acquire()) {}

        ~holder() {
            res->release();
        }

        T* operator->() {
            return res;
        }
    };

    deadline_timer::deadline_timer() : hh(handle::create()) {
        FT_DEBUG_ONLY(register_object(this));
    }

    deadline_timer::deadline_timer(std::chrono::high_resolution_clock::duration dur) : deadline_timer() {
        FT_DEBUG_ONLY(register_object(this));
        expires_from_now(dur);
    }

    deadline_timer::deadline_timer(std::chrono::high_resolution_clock::time_point point) : deadline_timer() {
        FT_DEBUG_ONLY(register_object(this));
        expires_at(point);
    }

    deadline_timer::deadline_timer(deadline_timer&& mov) : hh(std::move(mov.hh)) {
        FT_DEBUG_ONLY(register_object(this));
        mov.hh = nullptr;
    }

    deadline_timer::~deadline_timer() {
        FT_DEBUG_ONLY(unregister_object(this));
        if (hh) {
            fast_task::unique_lock lock(hh->no_race);
            hh->shutdown = true;
        }
        cancel();
    }

    size_t deadline_timer::cancel() {
        if (!hh)
            return 0;
        fast_task::unique_lock lock(hh->no_race);
        if (hh->time_point < std::chrono::high_resolution_clock::now()) {
            hh->time_point = std::chrono::high_resolution_clock::time_point();
            size_t res = hh->scheduled_tasks.size();
            hh->scheduled_tasks.clear();
            hh->canceled_tasks.clear();
            return res;
        } else
            return 0;
    }

    bool deadline_timer::cancel_one() {
        if (!hh)
            return 0;
        fast_task::unique_lock lock(hh->no_race);
        auto& st = hh->scheduled_tasks;
        if (hh->time_point < std::chrono::high_resolution_clock::now() && !st.empty()) {
            hh->canceled_tasks.insert(st.front());
            st.pop_front();
            return true;
        } else
            return 0;
    }

    void deadline_timer::async_wait(const std::shared_ptr<task>& t) {
        if (!hh)
            return;
        fast_task::unique_lock lock(hh->no_race);
        if (hh->time_point <= std::chrono::high_resolution_clock::now())
            scheduler::start(t);
        else {
            hh->scheduled_tasks.push_back(t.get());
            scheduler::schedule_until(
                std::make_shared<task>([hh = holder(hh), t, timeout_time = hh->time_point]() mutable {
                    fast_task::unique_lock lock(hh->no_race);
                    auto& ct = hh->canceled_tasks;
                    if (ct.find(t.get()) == ct.end()) {
                        if (hh->time_point == timeout_time)
                            scheduler::start(t);
                    } else
                        ct.erase(t.get());
                }),
                hh->time_point
            );
        }
    }

    //true if got timeout
    void deadline_timer::async_wait(std::function<void(status)>&& callback) {
        if (!hh)
            return;
        fast_task::unique_lock lock(hh->no_race);
        if (hh->time_point <= std::chrono::high_resolution_clock::now())
            callback(status::timeouted);
        else {
            scheduler::schedule_until(
                std::make_shared<task>([hh = holder(hh), callback = std::move(callback), timeout_time = hh->time_point]() mutable {
                    if (hh->shutdown) {
                        callback(status::shutdown);
                        return;
                    }
                    bool timed_out;
                    {
                        fast_task::unique_lock lock(hh->no_race);
                        timed_out = hh->canceled_tasks.find(loc.curr_task.get()) == hh->canceled_tasks.end();
                        if (timed_out)
                            timed_out = hh->time_point == timeout_time;

                        if (hh->shutdown) { //double check, but in lock
                            callback(status::shutdown);
                            return;
                        }
                    }
                    callback(timed_out ? status::timeouted : status::canceled);
                }),
                hh->time_point
            );
        }
    }

    //true if got timeout
    void deadline_timer::async_wait(const std::function<void(status)>& cc) {
        async_wait(std::function(cc));
    }

    size_t deadline_timer::expires_from_now(std::chrono::high_resolution_clock::duration dur) {
        if (!hh)
            return 0;
        fast_task::unique_lock lock(hh->no_race);
        hh->time_point = std::chrono::high_resolution_clock::now() + dur;
        hh->canceled_tasks.clear();
        return hh->scheduled_tasks.size();
    }

    size_t deadline_timer::expires_at(std::chrono::high_resolution_clock::time_point point) {
        if (!hh)
            return 0;
        fast_task::unique_lock lock(hh->no_race);
        hh->time_point = point;
        hh->canceled_tasks.clear();
        return hh->scheduled_tasks.size();
    }

    deadline_timer::status deadline_timer::wait() {
        if (!hh)
            return status::shutdown;
        if (hh->time_point <= std::chrono::high_resolution_clock::now())
            return status::timeouted;
        else {
            fast_task::unique_lock lock(hh->no_race);
            hh->scheduled_tasks.push_back(loc.curr_task.get());
            auto timeout_time = hh->time_point;
            lock.unlock();
            this_task::sleep_until(hh->time_point);
            lock.lock();
            auto& ct = hh->canceled_tasks;
            if (ct.find(loc.curr_task.get()) == ct.end()) {
                if (hh->time_point == timeout_time)
                    return status::timeouted;
            } else
                ct.erase(loc.curr_task.get());
            return status::canceled;
        }
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
        return hh->time_point <= std::chrono::high_resolution_clock::now();
    }
}