
#include <tasks.hpp>
#include <tasks/_internal.hpp>
#include <unordered_set>

namespace fast_task {

    struct deadline_timer::handle {
        task_mutex no_race;
        std::chrono::high_resolution_clock::time_point time_point;
        std::unordered_set<void*> canceled_tasks;
        std::list<void*> scheduled_tasks;
        bool shutdown = false;
    };

    deadline_timer::deadline_timer() : hh(std::make_shared<handle>()) {}

    deadline_timer::deadline_timer(std::chrono::high_resolution_clock::duration dur) : deadline_timer() {
        expires_from_now(dur);
    }

    deadline_timer::deadline_timer(std::chrono::high_resolution_clock::time_point point) : deadline_timer() {
        expires_at(point);
    }

    deadline_timer::deadline_timer(deadline_timer&& mov) : hh(std::move(mov.hh)) {}

    deadline_timer::~deadline_timer(){
        if (hh) {
            std::unique_lock lock(hh->no_race);
            hh->shutdown = true;
        }
        cancel();
    }

    size_t deadline_timer::cancel() {
        if (!hh)
            return 0;
        std::unique_lock lock(hh->no_race);
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
        std::unique_lock lock(hh->no_race);
        if (hh->time_point < std::chrono::high_resolution_clock::now() && !hh->scheduled_tasks.empty()) {
            hh->canceled_tasks.insert(hh->scheduled_tasks.front());
            hh->scheduled_tasks.pop_front();
            return true;
        } else
            return 0;
    }

    void deadline_timer::async_wait(const std::shared_ptr<task>& t) {
        if (!hh)
            return;
        std::unique_lock lock(hh->no_race);
        if (hh->time_point <= std::chrono::high_resolution_clock::now())
            task::start(t);
        else {
            hh->scheduled_tasks.push_back(t.get());
            task::schedule_until(
                std::make_shared<task>([hh = hh, t, timeout_time = hh->time_point]() mutable {
                    std::unique_lock lock(hh->no_race);
                    if (hh->canceled_tasks.find(t.get()) == hh->canceled_tasks.end()) {
                        if (hh->time_point == timeout_time)
                            task::start(t);
                    } else
                        hh->canceled_tasks.erase(t.get());
                }),
                hh->time_point
            );
        }
    }

    //true if got timeout
    void deadline_timer::async_wait(std::function<void(status)>&& callback) {
        if (!hh)
            return;
        std::unique_lock lock(hh->no_race);
        if (hh->time_point <= std::chrono::high_resolution_clock::now())
            callback(status::timeouted);
        else {
            task::schedule_until(
                std::make_shared<task>([hh = hh, callback = std::move(callback), timeout_time = hh->time_point]() mutable {
                    if (hh->shutdown){
                        callback(status::shutdown);
                        return;
                    }
                    bool timed_out;
                    {
                        std::unique_lock lock(hh->no_race);
                        timed_out = hh->canceled_tasks.find(loc.curr_task.get()) == hh->canceled_tasks.end();
                        if (timed_out)
                            timed_out = hh->time_point == timeout_time;

                        if (hh->shutdown) {//double check, but in lock
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
        std::unique_lock lock(hh->no_race);
        hh->time_point = std::chrono::high_resolution_clock::now() + dur;
        hh->canceled_tasks.clear();
        return hh->scheduled_tasks.size();
    }

    size_t deadline_timer::expires_at(std::chrono::high_resolution_clock::time_point point) {
        if (!hh)
            return 0;
        std::unique_lock lock(hh->no_race);
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
            std::unique_lock lock(hh->no_race);
            hh->scheduled_tasks.push_back(loc.curr_task.get());
            auto timeout_time = hh->time_point;
            lock.unlock();
            task::sleep_until(hh->time_point);
            lock.lock();
            if (hh->canceled_tasks.find(loc.curr_task.get()) == hh->canceled_tasks.end()) {
                if (hh->time_point == timeout_time)
                    return status::timeouted;
            } else
                hh->canceled_tasks.erase(loc.curr_task.get());
            return status::canceled;
        }
    }

    deadline_timer::status deadline_timer::wait(std::unique_lock<mutex_unify>& lock) {
        struct relock {
            std::unique_lock<mutex_unify>& lock;

            relock(std::unique_lock<mutex_unify>& lock) : lock(lock) {
                lock.unlock();
            };

            ~relock() {
                lock.lock();
            }
        } re_lock(lock);

        return wait();
    }
}