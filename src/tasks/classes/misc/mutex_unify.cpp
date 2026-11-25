// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <fast_task/task.hpp>
#include <tasks/_internal.hpp>

namespace fast_task {

    void mutex_unify::lock() {
        switch (type) {
        case mutex_unify_type::std_nmut:
            std_nmut->lock();
            break;
        case mutex_unify_type::std_ntimed:
            std_ntimed->lock();
            break;
        case mutex_unify_type::std_nrec:
            std_nrec->lock();
            break;
        case mutex_unify_type::nmut:
            nmut->lock();
            break;
        case mutex_unify_type::ntimed:
            ntimed->lock();
            break;
        case mutex_unify_type::nrec:
            nrec->lock();
            break;
        case mutex_unify_type::rwmut_r:
            rwmut->lock_shared();
            break;
        case mutex_unify_type::rwmut_w:
            rwmut->lock();
            break;
        case mutex_unify_type::umut:
            umut->lock();
            break;
        case mutex_unify_type::urmut:
            urmut->lock();
            break;
        case mutex_unify_type::urwmut_r:
            urwmut->read_lock();
            break;
        case mutex_unify_type::urwmut_w:
            urwmut->write_lock();
            break;
        case mutex_unify_type::mmut:
            mmut->lock();
            break;
        case mutex_unify_type::uspin:
            uspin->lock();
            break;
        case mutex_unify_type::sem:
            sem->lock();
            break;
        case mutex_unify_type::lim:
            lim->lock();
            break;
        case mutex_unify_type::task_obj:
            reinterpret_cast<task_object*>(nmut)->lock();
            break;
        default:
            break;
        }
    }

    bool mutex_unify::try_lock() {
        switch (type) {
        case mutex_unify_type::std_nmut:
            return std_nmut->try_lock();
        case mutex_unify_type::std_ntimed:
            return std_ntimed->try_lock();
        case mutex_unify_type::std_nrec:
            return std_nrec->try_lock();
        case mutex_unify_type::nmut:
            return nmut->try_lock();
        case mutex_unify_type::ntimed:
            return ntimed->try_lock();
        case mutex_unify_type::nrec:
            return nrec->try_lock();
        case mutex_unify_type::rwmut_r:
            return rwmut->try_lock_shared();
        case mutex_unify_type::rwmut_w:
            return rwmut->try_lock();
        case mutex_unify_type::umut:
            return umut->try_lock();
        case mutex_unify_type::urmut:
            return urmut->try_lock();
        case mutex_unify_type::urwmut_r:
            return urwmut->try_read_lock();
        case mutex_unify_type::urwmut_w:
            return urwmut->try_write_lock();
        case mutex_unify_type::mmut:
            return mmut->try_lock();
        case mutex_unify_type::uspin:
            return uspin->try_lock();
        case mutex_unify_type::sem:
            return sem->try_lock();
        case mutex_unify_type::lim:
            return lim->try_lock();
        case mutex_unify_type::task_obj: {
            auto* obj = reinterpret_cast<task_object*>(nmut);
            interrupt_unsafe_region::lock();
            uint16_t cur = obj->state.load(std::memory_order_relaxed);
            while ((cur & task_object::state_f::spin_lock_locked) == 0) {
                if (obj->state.compare_exchange_weak(
                        cur,
                        static_cast<uint16_t>(cur | task_object::state_f::spin_lock_locked),
                        std::memory_order_acquire,
                        std::memory_order_relaxed
                    ))
                    return true;
            }
            interrupt_unsafe_region::unlock();
            return false;
        }
        default:
            return false;
        }
    }

    bool mutex_unify::try_lock_until(fast_task::time_point time_point) {
        switch (type) {
        case mutex_unify_type::std_nmut:
            return std_nmut->try_lock();
        case mutex_unify_type::std_ntimed:
            return std_ntimed->try_lock_until(time_point);
        case mutex_unify_type::std_nrec:
            return std_nrec->try_lock();
        case mutex_unify_type::nmut:
            return nmut->try_lock();
        case mutex_unify_type::ntimed:
            return ntimed->try_lock_until(time_point);
        case mutex_unify_type::nrec:
            return nrec->try_lock();
        case mutex_unify_type::rwmut_r:
            return rwmut->try_lock_shared();
        case mutex_unify_type::rwmut_w:
            return rwmut->try_lock();
        case mutex_unify_type::umut:
            return umut->try_lock_until(time_point);
        case mutex_unify_type::urmut:
            return urmut->try_lock_until(time_point);
        case mutex_unify_type::urwmut_r:
            return urwmut->try_read_lock_until(time_point);
        case mutex_unify_type::urwmut_w:
            return urwmut->try_write_lock_until(time_point);
        case mutex_unify_type::mmut:
            return mmut->try_lock_until(time_point);
        case mutex_unify_type::uspin:
            while (!uspin->try_lock()) {
                if (fast_task::clock::now() >= time_point)
                    return false;
                cpu_relax();
            }
            return true;
        case mutex_unify_type::sem:
            return sem->try_lock_until(time_point);
        case mutex_unify_type::lim:
            return lim->try_lock_until(time_point);
        case mutex_unify_type::task_obj:
            return try_lock();
        default:
            return false;
        }
    }

    void mutex_unify::unlock() {
        switch (type) {
        case mutex_unify_type::std_nmut:
            std_nmut->unlock();
            break;
        case mutex_unify_type::std_ntimed:
            std_ntimed->unlock();
            break;
        case mutex_unify_type::std_nrec:
            std_nrec->unlock();
            break;
        case mutex_unify_type::nmut:
            nmut->unlock();
            break;
        case mutex_unify_type::ntimed:
            ntimed->unlock();
            break;
        case mutex_unify_type::nrec:
            nrec->unlock();
            break;
        case mutex_unify_type::rwmut_r:
            rwmut->unlock_shared();
            break;
        case mutex_unify_type::rwmut_w:
            rwmut->unlock();
            break;
        case mutex_unify_type::umut:
            umut->unlock();
            break;
        case mutex_unify_type::urmut:
            urmut->unlock();
            break;
        case mutex_unify_type::urwmut_r:
            urwmut->read_unlock();
            break;
        case mutex_unify_type::urwmut_w:
            urwmut->write_unlock();
            break;
        case mutex_unify_type::mmut:
            mmut->unlock();
            break;
        case mutex_unify_type::uspin:
            uspin->unlock();
            break;
        case mutex_unify_type::sem:
            sem->release();
            break;
        case mutex_unify_type::lim:
            lim->unlock();
            break;
        case mutex_unify_type::task_obj:
            reinterpret_cast<task_object*>(nmut)->unlock();
            break;
        default:
            break;
        }
    }

    mutex_unify::mutex_unify() {
        std_nmut = nullptr;
        type = mutex_unify_type::nothing;
    }

    mutex_unify::mutex_unify(const mutex_unify& mut) {
        type = mut.type;
        nmut = mut.nmut;
    }

    mutex_unify::mutex_unify(std::mutex& smut) {
        type = mutex_unify_type::std_nmut;
        std_nmut = std::addressof(smut);
    }

    mutex_unify::mutex_unify(std::timed_mutex& smut) {
        type = mutex_unify_type::std_ntimed;
        std_ntimed = std::addressof(smut);
    }

    mutex_unify::mutex_unify(std::recursive_mutex& smut) {
        type = mutex_unify_type::std_nrec;
        std_nrec = std::addressof(smut);
    }

    mutex_unify::mutex_unify(fast_task::native::mutex& smut) {
        type = mutex_unify_type::nmut;
        nmut = std::addressof(smut);
    }

    mutex_unify::mutex_unify(fast_task::native::timed_mutex& smut) {
        type = mutex_unify_type::ntimed;
        ntimed = std::addressof(smut);
    }

    mutex_unify::mutex_unify(fast_task::native::rw_mutex& smut, bool write_read) {
        type = write_read ? mutex_unify_type::rwmut_w : mutex_unify_type::rwmut_r;
        rwmut = std::addressof(smut);
    }

    mutex_unify::mutex_unify(fast_task::native::recursive_mutex& smut) {
        type = mutex_unify_type::nrec;
        nrec = std::addressof(smut);
    }

    mutex_unify::mutex_unify(fast_task::native::spin_lock& spin) {
        type = mutex_unify_type::uspin;
        uspin = std::addressof(spin);
    }

    mutex_unify::mutex_unify(mutex& smut) {
        type = mutex_unify_type::umut;
        umut = std::addressof(smut);
    }

    mutex_unify::mutex_unify(rw_mutex& smut, bool write_read) {
        type = write_read ? mutex_unify_type::urwmut_w : mutex_unify_type::urwmut_r;
        urwmut = std::addressof(smut);
    }

    mutex_unify::mutex_unify(recursive_mutex& smut) {
        type = mutex_unify_type::urmut;
        urmut = std::addressof(smut);
    }

    mutex_unify::mutex_unify(multiply_mutex& mmut)
        : mmut(&mmut) {
        type = mutex_unify_type::mmut;
    }

    mutex_unify::mutex_unify(semaphore& sem)
        : sem(&sem) {
        type = mutex_unify_type::sem;
    }

    mutex_unify::mutex_unify(limiter& lim)
        : lim(&lim) {
        type = mutex_unify_type::lim;
    }

    mutex_unify::mutex_unify(std::nullptr_t) {
        std_nmut = nullptr;
        type = mutex_unify_type::nothing;
    }

    mutex_unify::~mutex_unify() {
        type = mutex_unify_type::nothing;
    }

    mutex_unify& mutex_unify::operator=(const mutex_unify& mut) {
        type = mut.type;
        nmut = mut.nmut;
        return *this;
    }

    mutex_unify& mutex_unify::operator=(std::mutex& smut) {
        type = mutex_unify_type::std_nmut;
        std_nmut = std::addressof(smut);
        return *this;
    }

    mutex_unify& mutex_unify::operator=(std::timed_mutex& smut) {
        type = mutex_unify_type::std_ntimed;
        std_ntimed = std::addressof(smut);
        return *this;
    }

    mutex_unify& mutex_unify::operator=(std::recursive_mutex& smut) {
        type = mutex_unify_type::std_nrec;
        std_nrec = std::addressof(smut);
        return *this;
    }

    mutex_unify& mutex_unify::operator=(fast_task::native::mutex& smut) {
        type = mutex_unify_type::nmut;
        nmut = std::addressof(smut);
        return *this;
    }

    mutex_unify& mutex_unify::operator=(fast_task::native::timed_mutex& smut) {
        type = mutex_unify_type::ntimed;
        ntimed = std::addressof(smut);
        return *this;
    }

    mutex_unify& mutex_unify::operator=(fast_task::native::recursive_mutex& smut) {
        type = mutex_unify_type::nrec;
        nrec = std::addressof(smut);
        return *this;
    }

    mutex_unify& mutex_unify::operator=(fast_task::native::spin_lock& spin) {
        type = mutex_unify_type::uspin;
        uspin = std::addressof(spin);
        return *this;
    }

    mutex_unify& mutex_unify::operator=(mutex& smut) {
        type = mutex_unify_type::umut;
        umut = std::addressof(smut);
        return *this;
    }

    mutex_unify& mutex_unify::operator=(recursive_mutex& smut) {
        type = mutex_unify_type::urmut;
        urmut = std::addressof(smut);
        return *this;
    }

    mutex_unify& mutex_unify::operator=(multiply_mutex& smut) {
        type = mutex_unify_type::mmut;
        mmut = std::addressof(smut);
        return *this;
    }

    mutex_unify& mutex_unify::operator=(semaphore& _sem) {
        type = mutex_unify_type::sem;
        this->sem = std::addressof(_sem);
        return *this;
    }

    mutex_unify& mutex_unify::operator=(limiter& _lim) {
        type = mutex_unify_type::lim;
        this->lim = std::addressof(_lim);
        return *this;
    }

    mutex_unify& mutex_unify::operator=(std::nullptr_t) {
        std_nmut = nullptr;
        type = mutex_unify_type::nothing;
        return *this;
    }

    bool mutex_unify::operator==(const mutex_unify& mut) {
        return nmut == mut.nmut && type == mut.type;
    }

    bool mutex_unify::operator==(std::mutex& smut) {
        return type == mutex_unify_type::std_nmut && std_nmut == std::addressof(smut);
    }

    bool mutex_unify::operator==(std::timed_mutex& smut) {
        return type == mutex_unify_type::std_ntimed && std_ntimed == std::addressof(smut);
    }

    bool mutex_unify::operator==(std::recursive_mutex& smut) {
        return type == mutex_unify_type::std_nrec && std_nrec == std::addressof(smut);
    }

    bool mutex_unify::operator==(fast_task::native::mutex& smut) {
        return type == mutex_unify_type::nmut && nmut == std::addressof(smut);
    }

    bool mutex_unify::operator==(fast_task::native::timed_mutex& smut) {
        return type == mutex_unify_type::ntimed && ntimed == std::addressof(smut);
    }

    bool mutex_unify::operator==(fast_task::native::rw_mutex& smut) {
        return (type == mutex_unify_type::rwmut_r || type == mutex_unify_type::rwmut_w) && rwmut == std::addressof(smut);
    }

    bool mutex_unify::operator==(fast_task::native::recursive_mutex& smut) {
        return type == mutex_unify_type::nrec && nrec == std::addressof(smut);
    }

    bool mutex_unify::operator==(fast_task::native::spin_lock& spin) {
        return type == mutex_unify_type::uspin && uspin == std::addressof(spin);
    }

    bool mutex_unify::operator==(mutex& smut) {
        return type == mutex_unify_type::umut && umut == std::addressof(smut);
    }

    bool mutex_unify::operator==(rw_mutex& smut) {
        return (type == mutex_unify_type::urwmut_r || type == mutex_unify_type::urwmut_w) && urwmut == std::addressof(smut);
    }

    bool mutex_unify::operator==(recursive_mutex& smut) {
        return type == mutex_unify_type::urmut && urmut == std::addressof(smut);
    }

    bool mutex_unify::operator==(class multiply_mutex& mut) {
        return type == mutex_unify_type::mmut && mmut == std::addressof(mut);
    }

    bool mutex_unify::operator==(semaphore& _sem) {
        return type == mutex_unify_type::sem && sem == std::addressof(_sem);
    }

    bool mutex_unify::operator==(limiter& _lim) {
        return type == mutex_unify_type::lim && lim == std::addressof(_lim);
    }

    bool mutex_unify::operator==(std::nullptr_t) {
        return type == mutex_unify_type::nothing || std_nmut == nullptr;
    }

    void mutex_unify::relock_start() {
        unlock();
    }

    void mutex_unify::relock_end() {
        lock();
    }

    mutex_unify::operator bool() {
        return type != mutex_unify_type::nothing;
    }

    bool mutex_unify::enter_wait(const task& task, enter_state& state) {
        switch (type) {
        case mutex_unify_type::std_nmut:
        case mutex_unify_type::std_ntimed:
        case mutex_unify_type::std_nrec:
        case mutex_unify_type::nmut:
        case mutex_unify_type::ntimed:
        case mutex_unify_type::nrec:
        case mutex_unify_type::rwmut_r:
        case mutex_unify_type::rwmut_w:
        case mutex_unify_type::task_obj:
            lock();
            return true;
        case mutex_unify_type::uspin:
            uspin->lock();
            return true;
        case mutex_unify_type::umut:
            return umut->enter_wait(task, state);
        case mutex_unify_type::urmut:
            return urmut->enter_wait(task, state);
        case mutex_unify_type::urwmut_r:
            return urwmut->enter_read_wait(task, state);
        case mutex_unify_type::urwmut_w:
            return urwmut->enter_write_wait(task, state);
        case mutex_unify_type::mmut:
            return mmut->enter_wait(task, state);
        case mutex_unify_type::sem:
            return sem->enter_wait(task, state);
        case mutex_unify_type::lim:
            return lim->enter_wait(task, state);
        default:
            return true;
        }
    }

    bool mutex_unify::enter_wait_until(const task& task, enter_state& state, fast_task::time_point time_point) {
        switch (type) {
        case mutex_unify_type::std_nmut:
        case mutex_unify_type::std_nrec:
        case mutex_unify_type::nmut:
        case mutex_unify_type::nrec:
        case mutex_unify_type::rwmut_r:
        case mutex_unify_type::rwmut_w:
        case mutex_unify_type::task_obj:
            lock();
            return true;
        case mutex_unify_type::std_ntimed:
            if (!std_ntimed->try_lock_until(time_point))
                get_data(task).set_time_end(true);
            else
                get_data(task).set_time_end(false);
            return true;
        case mutex_unify_type::ntimed:
            if (!ntimed->try_lock_until(time_point))
                get_data(task).set_time_end(true);
            else
                get_data(task).set_time_end(false);
            return true;
        case mutex_unify_type::uspin:
            uspin->lock();
            return true;
        case mutex_unify_type::umut:
            return umut->enter_wait_until(task, state, time_point);
        case mutex_unify_type::urmut:
            return urmut->enter_wait_until(task, state, time_point);
        case mutex_unify_type::urwmut_r:
            return urwmut->enter_read_wait_until(task, state, time_point);
        case mutex_unify_type::urwmut_w:
            return urwmut->enter_write_wait_until(task, state, time_point);
        case mutex_unify_type::mmut:
            return mmut->enter_wait_until(task, state, time_point);
        case mutex_unify_type::sem:
            return sem->enter_wait_until(task, state, time_point);
        case mutex_unify_type::lim:
            return lim->enter_wait_until(task, state, time_point);
        default:
            return true;
        }
    }

    void mutex_unify::donate_ownership(fast_task::task* target_owner) {
        switch (type) {
        case mutex_unify_type::umut:
            umut->transfer_ownership(target_owner->get_id());
            break;
        case mutex_unify_type::urmut:
            urmut->mut.transfer_ownership(target_owner->get_id());
            break;
        case mutex_unify_type::urwmut_r:
            break;
        case mutex_unify_type::urwmut_w:
            urwmut->values.writer_owner.store(target_owner->get_id(), std::memory_order_release);
            break;
        case mutex_unify_type::mmut:
            mmut->donate_ownership(target_owner);
            break;
        case mutex_unify_type::lim: {
            if (!target_owner)
                break;
            size_t cur_id = this_task::get_id();
            size_t target_id = target_owner->get_id();
            if (cur_id == target_id)
                break;
            fast_task::lock_guard guard(lim->values.lock_check_lock);
            size_t idx = lim->values.lock_check.find(cur_id);
            if (idx != limiter::holder_set::npos)
                lim->values.lock_check.erase(idx);
            if (lim->values.lock_check.find(target_id) == limiter::holder_set::npos)
                lim->values.lock_check.push(target_id);
            break;
        }
        default:
            break;
        }
    }

}
