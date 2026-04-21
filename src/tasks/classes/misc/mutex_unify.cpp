// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <task.hpp>
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
        case mutex_unify_type::uspin:
            return uspin->try_lock();
        default:
            return false;
        }
    }

    bool mutex_unify::try_lock_until(std::chrono::high_resolution_clock::time_point time_point) {
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
        default:
            break;
        }
    }

    mutex_unify::mutex_unify() {
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

    mutex_unify::mutex_unify(fast_task::mutex& smut) {
        type = mutex_unify_type::nmut;
        nmut = std::addressof(smut);
    }

    mutex_unify::mutex_unify(fast_task::timed_mutex& smut) {
        type = mutex_unify_type::ntimed;
        ntimed = std::addressof(smut);
    }

    mutex_unify::mutex_unify(fast_task::rw_mutex& smut, bool write_read) {
        type = write_read ? mutex_unify_type::rwmut_w : mutex_unify_type::rwmut_r;
        rwmut = std::addressof(smut);
    }

    mutex_unify::mutex_unify(fast_task::recursive_mutex& smut) {
        type = mutex_unify_type::nrec;
        nrec = std::addressof(smut);
    }

    mutex_unify::mutex_unify(fast_task::spin_lock& spin) {
        type = mutex_unify_type::uspin;
        uspin = std::addressof(spin);
    }

    mutex_unify::mutex_unify(task_mutex& smut) {
        type = mutex_unify_type::umut;
        umut = std::addressof(smut);
    }

    mutex_unify::mutex_unify(task_rw_mutex& smut, bool write_read) {
        type = write_read ? mutex_unify_type::urwmut_w : mutex_unify_type::urwmut_r;
        urwmut = std::addressof(smut);
    }

    mutex_unify::mutex_unify(task_recursive_mutex& smut) {
        type = mutex_unify_type::urmut;
        urmut = std::addressof(smut);
    }

    mutex_unify::mutex_unify(multiply_mutex& mmut)
        : mmut(&mmut) {
        type = mutex_unify_type::mmut;
    }

    mutex_unify::mutex_unify(task_semaphore& sem)
        : sem(&sem) {
        type = mutex_unify_type::sem;
    }

    mutex_unify::mutex_unify(task_limiter& lim)
        : lim(&lim) {
        type = mutex_unify_type::lim;
    }

    mutex_unify::mutex_unify(std::nullptr_t) {
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

    mutex_unify& mutex_unify::operator=(fast_task::mutex& smut) {
        type = mutex_unify_type::nmut;
        nmut = std::addressof(smut);
        return *this;
    }

    mutex_unify& mutex_unify::operator=(fast_task::timed_mutex& smut) {
        type = mutex_unify_type::ntimed;
        ntimed = std::addressof(smut);
        return *this;
    }

    mutex_unify& mutex_unify::operator=(fast_task::recursive_mutex& smut) {
        type = mutex_unify_type::nrec;
        nrec = std::addressof(smut);
        return *this;
    }

    mutex_unify& mutex_unify::operator=(fast_task::spin_lock& spin) {
        type = mutex_unify_type::uspin;
        uspin = std::addressof(spin);
        return *this;
    }

    mutex_unify& mutex_unify::operator=(task_mutex& smut) {
        type = mutex_unify_type::umut;
        umut = std::addressof(smut);
        return *this;
    }

    mutex_unify& mutex_unify::operator=(task_recursive_mutex& smut) {
        type = mutex_unify_type::urmut;
        urmut = std::addressof(smut);
        return *this;
    }

    mutex_unify& mutex_unify::operator=(multiply_mutex& smut) {
        type = mutex_unify_type::mmut;
        mmut = std::addressof(smut);
        return *this;
    }

    mutex_unify& mutex_unify::operator=(task_semaphore& _sem) {
        type = mutex_unify_type::sem;
        this->sem = std::addressof(_sem);
        return *this;
    }

    mutex_unify& mutex_unify::operator=(task_limiter& _lim) {
        type = mutex_unify_type::lim;
        this->lim = std::addressof(_lim);
        return *this;
    }

    mutex_unify& mutex_unify::operator=(std::nullptr_t) {
        type = mutex_unify_type::nothing;
        return *this;
    }

    bool mutex_unify::operator==(const mutex_unify& mut) {
        return nmut == mut.nmut && type == mut.type;
    }

    bool mutex_unify::operator==(std::mutex& smut) {
        return (void*)nmut == (void*)std::addressof(smut);
    }

    bool mutex_unify::operator==(std::timed_mutex& smut) {
        return (void*)nmut == (void*)std::addressof(smut);
    }

    bool mutex_unify::operator==(std::recursive_mutex& smut) {
        return (void*)nmut == (void*)std::addressof(smut);
    }

    bool mutex_unify::operator==(fast_task::mutex& smut) {
        return (void*)nmut == (void*)std::addressof(smut);
    }

    bool mutex_unify::operator==(fast_task::timed_mutex& smut) {
        return (void*)nmut == (void*)std::addressof(smut);
    }

    bool mutex_unify::operator==(fast_task::recursive_mutex& smut) {
        return (void*)nmut == (void*)std::addressof(smut);
    }

    bool mutex_unify::operator==(fast_task::spin_lock& spin) {
        return (void*)nmut == (void*)std::addressof(spin);
    }

    bool mutex_unify::operator==(task_mutex& smut) {
        return (void*)nmut == (void*)std::addressof(smut);
    }

    bool mutex_unify::operator==(task_rw_mutex& smut) {
        return (void*)nmut == (void*)std::addressof(smut);
    }

    bool mutex_unify::operator==(task_recursive_mutex& smut) {
        return (void*)nmut == (void*)std::addressof(smut);
    }

    bool mutex_unify::operator==(class multiply_mutex& mut) {
        return (void*)nmut == (void*)std::addressof(mut);
    }

    bool mutex_unify::operator==(task_semaphore& _sem) {
        return (void*)nmut == (void*)std::addressof(_sem);
    }

    bool mutex_unify::operator==(task_limiter& _lim) {
        return (void*)nmut == (void*)std::addressof(_lim);
    }

    bool mutex_unify::operator==(std::nullptr_t) {
        return (void*)nmut == nullptr;
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

    bool mutex_unify::enter_wait(const std::shared_ptr<task>& task) {
        switch (type) {
        case mutex_unify_type::std_nmut:
        case mutex_unify_type::std_ntimed:
        case mutex_unify_type::std_nrec:
        case mutex_unify_type::nmut:
        case mutex_unify_type::ntimed:
        case mutex_unify_type::nrec:
        case mutex_unify_type::rwmut_r:
        case mutex_unify_type::rwmut_w:
            lock();
            return true;
        case mutex_unify_type::umut:
            return umut->enter_wait(task);
        case mutex_unify_type::urmut:
            return urmut->enter_wait(task);
        case mutex_unify_type::urwmut_r:
            return urwmut->enter_read_wait(task);
        case mutex_unify_type::urwmut_w:
            return urwmut->enter_write_wait(task);
        case mutex_unify_type::mmut:
            return mmut->enter_wait(task);
        case mutex_unify_type::sem:
            return sem->enter_wait(task);
        case mutex_unify_type::lim:
            return lim->enter_wait(task);
        default:
            return true;
        }
    }

    bool mutex_unify::enter_wait_until(const std::shared_ptr<task>& task, std::chrono::high_resolution_clock::time_point time_point) {
        switch (type) {
        case mutex_unify_type::std_nmut:
        case mutex_unify_type::std_ntimed:
        case mutex_unify_type::std_nrec:
        case mutex_unify_type::nmut:
        case mutex_unify_type::ntimed:
        case mutex_unify_type::nrec:
        case mutex_unify_type::rwmut_r:
        case mutex_unify_type::rwmut_w:
            lock();
            return true;
        case mutex_unify_type::umut:
            return umut->enter_wait_until(task, time_point);
        case mutex_unify_type::urmut:
            return urmut->enter_wait_until(task, time_point);
        case mutex_unify_type::urwmut_r:
            return urwmut->enter_read_wait_until(task, time_point);
        case mutex_unify_type::urwmut_w:
            return urwmut->enter_write_wait_until(task, time_point);
        case mutex_unify_type::mmut:
            return mmut->enter_wait_until(task, time_point);
        case mutex_unify_type::sem:
            return sem->enter_wait_until(task, time_point);
        case mutex_unify_type::lim:
            return lim->enter_wait_until(task, time_point);
        default:
            return true;
        }
    }

    void mutex_unify::donate_ownership(fast_task::task* target_owner) {
        switch (type) {
        case mutex_unify_type::umut:
            umut->values.current_task = target_owner;
            break;
        case mutex_unify_type::urmut:
            urmut->mutex.values.current_task = target_owner;
            break;
        case mutex_unify_type::urwmut_r:
            urwmut->values.readers.remove(loc.curr_task.get());
            urwmut->values.readers.push_back(target_owner);
            break;
        case mutex_unify_type::urwmut_w:
            urwmut->values.current_writer_task = target_owner;
            break;
        case mutex_unify_type::mmut:
            mmut->donate_ownership(target_owner);
            break;
        default:
            break;
        }
    }
}
