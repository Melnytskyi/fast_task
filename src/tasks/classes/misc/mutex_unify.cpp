// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <tasks.hpp>

namespace fast_task {

    void mutex_unify::lock() {
        switch (type) {
        case mutex_unify_type::nmut:
            nmut->lock();
            break;
        case mutex_unify_type::ntimed:
            ntimed->lock();
            break;
        case mutex_unify_type::nrec:
            nrec->lock();
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
        default:
            break;
        }
    }

    bool mutex_unify::try_lock() {
        switch (type) {
        case mutex_unify_type::nmut:
            return nmut->try_lock();
        case mutex_unify_type::ntimed:
            return ntimed->try_lock();
        case mutex_unify_type::nrec:
            return nrec->try_lock();
        case mutex_unify_type::umut:
            return umut->try_lock();
        case mutex_unify_type::urmut:
            return urmut->try_lock();
        case mutex_unify_type::urwmut_r:
            return urwmut->try_read_lock();
        case mutex_unify_type::urwmut_w:
            return urwmut->try_write_lock();
        default:
            return false;
        }
    }

    bool mutex_unify::try_lock_for(size_t milliseconds) {
        switch (type) {
        case mutex_unify_type::noting:
            return false;
        case mutex_unify_type::ntimed:
            return ntimed->try_lock_for(std::chrono::milliseconds(milliseconds));
        case mutex_unify_type::nrec:
            return nrec->try_lock();
        case mutex_unify_type::umut:
            return umut->try_lock_for(milliseconds);
        case mutex_unify_type::urmut:
            return urmut->try_lock_for(milliseconds);
        case mutex_unify_type::urwmut_r:
            return urwmut->try_read_lock_for(milliseconds);
        case mutex_unify_type::urwmut_w:
            return urwmut->try_write_lock_for(milliseconds);
        case mutex_unify_type::mmut:
            return mmut->try_lock_for(milliseconds);
        default:
            return false;
        }
    }

    bool mutex_unify::try_lock_until(std::chrono::high_resolution_clock::time_point time_point) {
        switch (type) {
        case mutex_unify_type::noting:
            return false;
        case mutex_unify_type::ntimed:
            return ntimed->try_lock_until(time_point);
        case mutex_unify_type::nrec:
            return nrec->try_lock();
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
        case mutex_unify_type::nmut:
            nmut->unlock();
            break;
        case mutex_unify_type::ntimed:
            ntimed->unlock();
            break;
        case mutex_unify_type::nrec:
            nrec->unlock();
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
        default:
            break;
        }
    }

    mutex_unify::mutex_unify() {
        type = mutex_unify_type::noting;
    }

    mutex_unify::mutex_unify(const mutex_unify& mut) {
        type = mut.type;
        nmut = mut.nmut;
    }

    mutex_unify::mutex_unify(std::mutex& smut) {
        type = mutex_unify_type::nmut;
        nmut = std::addressof(smut);
    }

    mutex_unify::mutex_unify(std::timed_mutex& smut) {
        type = mutex_unify_type::ntimed;
        ntimed = std::addressof(smut);
    }

    mutex_unify::mutex_unify(std::recursive_mutex& smut) {
        type = mutex_unify_type::nrec;
        nrec = std::addressof(smut);
    }

    mutex_unify::mutex_unify(task_mutex& smut) {
        type = mutex_unify_type::umut;
        umut = std::addressof(smut);
    }

    mutex_unify::mutex_unify(task_rw_mutex& smut, bool read_write) {
        type = read_write ? mutex_unify_type::urwmut_w : mutex_unify_type::urwmut_r;
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

    mutex_unify::mutex_unify(nullptr_t) {
        type = mutex_unify_type::noting;
    }

    mutex_unify::~mutex_unify() {
        type = mutex_unify_type::noting;
    }

    mutex_unify& mutex_unify::operator=(const mutex_unify& mut) {
        type = mut.type;
        nmut = mut.nmut;
        return *this;
    }

    mutex_unify& mutex_unify::operator=(std::mutex& smut) {
        type = mutex_unify_type::nmut;
        nmut = std::addressof(smut);
        return *this;
    }

    mutex_unify& mutex_unify::operator=(std::timed_mutex& smut) {
        type = mutex_unify_type::ntimed;
        ntimed = std::addressof(smut);
        return *this;
    }

    mutex_unify& mutex_unify::operator=(std::recursive_mutex& smut) {
        type = mutex_unify_type::nrec;
        nrec = std::addressof(smut);
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

    mutex_unify& mutex_unify::operator=(nullptr_t) {
        type = mutex_unify_type::noting;
        return *this;
    }

    void mutex_unify::relock_start() {
        unlock();
    }

    void mutex_unify::relock_end() {
        lock();
    }

    mutex_unify::operator bool() {
        return type != mutex_unify_type::noting;
    }
}
