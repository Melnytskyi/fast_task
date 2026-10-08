#ifndef INCLUDE_SHARED_PRIMITIVES
#define INCLUDE_SHARED_PRIMITIVES
#include <stdexcept>
#include <utility>

namespace fast_task {
    struct adopt_lock_t {};

    struct defer_lock_t {};

    struct defer_unlock_t {};

    constexpr adopt_lock_t adopt_lock{};
    constexpr defer_lock_t defer_lock{};
    constexpr defer_unlock_t defer_unlock{};

    template <class Mutex>
    class lock_guard {
        Mutex& _mtx;

    public:
        lock_guard(Mutex& mtx)
            : _mtx(mtx) {
            _mtx.lock();
        }

        lock_guard(Mutex& mtx, adopt_lock_t)
            : _mtx(mtx) {}

        lock_guard(Mutex& mtx, defer_lock_t)
            : _mtx(mtx) {}

        lock_guard(const lock_guard&) = delete;
        lock_guard(lock_guard&&) = delete;
        lock_guard& operator=(const lock_guard&) = delete;
        lock_guard& operator=(lock_guard&&) = delete;

        ~lock_guard() {
            _mtx.unlock();
        }

        Mutex* mutex() const {
            return &_mtx;
        }
    };

    template <class Mutex>
    class unique_lock {
        Mutex* _mtx;
        bool _locked;

    public:
        unique_lock(Mutex& mtx)
            : _mtx(&mtx), _locked(true) {
            _mtx->lock();
        }

        unique_lock(Mutex& mtx, adopt_lock_t)
            : _mtx(&mtx), _locked(true) {}

        unique_lock(Mutex& mtx, defer_lock_t)
            : _mtx(&mtx), _locked(false) {}

        unique_lock(const unique_lock&) = delete;

        unique_lock(unique_lock&& other) noexcept
            : _mtx(other._mtx), _locked(other._locked) {
            other._mtx = nullptr;
            other._locked = false;
        }

        unique_lock& operator=(const unique_lock&) = delete;

        unique_lock& operator=(unique_lock&& other) {
            unique_lock(std::move(other)).swap(*this);
            return *this;
        }

        void lock() {
            if (!_locked) {
                _mtx->lock();
                _locked = true;
            } else
                throw std::logic_error("Program tried lock locked mutex");
        }

        bool try_lock() {
            if (!_locked)
                return _locked = _mtx->try_lock();
            else
                throw std::logic_error("Program tried lock locked mutex");
        }

        void unlock() {
            if (_locked) {
                _mtx->unlock();
                _locked = false;
            } else
                throw std::logic_error("Program tried lock locked mutex");
        }

        ~unique_lock() {
            if (_locked && _mtx)
                _mtx->unlock();
        }

        Mutex* mutex() {
            return _mtx;
        }

        Mutex* release() {
            auto tmp = _mtx;
            _mtx = nullptr;
            _locked = false;
            return tmp;
        }

        unique_lock& swap(unique_lock& other) noexcept {
            std::swap(_mtx, other._mtx);
            std::swap(_locked, other._locked);
            return *this;
        }
    };

    template <class Mutex>
    class shared_lock {
        Mutex* _mtx;
        bool _locked;

    public:
        shared_lock(Mutex& mtx)
            : _mtx(&mtx), _locked(true) {
            _mtx->lock_shared();
        }

        shared_lock(Mutex& mtx, adopt_lock_t)
            : _mtx(&mtx), _locked(true) {}

        shared_lock(Mutex& mtx, defer_lock_t)
            : _mtx(&mtx), _locked(false) {}

        shared_lock(const shared_lock&) = delete;

        shared_lock(shared_lock&& other) noexcept
            : _mtx(other._mtx), _locked(other._locked) {
            other._mtx = nullptr;
            other._locked = false;
        }

        shared_lock& operator=(const shared_lock&) = delete;

        shared_lock& operator=(shared_lock&& other) {
            shared_lock(std::move(other)).swap(*this);
            return *this;
        }

        ~shared_lock() {
            if (_locked)
                _mtx->unlock_shared();
        }

        Mutex* mutex() const {
            return _mtx;
        }

        Mutex* release() {
            auto tmp = _mtx;
            _mtx = nullptr;
            _locked = false;
            return tmp;
        }

        void lock() {
            if (!_locked) {
                _mtx->lock_shared();
                _locked = true;
            } else
                throw std::logic_error("Program tried lock locked mutex");
        }

        bool try_lock() {
            if (!_locked)
                return _locked = _mtx->try_lock_shared();
            else
                throw std::logic_error("Program tried lock locked mutex");
        }

        void unlock() {
            if (_locked) {
                _mtx->unlock_shared();
                _locked = false;
            } else
                throw std::logic_error("Program tried lock locked mutex");
        }

        shared_lock& swap(shared_lock& other) noexcept {
            std::swap(_mtx, other._mtx);
            std::swap(_locked, other._locked);
            return *this;
        }
    };

    template <class Mutex>
    class relock_guard {
        Mutex& _mtx;

    public:
        relock_guard(Mutex& mtx)
            : _mtx(mtx) {
            _mtx.unlock();
        }

        relock_guard(Mutex& mtx, defer_unlock_t)
            : _mtx(mtx) {}

        relock_guard(const relock_guard&) = delete;
        relock_guard(relock_guard&& other) = delete;
        relock_guard& operator=(const relock_guard&) = delete;
        relock_guard& operator=(relock_guard&& other) = delete;

        ~relock_guard() {
            _mtx.lock();
        }

        Mutex* mutex() const {
            return &_mtx;
        }
    };

    enum class cv_status {
        no_timeout,
        timeout
    };
}
#endif /* INCLUDE_SHARED_PRIMITIVES */
