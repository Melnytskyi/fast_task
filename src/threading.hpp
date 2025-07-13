// Copyright Danyil Melnytskyi 2022-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_THREADING
#define FAST_TASK_THREADING
#include <chrono>
#include <tuple>
#include <type_traits>

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
        unique_lock(unique_lock&&) = delete;
        unique_lock& operator=(const unique_lock&) = delete;
        unique_lock& operator=(unique_lock&&) = delete;

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
            _mtx = nullptr;
            return _mtx;
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
        shared_lock(shared_lock&&) = delete;
        shared_lock& operator=(const shared_lock&) = delete;
        shared_lock& operator=(shared_lock&&) = delete;

        ~shared_lock() {
            if (_locked)
                _mtx->unlock_shared();
        }

        Mutex* mutex() const {
            return &_mtx;
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
        relock_guard(relock_guard&&) = delete;
        relock_guard& operator=(const relock_guard&) = delete;
        relock_guard& operator=(relock_guard&&) = delete;

        ~relock_guard() {
            _mtx.lock();
        }

        Mutex* mutex() const {
            return &_mtx;
        }
    };

    class thread {
        unsigned long _id;
        void* _thread;
        static void* create(void (*function)(void*), void* arg, unsigned long& id, size_t stack_size, bool stack_reservation, int& error_code);

        template <class Tuple, size_t... Indexes>
        static void execute(void* arguments) {
            std::unique_ptr<Tuple> stored_args(static_cast<Tuple*>(arguments));
            Tuple& args = *stored_args.get();
            std::invoke(std::move(std::get<Indexes>(args))...);
        }

        template <class Tuple, size_t... Indexes>
        static auto create_executor(std::index_sequence<Indexes...>) {
            return &execute<Tuple, Indexes...>;
        }

        template <class F, class... Args>
        void start(size_t stack_allocation, bool as_reserved, F&& f, Args&&... args) {
            using Tuple = std::tuple<std::decay_t<F>, std::decay_t<Args>...>;

            auto stored_args = std::make_unique<Tuple>(std::forward<F>(f), std::forward<Args>(args)...);
            int error_code;
            _thread = create(
                create_executor<Tuple>(std::make_index_sequence<1 + sizeof...(Args)>{}),
                stored_args.get(),
                _id,
                stack_allocation,
                as_reserved,
                error_code);
            if (_thread)
                stored_args.release();
            else
                throw std::system_error(error_code, std::system_category());
        }

    public:
        struct id;

        struct stack_size {
            size_t _size;

            stack_size(size_t size)
                : _size(size) {}
        };

        struct reserved_stack_size {
            size_t _size;

            reserved_stack_size(size_t size)
                : _size(size) {}
        };

        template <class F, class... Args>
        thread(stack_size size, F&& f, Args&&... args) {
            start(size._size, false, std::forward<F>(f), std::forward<Args>(args)...);
        }

        template <class F, class... Args>
        thread(reserved_stack_size size, F&& f, Args&&... args) {
            start(size._size, true, std::forward<F>(f), std::forward<Args>(args)...);
        }

        template <class F, class... Args>
        thread(F&& f, Args&&... args) {
            start(0, false, std::forward<F>(f), std::forward<Args>(args)...);
        }

        ~thread() {
            if (_thread)
                detach();
        }

        [[nodiscard]] id get_id() const noexcept;

        [[nodiscard]] void* native_handle() noexcept {
            return _thread;
        }

        [[nodiscard]] static unsigned int hardware_concurrency() noexcept;

        void join();
        void detach();
        [[nodiscard]] bool joinable() const noexcept;

        bool suspend();
        bool resume();
        void insert_context(void (*inserted_context)(void*), void* arg);
        static bool suspend(id);
        static bool resume(id);
        static bool insert_context(id, void (*inserted_context)(void*), void* arg);
    };

    namespace this_thread {
        thread::id get_id() noexcept;
        void yield() noexcept;
        void sleep_for(std::chrono::milliseconds ms);
        void sleep_until(std::chrono::high_resolution_clock::time_point time);
    }

    struct thread::id {
        id() = default;
        id(const id& other) = default;
        id(id&& other) = default;
        id& operator=(const id& other) = default;
        id& operator=(id&& other) = default;
        bool operator==(const id& other) const noexcept;
        bool operator!=(const id& other) const noexcept;
        bool operator<(const id& other) const noexcept;
        bool operator<=(const id& other) const noexcept;
        bool operator>(const id& other) const noexcept;
        bool operator>=(const id& other) const noexcept;
        operator size_t() const noexcept;

    public:
        friend class thread;
        friend id fast_task::this_thread::get_id() noexcept;
        friend struct std::hash<id>;

        id(unsigned long id)
            : _id(id) {}

        unsigned long _id;
    };

    class mutex {
        friend class condition_variable;
#ifdef _WIN32
        void* _mutex;
#else
        pthread_mutex_t* _mutex;
#endif
    public:
        mutex();
        mutex(const mutex& other) = delete;
        mutex(mutex&& other) = delete;
        mutex& operator=(const mutex& other) = delete;
        mutex& operator=(mutex&& other) = delete;
        ~mutex() noexcept(false);
        void lock();
        void unlock();
        bool try_lock();
    };

    class rw_mutex {
        friend class condition_variable;
#ifdef _WIN32
        void* _mutex;
#else
        pthread_rwlock_t* _mutex;
#endif
    public:
        rw_mutex();
        rw_mutex(const rw_mutex& other) = delete;
        rw_mutex(rw_mutex&& other) = delete;
        rw_mutex& operator=(const rw_mutex& other) = delete;
        rw_mutex& operator=(rw_mutex&& other) = delete;
        ~rw_mutex() noexcept(false);
        void lock();
        void unlock();
        bool try_lock();

        void lock_shared();
        void unlock_shared();
        bool try_lock_shared();
    };

    struct relock_state {
        unsigned int _state;
    };

    class recursive_mutex {
        friend class condition_variable;
        mutex actual_mutex;
        size_t count = 0;
        fast_task::thread::id owner;

    public:
        recursive_mutex();
        recursive_mutex(const recursive_mutex& other) = delete;
        recursive_mutex(recursive_mutex&& other) = delete;
        recursive_mutex& operator=(const recursive_mutex& other) = delete;
        recursive_mutex& operator=(recursive_mutex&& other) = delete;
        ~recursive_mutex() noexcept(false);
        void lock();
        void unlock();
        bool try_lock();

        relock_state relock_begin();
        void relock_end(relock_state state);
    };
    enum class cv_status {
        no_timeout,
        timeout
    };

    class condition_variable {
#ifdef _WIN32
        void* _cond;
#else
        pthread_cond_t* _cond;
#endif
    public:
        condition_variable();
        condition_variable(const condition_variable& other) = delete;
        condition_variable(condition_variable&& other) = delete;
        condition_variable& operator=(const condition_variable& other) = delete;
        condition_variable& operator=(condition_variable&& other) = delete;
        ~condition_variable() noexcept(false);
        void notify_one();
        void notify_all();
        void wait(mutex& mtx);
        cv_status wait_for(mutex& mtx, std::chrono::milliseconds ms);
        cv_status wait_until(mutex& mtx, std::chrono::high_resolution_clock::time_point time);

        void wait(recursive_mutex& mtx);
        cv_status wait_for(recursive_mutex& mtx, std::chrono::milliseconds ms);
        cv_status wait_until(recursive_mutex& mtx, std::chrono::high_resolution_clock::time_point time);

        inline void wait(fast_task::unique_lock<mutex>& mtx) {
            wait(*mtx.mutex());
        }

        inline cv_status wait_for(fast_task::unique_lock<mutex>& mtx, std::chrono::milliseconds ms) {
            return wait_until(*mtx.mutex(), std::chrono::high_resolution_clock::now() + ms);
        }

        inline cv_status wait_until(fast_task::unique_lock<mutex>& mtx, std::chrono::high_resolution_clock::time_point time) {
            return wait_until(*mtx.mutex(), time);
        }

        inline void wait(fast_task::unique_lock<recursive_mutex>& mtx) {
            wait(*mtx.mutex());
        }

        inline cv_status wait_for(fast_task::unique_lock<recursive_mutex>& mtx, std::chrono::milliseconds ms) {
            return wait_until(*mtx.mutex(), std::chrono::high_resolution_clock::now() + ms);
        }

        inline cv_status wait_until(fast_task::unique_lock<recursive_mutex>& mtx, std::chrono::high_resolution_clock::time_point time) {
            return wait_until(*mtx.mutex(), time);
        }
    };

    class timed_mutex {
        friend class condition_variable;
#ifdef _WIN32
        condition_variable _cond;
        mutex _mutex;
        unsigned int locked = 0;
#else
        pthread_mutex_t* _mutex;
#endif
    public:
        timed_mutex();
        timed_mutex(const timed_mutex& other) = delete;
        timed_mutex(timed_mutex&& other) = delete;
        timed_mutex& operator=(const timed_mutex& other) = delete;
        timed_mutex& operator=(timed_mutex&& other) = delete;
        ~timed_mutex() noexcept(false);
        void lock();
        void unlock();
        bool try_lock();
        bool try_lock_for(std::chrono::milliseconds ms);
        bool try_lock_until(std::chrono::high_resolution_clock::time_point time);
    };

    template <class M>
    struct full_state_relock_guard {
        M& ref;

        full_state_relock_guard(M& ref)
            : ref(ref) {
            ref.unlock();
        }

        ~full_state_relock_guard() {
            ref.lock();
        }
    };

    template <>
    struct full_state_relock_guard<recursive_mutex> {
        recursive_mutex& ref;
        relock_state state;

        full_state_relock_guard(recursive_mutex& ref)
            : ref(ref) {
            state = ref.relock_begin();
            ref.unlock();
        }

        ~full_state_relock_guard() {
            ref.lock();
            ref.relock_end(state);
        }
    };

    template <>
    struct full_state_relock_guard<fast_task::unique_lock<recursive_mutex>> {
        fast_task::unique_lock<recursive_mutex>& ref;
        relock_state state;

        full_state_relock_guard(fast_task::unique_lock<recursive_mutex>& ref)
            : ref(ref) {
            state = ref.mutex()->relock_begin();
            ref.unlock();
        }

        ~full_state_relock_guard() {
            ref.lock();
            ref.mutex()->relock_end(state);
        }
    };

    template <>
    struct full_state_relock_guard<class MutexUnify> {
        class MutexUnify& ref;

        full_state_relock_guard(class MutexUnify& ref);

        ~full_state_relock_guard();
    };

    class condition_variable_any {
        condition_variable _cond;
        mutex _mutex;

    public:
        condition_variable_any() = default;
        void notify_one();
        void notify_all();

        template <class mut>
        void wait(mut& mtx) {
            fast_task::unique_lock<mutex> lock(_mutex);
            full_state_relock_guard<mut> relock(mtx);
            _cond.wait(_mutex);
            lock.unlock();
        }

        template <class mut>
        cv_status wait_for(mut& mtx, std::chrono::milliseconds ms) {
            return wait_until(mtx, std::chrono::high_resolution_clock::now() + ms);
        }

        template <class mut>
        cv_status wait_until(mut& mtx, std::chrono::high_resolution_clock::time_point time) {
            fast_task::unique_lock<mutex> lock(_mutex);
            full_state_relock_guard<mut> relock(mtx);
            cv_status ret = _cond.wait_until(_mutex, time);
            lock.unlock();
            return ret;
        }
    };
}

namespace std {
    template <>
    struct hash<fast_task::thread::id> {
        size_t operator()(const fast_task::thread::id& id) const noexcept {
            return std::hash<unsigned int>()(id._id);
        }
    };
}

#endif
