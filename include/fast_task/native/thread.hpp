// Copyright Danyil Melnytskyi 2022-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_INCLUDE_NATIVE_THREAD
#define FAST_TASK_INCLUDE_NATIVE_THREAD
#include "../shared.hpp"
#include <chrono>
#include <cstdint>
#include <functional> //std::invoke
#include <memory>
#include <tuple>
#include <type_traits>

namespace fast_task::native {
    class FT_API thread {
        unsigned long _id;
        void* _thread;
        static void init_dat();
        static void* create(void (*function)(void*), void* arg, unsigned long& id, size_t stack_size, bool stack_reservation, int& error_code);

        template <class Tuple, size_t... Indexes>
        static void execute(void* arguments) {
            std::unique_ptr<Tuple> stored_args(static_cast<Tuple*>(arguments));
            init_dat();
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
                error_code
            );
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

        thread() {
            _id = 0;
            _thread = nullptr;
        }

        thread(thread&& other) noexcept
            : _id(other._id), _thread(other._thread) {
            other._id = 0;
            other._thread = nullptr;
        }

        thread& operator=(thread&& other) noexcept {
            if (joinable())
                detach();
            _id = other._id;
            _thread = other._thread;
            other._id = 0;
            other._thread = nullptr;
            return *this;
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
        thread::id FT_API get_id() noexcept;
        void FT_API yield() noexcept;
        void FT_API sleep_for(std::chrono::milliseconds ms);
        void FT_API sleep_until(std::chrono::high_resolution_clock::time_point time);
    }

    struct FT_API thread::id {
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
        friend id this_thread::get_id() noexcept;
        friend struct std::hash<id>;

        id(unsigned long id)
            : _id(id) {}

        unsigned long _id;
    };
}

namespace std {
    template <>
    struct FT_API hash<fast_task::native::thread::id> {
        size_t operator()(const fast_task::native::thread::id& id) const noexcept {
            return std::hash<unsigned int>()(id._id);
        }
    };
}


#endif /* FAST_TASK_INCLUDE_NATIVE_THREAD */
