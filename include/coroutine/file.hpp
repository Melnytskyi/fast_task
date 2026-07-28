#ifndef FAST_TASK_INCLUDE_COROUTINE_FILE
#define FAST_TASK_INCLUDE_COROUTINE_FILE
#include "../file.hpp"
#include "../polyfill/expected.hpp"
#include "core.hpp"
#include "detail/lock_misc.hpp"

namespace fast_task {
    namespace detail {
        template <typename T>
        class [[nodiscard("I/O operations must be awaited or explicitly canceled")]] io_handle {
            file::io_operation<T> op;

        public:
            io_handle(file::io_operation<T>&& op)
                : op(std::move(op)) {}

            io_handle(const io_handle&) = delete;
            io_handle& operator=(const io_handle&) = delete;

            io_handle(io_handle&&) noexcept = default;
            io_handle& operator=(io_handle&&) noexcept = default;

            ~io_handle() {
                if (!op.is_done())
                    std::terminate();
            }

            struct awaiter {
                enter_state state;
                io_handle& self;

                bool await_ready() noexcept {
                    return self.op.is_done();
                }

                bool await_suspend(base_coro_handle h) {
                    return !self.op.enter_wait(h.promise->task_object, state);
                }

                T await_resume() {
                    return self.op.get();
                }
            };

            awaiter operator co_await() noexcept {
                return awaiter{{}, *this};
            }

            struct cancel_awaiter {
                enter_state state;
                io_handle& self;

                bool await_ready() noexcept {
                    return self.op.is_done();
                }

                bool await_suspend(base_coro_handle h) {
                    return !self.op.enter_cancel(h.promise->task_object, state);
                }

                void await_resume() {}
            };

            cancel_awaiter cancel() noexcept {
                return cancel_awaiter{{}, *this};
            }
        };

        template <>
        class [[nodiscard("I/O operations must be awaited or explicitly canceled")]] io_handle<void> {
            file::io_operation<void> op;

        public:
            io_handle(file::io_operation<void>&& op)
                : op(std::move(op)) {}

            io_handle(const io_handle&) = delete;
            io_handle& operator=(const io_handle&) = delete;

            io_handle(io_handle&&) noexcept = default;
            io_handle& operator=(io_handle&&) noexcept = default;

            ~io_handle() {
                if (!op.is_done())
                    std::terminate();
            }

            struct awaiter {
                enter_state state;
                io_handle& self;

                bool await_ready() noexcept {
                    return self.op.is_done();
                }

                bool await_suspend(base_coro_handle h) {
                    return !self.op.enter_wait(h.promise->task_object, state);
                }

                void await_resume() {
                    self.op.get();
                }
            };

            awaiter operator co_await() noexcept {
                return awaiter{{}, *this};
            }

            struct cancel_awaiter {
                enter_state state;
                io_handle& self;

                bool await_ready() noexcept {
                    return self.op.is_done();
                }

                bool await_suspend(base_coro_handle h) {
                    return !self.op.enter_cancel(h.promise->task_object, state);
                }

                void await_resume() {}
            };

            cancel_awaiter cancel() noexcept {
                return cancel_awaiter{{}, *this};
            }
        };

        template <typename T>
        class [[nodiscard("I/O operations must be awaited or explicitly canceled")]] io_handle_until {
            file::io_operation<T> op;
            std::chrono::high_resolution_clock::time_point tp;

        public:
            io_handle_until(file::io_operation<T>&& op, std::chrono::high_resolution_clock::time_point tp)
                : op(std::move(op)), tp(tp) {}

            io_handle_until(const io_handle_until&) = delete;
            io_handle_until& operator=(const io_handle_until&) = delete;

            io_handle_until(io_handle_until&&) noexcept = default;
            io_handle_until& operator=(io_handle_until&&) noexcept = default;

            ~io_handle_until() {
                if (!op.is_done())
                    std::terminate();
            }

            struct awaiter {
                enter_state state;
                io_handle_until& self;

                bool await_ready() noexcept {
                    return self.op.is_done();
                }

                bool await_suspend(base_coro_handle h) {
                    return !self.op.enter_wait_until(h.promise->task_object, state, self.tp);
                }

                std::optional<T> await_resume() {
                    if (self.op.is_done())
                        return self.op.get();
                    return std::nullopt;
                }
            };

            awaiter operator co_await() noexcept {
                return awaiter{{}, *this};
            }

            struct cancel_awaiter {
                enter_state state;
                io_handle_until& self;

                bool await_ready() noexcept {
                    return self.op.is_done();
                }

                bool await_suspend(base_coro_handle h) {
                    return !self.op.enter_cancel(h.promise->task_object, state);
                }

                void await_resume() {}
            };

            cancel_awaiter cancel() noexcept {
                return cancel_awaiter{{}, *this};
            }
        };

        template <>
        class [[nodiscard("I/O operations must be awaited or explicitly canceled")]] io_handle_until<void> {
            file::io_operation<void> op;
            std::chrono::high_resolution_clock::time_point tp;

        public:
            io_handle_until(file::io_operation<void>&& op, std::chrono::high_resolution_clock::time_point tp)
                : op(std::move(op)), tp(tp) {}

            io_handle_until(const io_handle_until&) = delete;
            io_handle_until& operator=(const io_handle_until&) = delete;

            io_handle_until(io_handle_until&&) noexcept = default;
            io_handle_until& operator=(io_handle_until&&) noexcept = default;

            ~io_handle_until() {
                if (!op.is_done())
                    std::terminate();
            }

            struct awaiter {
                enter_state state;
                io_handle_until& self;

                bool await_ready() noexcept {
                    return self.op.is_done();
                }

                bool await_suspend(base_coro_handle h) {
                    return !self.op.enter_wait_until(h.promise->task_object, state, self.tp);
                }

                bool await_resume() {
                    if (self.op.is_done()) {
                        self.op.get();
                        return true;
                    }
                    return false;
                }
            };

            awaiter operator co_await() noexcept {
                return awaiter{{}, *this};
            }

            struct cancel_awaiter {
                enter_state state;
                io_handle_until& self;

                bool await_ready() noexcept {
                    return self.op.is_done();
                }

                bool await_suspend(base_coro_handle h) {
                    return !self.op.enter_cancel(h.promise->task_object, state);
                }

                void await_resume() {}
            };

            cancel_awaiter cancel() noexcept {
                return cancel_awaiter{{}, *this};
            }
        };

        template <typename T>
        class [[nodiscard("I/O operations must be awaited or explicitly canceled")]] safe_io_handle {
            file::io_operation<T> op;

        public:
            safe_io_handle(file::io_operation<T>&& op)
                : op(std::move(op)) {}

            safe_io_handle(const safe_io_handle&) = delete;
            safe_io_handle& operator=(const safe_io_handle&) = delete;

            safe_io_handle(safe_io_handle&&) noexcept = default;
            safe_io_handle& operator=(safe_io_handle&&) noexcept = default;

            ~safe_io_handle() {
                if (!op.is_done())
                    std::terminate();
            }

            struct awaiter {
                enter_state state;
                safe_io_handle& self;

                bool await_ready() noexcept {
                    return self.op.is_done();
                }

                bool await_suspend(base_coro_handle h) {
                    return !self.op.enter_wait(h.promise->task_object, state);
                }

                polyfill::expected<T, file::io_errors> await_resume() {
                    if (auto err = self.op.get_error())
                        return polyfill::unexpected(*err);
                    return *self.op.try_get();
                }
            };

            awaiter operator co_await() noexcept {
                return awaiter{{}, *this};
            }

            struct cancel_awaiter {
                enter_state state;
                safe_io_handle& self;

                bool await_ready() noexcept {
                    return self.op.is_done();
                }

                bool await_suspend(base_coro_handle h) {
                    return !self.op.enter_cancel(h.promise->task_object, state);
                }

                void await_resume() {}
            };

            cancel_awaiter cancel() noexcept {
                return cancel_awaiter{{}, *this};
            }
        };

        template <>
        class [[nodiscard("I/O operations must be awaited or explicitly canceled")]] safe_io_handle<void> {
            file::io_operation<void> op;

        public:
            safe_io_handle(file::io_operation<void>&& op)
                : op(std::move(op)) {}

            safe_io_handle(const safe_io_handle&) = delete;
            safe_io_handle& operator=(const safe_io_handle&) = delete;

            safe_io_handle(safe_io_handle&&) noexcept = default;
            safe_io_handle& operator=(safe_io_handle&&) noexcept = default;

            ~safe_io_handle() {
                if (!op.is_done())
                    std::terminate();
            }

            struct awaiter {
                enter_state state;
                safe_io_handle& self;

                bool await_ready() noexcept {
                    return self.op.is_done();
                }

                bool await_suspend(base_coro_handle h) {
                    return !self.op.enter_wait(h.promise->task_object, state);
                }

                polyfill::expected<void, file::io_errors> await_resume() {
                    if (auto err = self.op.get_error())
                        return polyfill::unexpected(*err);
                    return {};
                }
            };

            awaiter operator co_await() noexcept {
                return awaiter{{}, *this};
            }

            struct cancel_awaiter {
                enter_state state;
                safe_io_handle& self;

                bool await_ready() noexcept {
                    return self.op.is_done();
                }

                bool await_suspend(base_coro_handle h) {
                    return !self.op.enter_cancel(h.promise->task_object, state);
                }

                void await_resume() {}
            };

            cancel_awaiter cancel() noexcept {
                return cancel_awaiter{{}, *this};
            }
        };

        template <typename T>
        class [[nodiscard("I/O operations must be awaited or explicitly canceled")]] safe_io_handle_until {
            file::io_operation<T> op;
            std::chrono::high_resolution_clock::time_point tp;

        public:
            safe_io_handle_until(file::io_operation<T>&& op, std::chrono::high_resolution_clock::time_point tp)
                : op(std::move(op)), tp(tp) {}

            safe_io_handle_until(const safe_io_handle_until&) = delete;
            safe_io_handle_until& operator=(const safe_io_handle_until&) = delete;

            safe_io_handle_until(safe_io_handle_until&&) noexcept = default;
            safe_io_handle_until& operator=(safe_io_handle_until&&) noexcept = default;

            ~safe_io_handle_until() {
                if (!op.is_done())
                    std::terminate();
            }

            struct awaiter {
                enter_state state;
                safe_io_handle_until& self;

                bool await_ready() noexcept {
                    return self.op.is_done();
                }

                bool await_suspend(base_coro_handle h) {
                    return !self.op.enter_wait_until(h.promise->task_object, state, self.tp);
                }

                std::optional<T> await_resume() {
                    if (auto err = self.op.get_error())
                        return polyfill::unexpected(*err);
                    return *self.op.try_get();
                }
            };

            awaiter operator co_await() noexcept {
                return awaiter{{}, *this};
            }

            struct cancel_awaiter {
                enter_state state;
                safe_io_handle_until& self;

                bool await_ready() noexcept {
                    return self.op.is_done();
                }

                bool await_suspend(base_coro_handle h) {
                    return !self.op.enter_cancel(h.promise->task_object, state);
                }

                void await_resume() {}
            };

            cancel_awaiter cancel() noexcept {
                return cancel_awaiter{{}, *this};
            }
        };

        template <>
        class [[nodiscard("I/O operations must be awaited or explicitly canceled")]] safe_io_handle_until<void> {
            file::io_operation<void> op;
            std::chrono::high_resolution_clock::time_point tp;

        public:
            safe_io_handle_until(file::io_operation<void>&& op, std::chrono::high_resolution_clock::time_point tp)
                : op(std::move(op)), tp(tp) {}

            safe_io_handle_until(const safe_io_handle_until&) = delete;
            safe_io_handle_until& operator=(const safe_io_handle_until&) = delete;

            safe_io_handle_until(safe_io_handle_until&&) noexcept = default;
            safe_io_handle_until& operator=(safe_io_handle_until&&) noexcept = default;

            ~safe_io_handle_until() {
                if (!op.is_done()) {
                    std::terminate();
                }
            }

            struct awaiter {
                enter_state state;
                safe_io_handle_until& self;

                bool await_ready() noexcept {
                    return self.op.is_done();
                }

                bool await_suspend(base_coro_handle h) {
                    return !self.op.enter_wait_until(h.promise->task_object, state, self.tp);
                }

                polyfill::expected<bool, file::io_errors> await_resume() {
                    if (auto err = self.op.get_error())
                        return polyfill::unexpected(*err);
                    return {self.op.is_done()};
                }
            };

            awaiter operator co_await() noexcept {
                return awaiter{{}, *this};
            }

            struct cancel_awaiter {
                enter_state state;
                safe_io_handle_until& self;

                bool await_ready() noexcept {
                    return self.op.is_done();
                }

                bool await_suspend(base_coro_handle h) {
                    return !self.op.enter_cancel(h.promise->task_object, state);
                }

                void await_resume() {}
            };

            cancel_awaiter cancel() noexcept {
                return cancel_awaiter{{}, *this};
            }
        };
    }

    inline auto async_read(file::file_handle& handle, uint32_t size) {
        return detail::io_handle{handle.make_read(size)};
    }

    inline auto async_read_at(file::file_handle& handle, uint64_t offset, uint32_t size) {
        return detail::io_handle{handle.make_read_at(offset, size)};
    }

    inline auto async_read_fixed(file::file_handle& handle, uint32_t size) {
        return detail::io_handle{handle.make_read_fixed(size)};
    }

    inline auto async_read_fixed_at(file::file_handle& handle, uint64_t offset, uint32_t size) {
        return detail::io_handle{handle.make_read_fixed_at(offset, size)};
    }

    inline auto async_write(file::file_handle& handle, const uint8_t* data, uint32_t size) {
        return detail::io_handle{handle.make_write(data, size)};
    }

    inline auto async_write_at(file::file_handle& handle, uint64_t offset, const uint8_t* data, uint32_t size) {
        return detail::io_handle{handle.make_write_at(offset, data, size)};
    }

    inline auto async_append(file::file_handle& handle, const uint8_t* data, uint32_t size) {
        return detail::io_handle{handle.make_append(data, size)};
    }

    inline auto async_read_until(file::file_handle& handle, uint32_t size, std::chrono::high_resolution_clock::time_point time_point) {
        return detail::io_handle_until{handle.make_read(size), time_point};
    }

    inline auto async_read_at_until(file::file_handle& handle, uint64_t offset, uint32_t size, std::chrono::high_resolution_clock::time_point time_point) {
        return detail::io_handle_until{handle.make_read_at(offset, size), time_point};
    }

    inline auto async_read_fixed_until(file::file_handle& handle, uint32_t size, std::chrono::high_resolution_clock::time_point time_point) {
        return detail::io_handle_until{handle.make_read_fixed(size), time_point};
    }

    inline auto async_read_fixed_at_until(file::file_handle& handle, uint64_t offset, uint32_t size, std::chrono::high_resolution_clock::time_point time_point) {
        return detail::io_handle_until{handle.make_read_fixed_at(offset, size), time_point};
    }

    inline auto async_write_until(file::file_handle& handle, const uint8_t* data, uint32_t size, std::chrono::high_resolution_clock::time_point time_point) {
        return detail::io_handle_until{handle.make_write(data, size), time_point};
    }

    inline auto async_write_at_until(file::file_handle& handle, uint64_t offset, const uint8_t* data, uint32_t size, std::chrono::high_resolution_clock::time_point time_point) {
        return detail::io_handle_until{handle.make_write_at(offset, data, size), time_point};
    }

    inline auto async_append_until(file::file_handle& handle, const uint8_t* data, uint32_t size, std::chrono::high_resolution_clock::time_point time_point) {
        return detail::io_handle_until{handle.make_append(data, size), time_point};
    }

    template <class Rep, class Period>
    inline auto async_read_for(file::file_handle& handle, uint32_t size, const std::chrono::duration<Rep, Period>& duration) {
        return detail::io_handle_until{handle.make_read(size), std::chrono::high_resolution_clock::now() + duration};
    }

    template <class Rep, class Period>
    inline auto async_read_at_for(file::file_handle& handle, uint64_t offset, uint32_t size, const std::chrono::duration<Rep, Period>& duration) {
        return detail::io_handle_until{handle.make_read_at(offset, size), std::chrono::high_resolution_clock::now() + duration};
    }

    template <class Rep, class Period>
    inline auto async_read_fixed_for(file::file_handle& handle, uint32_t size, const std::chrono::duration<Rep, Period>& duration) {
        return detail::io_handle_until{handle.make_read_fixed(size), std::chrono::high_resolution_clock::now() + duration};
    }

    template <class Rep, class Period>
    inline auto async_read_fixed_at_for(file::file_handle& handle, uint64_t offset, uint32_t size, const std::chrono::duration<Rep, Period>& duration) {
        return detail::io_handle_until{handle.make_read_fixed_at(offset, size), std::chrono::high_resolution_clock::now() + duration};
    }

    template <class Rep, class Period>
    inline auto async_write_for(file::file_handle& handle, const uint8_t* data, uint32_t size, const std::chrono::duration<Rep, Period>& duration) {
        return detail::io_handle_until{handle.make_write(data, size), std::chrono::high_resolution_clock::now() + duration};
    }

    template <class Rep, class Period>
    inline auto async_write_at_for(file::file_handle& handle, uint64_t offset, const uint8_t* data, uint32_t size, const std::chrono::duration<Rep, Period>& duration) {
        return detail::io_handle_until{handle.make_write_at(offset, data, size), std::chrono::high_resolution_clock::now() + duration};
    }

    template <class Rep, class Period>
    inline auto async_append_for(file::file_handle& handle, const uint8_t* data, uint32_t size, const std::chrono::duration<Rep, Period>& duration) {
        return detail::io_handle_until{handle.make_append(data, size), std::chrono::high_resolution_clock::now() + duration};
    }

    inline auto safe_async_read(file::file_handle& handle, uint32_t size) {
        return detail::safe_io_handle{handle.make_read(size)};
    }

    inline auto safe_async_read_at(file::file_handle& handle, uint64_t offset, uint32_t size) {
        return detail::safe_io_handle{handle.make_read_at(offset, size)};
    }

    inline auto safe_async_read_fixed(file::file_handle& handle, uint32_t size) {
        return detail::safe_io_handle{handle.make_read_fixed(size)};
    }

    inline auto safe_async_read_fixed_at(file::file_handle& handle, uint64_t offset, uint32_t size) {
        return detail::safe_io_handle{handle.make_read_fixed_at(offset, size)};
    }

    inline auto safe_async_write(file::file_handle& handle, const uint8_t* data, uint32_t size) {
        return detail::safe_io_handle{handle.make_write(data, size)};
    }

    inline auto safe_async_write_at(file::file_handle& handle, uint64_t offset, const uint8_t* data, uint32_t size) {
        return detail::safe_io_handle{handle.make_write_at(offset, data, size)};
    }

    inline auto safe_async_append(file::file_handle& handle, const uint8_t* data, uint32_t size) {
        return detail::safe_io_handle{handle.make_append(data, size)};
    }

    inline auto safe_async_read_until(file::file_handle& handle, uint32_t size, std::chrono::high_resolution_clock::time_point time_point) {
        return detail::safe_io_handle_until{handle.make_read(size), time_point};
    }

    inline auto safe_async_read_at_until(file::file_handle& handle, uint64_t offset, uint32_t size, std::chrono::high_resolution_clock::time_point time_point) {
        return detail::safe_io_handle_until{handle.make_read_at(offset, size), time_point};
    }

    inline auto safe_async_read_fixed_until(file::file_handle& handle, uint32_t size, std::chrono::high_resolution_clock::time_point time_point) {
        return detail::safe_io_handle_until{handle.make_read_fixed(size), time_point};
    }

    inline auto safe_async_read_fixed_at_until(file::file_handle& handle, uint64_t offset, uint32_t size, std::chrono::high_resolution_clock::time_point time_point) {
        return detail::safe_io_handle_until{handle.make_read_fixed_at(offset, size), time_point};
    }

    inline auto safe_async_write_until(file::file_handle& handle, const uint8_t* data, uint32_t size, std::chrono::high_resolution_clock::time_point time_point) {
        return detail::safe_io_handle_until{handle.make_write(data, size), time_point};
    }

    inline auto safe_async_write_at_until(file::file_handle& handle, uint64_t offset, const uint8_t* data, uint32_t size, std::chrono::high_resolution_clock::time_point time_point) {
        return detail::safe_io_handle_until{handle.make_write_at(offset, data, size), time_point};
    }

    inline auto safe_async_append_until(file::file_handle& handle, const uint8_t* data, uint32_t size, std::chrono::high_resolution_clock::time_point time_point) {
        return detail::safe_io_handle_until{handle.make_append(data, size), time_point};
    }

    template <class Rep, class Period>
    inline auto safe_async_read_for(file::file_handle& handle, uint32_t size, std::chrono::duration<Rep, Period> timeout) {
        return detail::safe_io_handle_until{handle.make_read(size), std::chrono::high_resolution_clock::now() + timeout};
    }

    template <class Rep, class Period>
    inline auto safe_async_read_at_for(file::file_handle& handle, uint64_t offset, uint32_t size, std::chrono::duration<Rep, Period> timeout) {
        return detail::safe_io_handle_until{handle.make_read_at(offset, size), std::chrono::high_resolution_clock::now() + timeout};
    }

    template <class Rep, class Period>
    inline auto safe_async_read_fixed_for(file::file_handle& handle, uint32_t size, std::chrono::duration<Rep, Period> timeout) {
        return detail::safe_io_handle_until{handle.make_read_fixed(size), std::chrono::high_resolution_clock::now() + timeout};
    }

    template <class Rep, class Period>
    inline auto safe_async_read_fixed_at_for(file::file_handle& handle, uint64_t offset, uint32_t size, std::chrono::duration<Rep, Period> timeout) {
        return detail::safe_io_handle_until{handle.make_read_fixed_at(offset, size), std::chrono::high_resolution_clock::now() + timeout};
    }

    template <class Rep, class Period>
    inline auto safe_async_write_for(file::file_handle& handle, const uint8_t* data, uint32_t size, std::chrono::duration<Rep, Period> timeout) {
        return detail::safe_io_handle_until{handle.make_write(data, size), std::chrono::high_resolution_clock::now() + timeout};
    }

    template <class Rep, class Period>
    inline auto safe_async_write_at_for(file::file_handle& handle, uint64_t offset, const uint8_t* data, uint32_t size, std::chrono::duration<Rep, Period> timeout) {
        return detail::safe_io_handle_until{handle.make_write_at(offset, data, size), std::chrono::high_resolution_clock::now() + timeout};
    }

    template <class Rep, class Period>
    inline auto safe_async_append_for(file::file_handle& handle, const uint8_t* data, uint32_t size, std::chrono::duration<Rep, Period> timeout) {
        return detail::safe_io_handle_until{handle.make_append(data, size), std::chrono::high_resolution_clock::now() + timeout};
    }
}

#endif /* FAST_TASK_INCLUDE_COROUTINE_FILE */