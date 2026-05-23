#ifndef INCLUDE_COROUTINE_FILE
#define INCLUDE_COROUTINE_FILE
#include "../files.hpp"
#include "core.hpp"
#include "detail/lock_misc.hpp"
#include <version>

#if defined(__cpp_lib_expected) && __cpp_lib_expected >= 202202L
    #include <expected>
#endif
namespace fast_task {
    namespace detail {
        template <typename T>
        struct io_awaiter {
            files::io_operation<T> op;

            bool await_ready() noexcept {
                return op.is_done();
            }

            bool await_suspend(base_coro_handle h) {
                return !op.enter_wait(h.promise->task_object);
            }

            T await_resume() {
                return op.get();
            }
        };

        template <typename T>
        struct io_awaiter_until {
            files::io_operation<T> op;
            std::chrono::high_resolution_clock::time_point tp;

            bool await_ready() noexcept {
                return op.is_done() || std::chrono::high_resolution_clock::now() >= tp;
            }

            bool await_suspend(base_coro_handle h) {
                return !op.enter_wait_until(h.promise->task_object, tp);
            }

            std::optional<T> await_resume() {
                if (op.is_done())
                    return op.get();
                return std::nullopt;
            }
        };

        template <>
        struct io_awaiter_until<void> {
            files::io_operation<void> op;
            std::chrono::high_resolution_clock::time_point tp;

            bool await_ready() noexcept {
                return op.is_done() || std::chrono::high_resolution_clock::now() >= tp;
            }

            bool await_suspend(base_coro_handle h) {
                return !op.enter_wait_until(h.promise->task_object, tp);
            }

            bool await_resume() {
                if (op.is_done()) {
                    op.get();
                    return true;
                }
                return false;
            }
        };

        template <typename T>
        struct safe_io_awaiter {
            files::io_operation<T> op;

            bool await_ready() noexcept {
                return op.is_done();
            }

            bool await_suspend(base_coro_handle h) {
                return !op.enter_wait(h.promise->task_object);
            }

#if defined(__cpp_lib_expected) && __cpp_lib_expected >= 202202L
            std::expected<T, files::io_errors> await_resume() noexcept {
                if (auto err = op.get_error())
                    return std::unexpected(*err);
                return *op.try_get();
            }
#else
            std::pair<std::optional<T>, std::optional<files::io_errors>> await_resume() noexcept {
                return {op.try_get(), op.get_error()};
            }
#endif
        };

        template <>
        struct safe_io_awaiter<void> {
            files::io_operation<void> op;

            bool await_ready() noexcept {
                return op.is_done();
            }

            bool await_suspend(base_coro_handle h) {
                return !op.enter_wait(h.promise->task_object);
            }

#if defined(__cpp_lib_expected) && __cpp_lib_expected >= 202202L
            std::expected<void, files::io_errors> await_resume() noexcept {
                if (auto err = op.get_error())
                    return std::unexpected(*err);
                return {};
            }
#else
            std::optional<files::io_errors> await_resume() noexcept {
                return op.get_error();
            }
#endif
        };

        template <typename T>
        struct safe_io_awaiter_until {
            files::io_operation<T> op;
            std::chrono::high_resolution_clock::time_point tp;

            bool await_ready() noexcept {
                return op.is_done() || std::chrono::high_resolution_clock::now() >= tp;
            }

            bool await_suspend(base_coro_handle h) {
                return !op.enter_wait_until(h.promise->task_object, tp);
            }

#if defined(__cpp_lib_expected) && __cpp_lib_expected >= 202202L
            std::expected<std::optional<T>, files::io_errors> await_resume() noexcept {
                if (auto err = op.get_error())
                    return std::unexpected(*err);
                return op.try_get();
            }
#else
            std::pair<std::optional<T>, std::optional<files::io_errors>> await_resume() noexcept {
                return {op.try_get(), op.get_error()};
            }
#endif
        };

        template <>
        struct safe_io_awaiter_until<void> {
            files::io_operation<void> op;
            std::chrono::high_resolution_clock::time_point tp;

            bool await_ready() noexcept {
                return op.is_done() || std::chrono::high_resolution_clock::now() >= tp;
            }

            bool await_suspend(base_coro_handle h) {
                return !op.enter_wait_until(h.promise->task_object, tp);
            }

#if defined(__cpp_lib_expected) && __cpp_lib_expected >= 202202L
            std::expected<bool, files::io_errors> await_resume() noexcept {
                if (auto err = op.get_error())
                    return std::unexpected(*err);
                return {op.is_done()};
            }
#else
            std::pair<bool, std::optional<files::io_errors>> await_resume() noexcept {
                if (auto err = op.get_error())
                    return {false, *err};
                if (op.is_done()) {
                    op.get();
                    return {true, std::nullopt};
                }
                return {false, std::nullopt};
            }
#endif
        };
    }

    inline auto async_read(files::file_handle& handle, uint32_t size) {
        return detail::io_awaiter{handle.make_read(size)};
    }

    inline auto async_read_at(files::file_handle& handle, uint64_t offset, uint32_t size) {
        return detail::io_awaiter{handle.make_read_at(offset, size)};
    }

    inline auto async_read_fixed(files::file_handle& handle, uint32_t size) {
        return detail::io_awaiter{handle.make_read_fixed(size)};
    }

    inline auto async_read_fixed_at(files::file_handle& handle, uint64_t offset, uint32_t size) {
        return detail::io_awaiter{handle.make_read_fixed_at(offset, size)};
    }

    inline auto async_write(files::file_handle& handle, const uint8_t* data, uint32_t size) {
        return detail::io_awaiter{handle.make_write(data, size)};
    }

    inline auto async_write_at(files::file_handle& handle, uint64_t offset, const uint8_t* data, uint32_t size) {
        return detail::io_awaiter{handle.make_write_at(offset, data, size)};
    }

    inline auto async_append(files::file_handle& handle, const uint8_t* data, uint32_t size) {
        return detail::io_awaiter{handle.make_append(data, size)};
    }

    inline auto async_read_until(files::file_handle& handle, uint32_t size, std::chrono::high_resolution_clock::time_point time_point) {
        return detail::io_awaiter_until{handle.make_read(size), time_point};
    }

    inline auto async_read_at_until(files::file_handle& handle, uint64_t offset, uint32_t size, std::chrono::high_resolution_clock::time_point time_point) {
        return detail::io_awaiter_until{handle.make_read_at(offset, size), time_point};
    }

    inline auto async_read_fixed_until(files::file_handle& handle, uint32_t size, std::chrono::high_resolution_clock::time_point time_point) {
        return detail::io_awaiter_until{handle.make_read_fixed(size), time_point};
    }

    inline auto async_read_fixed_at_until(files::file_handle& handle, uint64_t offset, uint32_t size, std::chrono::high_resolution_clock::time_point time_point) {
        return detail::io_awaiter_until{handle.make_read_fixed_at(offset, size), time_point};
    }

    inline auto async_write_until(files::file_handle& handle, const uint8_t* data, uint32_t size, std::chrono::high_resolution_clock::time_point time_point) {
        return detail::io_awaiter_until{handle.make_write(data, size), time_point};
    }

    inline auto async_write_at_until(files::file_handle& handle, uint64_t offset, const uint8_t* data, uint32_t size, std::chrono::high_resolution_clock::time_point time_point) {
        return detail::io_awaiter_until{handle.make_write_at(offset, data, size), time_point};
    }

    inline auto async_append_until(files::file_handle& handle, const uint8_t* data, uint32_t size, std::chrono::high_resolution_clock::time_point time_point) {
        return detail::io_awaiter_until{handle.make_append(data, size), time_point};
    }

    template <class Rep, class Period>
    inline auto async_read_for(files::file_handle& handle, uint32_t size, const std::chrono::duration<Rep, Period>& duration) {
        return detail::io_awaiter_until{handle.make_read(size), std::chrono::high_resolution_clock::now() + duration};
    }

    template <class Rep, class Period>
    inline auto async_read_at_for(files::file_handle& handle, uint64_t offset, uint32_t size, const std::chrono::duration<Rep, Period>& duration) {
        return detail::io_awaiter_until{handle.make_read_at(offset, size), std::chrono::high_resolution_clock::now() + duration};
    }

    template <class Rep, class Period>
    inline auto async_read_fixed_for(files::file_handle& handle, uint32_t size, const std::chrono::duration<Rep, Period>& duration) {
        return detail::io_awaiter_until{handle.make_read_fixed(size), std::chrono::high_resolution_clock::now() + duration};
    }

    template <class Rep, class Period>
    inline auto async_read_fixed_at_for(files::file_handle& handle, uint64_t offset, uint32_t size, const std::chrono::duration<Rep, Period>& duration) {
        return detail::io_awaiter_until{handle.make_read_fixed_at(offset, size), std::chrono::high_resolution_clock::now() + duration};
    }

    template <class Rep, class Period>
    inline auto async_write_for(files::file_handle& handle, const uint8_t* data, uint32_t size, const std::chrono::duration<Rep, Period>& duration) {
        return detail::io_awaiter_until{handle.make_write(data, size), std::chrono::high_resolution_clock::now() + duration};
    }

    template <class Rep, class Period>
    inline auto async_write_at_for(files::file_handle& handle, uint64_t offset, const uint8_t* data, uint32_t size, const std::chrono::duration<Rep, Period>& duration) {
        return detail::io_awaiter_until{handle.make_write_at(offset, data, size), std::chrono::high_resolution_clock::now() + duration};
    }

    template <class Rep, class Period>
    inline auto async_append_for(files::file_handle& handle, const uint8_t* data, uint32_t size, const std::chrono::duration<Rep, Period>& duration) {
        return detail::io_awaiter_until{handle.make_append(data, size), std::chrono::high_resolution_clock::now() + duration};
    }

    inline auto safe_async_read(files::file_handle& handle, uint32_t size) {
        return detail::safe_io_awaiter{handle.make_read(size)};
    }

    inline auto safe_async_read_at(files::file_handle& handle, uint64_t offset, uint32_t size) {
        return detail::safe_io_awaiter{handle.make_read_at(offset, size)};
    }

    inline auto safe_async_read_fixed(files::file_handle& handle, uint32_t size) {
        return detail::safe_io_awaiter{handle.make_read_fixed(size)};
    }

    inline auto safe_async_read_fixed_at(files::file_handle& handle, uint64_t offset, uint32_t size) {
        return detail::safe_io_awaiter{handle.make_read_fixed_at(offset, size)};
    }

    inline auto safe_async_write(files::file_handle& handle, const uint8_t* data, uint32_t size) {
        return detail::safe_io_awaiter{handle.make_write(data, size)};
    }

    inline auto safe_async_write_at(files::file_handle& handle, uint64_t offset, const uint8_t* data, uint32_t size) {
        return detail::safe_io_awaiter{handle.make_write_at(offset, data, size)};
    }

    inline auto safe_async_append(files::file_handle& handle, const uint8_t* data, uint32_t size) {
        return detail::safe_io_awaiter{handle.make_append(data, size)};
    }

    inline auto safe_async_read_until(files::file_handle& handle, uint32_t size, std::chrono::high_resolution_clock::time_point time_point) {
        return detail::safe_io_awaiter_until{handle.make_read(size), time_point};
    }

    inline auto safe_async_read_at_until(files::file_handle& handle, uint64_t offset, uint32_t size, std::chrono::high_resolution_clock::time_point time_point) {
        return detail::safe_io_awaiter_until{handle.make_read_at(offset, size), time_point};
    }

    inline auto safe_async_read_fixed_until(files::file_handle& handle, uint32_t size, std::chrono::high_resolution_clock::time_point time_point) {
        return detail::safe_io_awaiter_until{handle.make_read_fixed(size), time_point};
    }

    inline auto safe_async_read_fixed_at_until(files::file_handle& handle, uint64_t offset, uint32_t size, std::chrono::high_resolution_clock::time_point time_point) {
        return detail::safe_io_awaiter_until{handle.make_read_fixed_at(offset, size), time_point};
    }

    inline auto safe_async_write_until(files::file_handle& handle, const uint8_t* data, uint32_t size, std::chrono::high_resolution_clock::time_point time_point) {
        return detail::safe_io_awaiter_until{handle.make_write(data, size), time_point};
    }

    inline auto safe_async_write_at_until(files::file_handle& handle, uint64_t offset, const uint8_t* data, uint32_t size, std::chrono::high_resolution_clock::time_point time_point) {
        return detail::safe_io_awaiter_until{handle.make_write_at(offset, data, size), time_point};
    }

    inline auto safe_async_append_until(files::file_handle& handle, const uint8_t* data, uint32_t size, std::chrono::high_resolution_clock::time_point time_point) {
        return detail::safe_io_awaiter_until{handle.make_append(data, size), time_point};
    }

    template <class Rep, class Period>
    inline auto safe_async_read_for(files::file_handle& handle, uint32_t size, std::chrono::duration<Rep, Period> timeout) {
        return detail::safe_io_awaiter_until{handle.make_read(size), std::chrono::high_resolution_clock::now() + timeout};
    }

    template <class Rep, class Period>
    inline auto safe_async_read_at_for(files::file_handle& handle, uint64_t offset, uint32_t size, std::chrono::duration<Rep, Period> timeout) {
        return detail::safe_io_awaiter_until{handle.make_read_at(offset, size), std::chrono::high_resolution_clock::now() + timeout};
    }

    template <class Rep, class Period>
    inline auto safe_async_read_fixed_for(files::file_handle& handle, uint32_t size, std::chrono::duration<Rep, Period> timeout) {
        return detail::safe_io_awaiter_until{handle.make_read_fixed(size), std::chrono::high_resolution_clock::now() + timeout};
    }

    template <class Rep, class Period>
    inline auto safe_async_read_fixed_at_for(files::file_handle& handle, uint64_t offset, uint32_t size, std::chrono::duration<Rep, Period> timeout) {
        return detail::safe_io_awaiter_until{handle.make_read_fixed_at(offset, size), std::chrono::high_resolution_clock::now() + timeout};
    }

    template <class Rep, class Period>
    inline auto safe_async_write_for(files::file_handle& handle, const uint8_t* data, uint32_t size, std::chrono::duration<Rep, Period> timeout) {
        return detail::safe_io_awaiter_until{handle.make_write(data, size), std::chrono::high_resolution_clock::now() + timeout};
    }

    template <class Rep, class Period>
    inline auto safe_async_write_at_for(files::file_handle& handle, uint64_t offset, const uint8_t* data, uint32_t size, std::chrono::duration<Rep, Period> timeout) {
        return detail::safe_io_awaiter_until{handle.make_write_at(offset, data, size), std::chrono::high_resolution_clock::now() + timeout};
    }

    template <class Rep, class Period>
    inline auto safe_async_append_for(files::file_handle& handle, const uint8_t* data, uint32_t size, std::chrono::duration<Rep, Period> timeout) {
        return detail::safe_io_awaiter_until{handle.make_append(data, size), std::chrono::high_resolution_clock::now() + timeout};
    }
}

#endif /* INCLUDE_COROUTINE_FILE */