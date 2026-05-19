// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef INCLUDE_COROUTINE_FILE
#define INCLUDE_COROUTINE_FILE
#include "../files.hpp"
#include "core.hpp"

namespace fast_task {
    // co_await-able wrappers around file_handle make_* methods.
    // Each function returns a future_ptr<T> that can be used with co_await.

    [[nodiscard]] inline auto async_read(files::file_handle& f, uint32_t size) {
        return f.make_read(size);
    }

    [[nodiscard]] inline auto async_read_at(files::file_handle& f, uint64_t offset, uint32_t size) {
        return f.make_read_at(offset, size);
    }

    [[nodiscard]] inline auto async_read_fixed(files::file_handle& f, uint32_t size) {
        return f.make_read_fixed(size);
    }

    [[nodiscard]] inline auto async_read_fixed_at(files::file_handle& f, uint64_t offset, uint32_t size) {
        return f.make_read_fixed_at(offset, size);
    }

    [[nodiscard]] inline auto async_write(files::file_handle& f, const uint8_t* data, uint32_t size) {
        return f.make_write(data, size);
    }

    [[nodiscard]] inline auto async_write_at(files::file_handle& f, uint64_t offset, const uint8_t* data, uint32_t size) {
        return f.make_write_at(offset, data, size);
    }

    [[nodiscard]] inline auto async_append(files::file_handle& f, const uint8_t* data, uint32_t size) {
        return f.make_append(data, size);
    }
}

#endif /* INCLUDE_COROUTINE_FILE */
