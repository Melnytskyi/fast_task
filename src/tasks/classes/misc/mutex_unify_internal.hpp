// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_MUTEX_UNIFY_INTERNAL
#define FAST_TASK_MUTEX_UNIFY_INTERNAL

#include <cstdint>

#include <fast_task/internal/task_object.hpp>
#include <fast_task/native/mutex.hpp>
#include <fast_task/task/mutex_unify.hpp>

namespace fast_task {
    struct mutex_unify_relock_access {
        static void* raw_ptr(const mutex_unify& m) noexcept {
            return reinterpret_cast<void*>(m.nmut);
        }

        static uint8_t raw_type(const mutex_unify& m) noexcept {
            return static_cast<uint8_t>(m.type);
        }

        static mutex_unify from_raw(void* ptr, uint8_t type) noexcept {
            mutex_unify m(nullptr);
            m.type = static_cast<mutex_unify::mutex_unify_type>(type);
            m.nmut = reinterpret_cast<fast_task::native::mutex*>(ptr);
            return m;
        }

        static mutex_unify from_task_object(task_object& obj) noexcept {
            mutex_unify m(nullptr);
            m.type = mutex_unify::mutex_unify_type::task_obj;
            m.nmut = reinterpret_cast<fast_task::native::mutex*>(&obj);
            return m;
        }
    };
}

#endif /* FAST_TASK_MUTEX_UNIFY_INTERNAL */
