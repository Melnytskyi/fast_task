// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef LIBRARY_FAST_TASK_INCLUDE_ALLOCATOR
#define LIBRARY_FAST_TASK_INCLUDE_ALLOCATOR
#include "shared.hpp"
#include <cstdint>
#include <type_traits>

namespace fast_task {
    struct FT_API allocator_tag {};

    static constexpr inline allocator_tag at{};

    FT_API void* allocate(size_t bytes);
    FT_API void free(void* p);

    template <class T>
    struct allocator {
        using value_type = T;
        using size_type = std::size_t;
        using difference_type = std::ptrdiff_t;
        using is_always_equal = std::true_type;

        using propagate_on_container_copy_assignment = std::false_type;
        using propagate_on_container_move_assignment = std::false_type;
        using propagate_on_container_copy_assignment = std::false_type;
        using propagate_on_container_swap = std::false_type;

        allocator() noexcept = default;
        template <class U>
        allocator(const allocator<U>&) noexcept {}

        [[nodiscard]] T* allocate(size_type n) {
            return (T*)fast_task::allocate(n * sizeof(T));
        }

        [[nodiscard]] T* deallocate(T* p, size_type n) {
            return fast_task::free(p);
        }
    };
}

template <class T, class U>
bool operator==(const fast_task::allocator<T>&, const fast_task::allocator<U>&) {
    return true;
}

template <class T, class U>
bool operator!=(const fast_task::allocator<T>&, const fast_task::allocator<U>&) {
    return false;
}

FT_API void* operator new(std::size_t n, fast_task::allocator_tag) noexcept(false);
FT_API void operator delete(void* p, fast_task::allocator_tag) noexcept;
FT_API void* operator new[](std::size_t s, fast_task::allocator_tag) noexcept(false);
FT_API void operator delete[](void* p, fast_task::allocator_tag) noexcept;

#endif /* LIBRARY_FAST_TASK_INCLUDE_ALLOCATOR */
