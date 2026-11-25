// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef LIBRARY_FAST_TASK_INCLUDE_ALLOCATOR
#define LIBRARY_FAST_TASK_INCLUDE_ALLOCATOR
#include "shared.hpp"
#include <cstddef>
#include <cstdint>
#include <limits>
#include <new>
#include <type_traits>

namespace fast_task {
    struct FT_API allocator_tag {};

    static constexpr inline allocator_tag at{};

    FT_API void* allocate(std::size_t bytes);
    FT_API void free(void* p);
    FT_API void* allocate_aligned(std::size_t bytes, std::size_t alignment);
    FT_API void free_aligned(void* p);

    template <class T>
    struct allocator {
        using value_type = T;
        using size_type = std::size_t;
        using difference_type = std::ptrdiff_t;
        using is_always_equal = std::true_type;

        using propagate_on_container_copy_assignment = std::false_type;
        using propagate_on_container_move_assignment = std::false_type;
        using propagate_on_container_swap = std::false_type;

        allocator() noexcept = default;
        template <class U>
        allocator(const allocator<U>&) noexcept {}

        [[nodiscard]] T* allocate(size_type n) {
            if (n > std::numeric_limits<size_type>::max() / sizeof(T))
                throw std::bad_array_new_length();
            const std::size_t bytes = n == 0 ? 1 : n * sizeof(T);
            void* p = nullptr;
            if constexpr (alignof(T) > alignof(std::max_align_t))
                p = fast_task::allocate_aligned(bytes, alignof(T));
            else
                p = fast_task::allocate(bytes);
            if (!p)
                throw std::bad_alloc();
            return static_cast<T*>(p);
        }

        void deallocate(T* p, size_type) noexcept {
            if constexpr (alignof(T) > alignof(std::max_align_t))
                fast_task::free_aligned(p);
            else
                fast_task::free(p);
        }
    };

    template <class T, class U>
    bool operator==(const allocator<T>&, const allocator<U>&) noexcept {
        return true;
    }

    template <class T, class U>
    bool operator!=(const allocator<T>&, const allocator<U>&) noexcept {
        return false;
    }
}

FT_API void* operator new(std::size_t n, fast_task::allocator_tag) noexcept(false);
FT_API void operator delete(void* p, fast_task::allocator_tag) noexcept;
FT_API void* operator new[](std::size_t s, fast_task::allocator_tag) noexcept(false);
FT_API void operator delete[](void* p, fast_task::allocator_tag) noexcept;
FT_API void* operator new(std::size_t n, std::align_val_t al, fast_task::allocator_tag) noexcept(false);
FT_API void operator delete(void* p, std::align_val_t al, fast_task::allocator_tag) noexcept;
FT_API void* operator new[](std::size_t s, std::align_val_t al, fast_task::allocator_tag) noexcept(false);
FT_API void operator delete[](void* p, std::align_val_t al, fast_task::allocator_tag) noexcept;

#endif /* LIBRARY_FAST_TASK_INCLUDE_ALLOCATOR */
