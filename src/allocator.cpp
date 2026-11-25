#include <cstdlib>
#include <exception>
#include <fast_task/allocator.hpp>
#include <fast_task/interrupt.hpp>
#include <limits>
#include <malloc.h>
#include <new>
#include <tasks/util/interrupt.hpp>

namespace fast_task {
    void* allocate(std::size_t bytes) {
        interrupt_unsafe_region region;
        return std::malloc(bytes);
    }

    void free(void* p) {
        interrupt_unsafe_region region;
        std::free(p);
    }

    void* allocate_aligned(std::size_t bytes, std::size_t alignment) {
        if (alignment == 0 || (alignment & (alignment - 1)) != 0)
            return nullptr;
        interrupt_unsafe_region region;
#ifdef _WIN32
        return _aligned_malloc(bytes == 0 ? 1 : bytes, alignment);
#else
        if (bytes == 0)
            bytes = alignment;
        if (bytes > std::numeric_limits<std::size_t>::max() - (alignment - 1))
            return nullptr;
        const std::size_t rounded = (bytes + alignment - 1) & ~(alignment - 1);
        return std::aligned_alloc(alignment, rounded);
#endif
    }

    void free_aligned(void* p) {
        interrupt_unsafe_region region;
#ifdef _WIN32
        _aligned_free(p);
#else
        std::free(p);
#endif
    }
}

void* operator new(std::size_t n, fast_task::allocator_tag) noexcept(false) {
    fast_task::interrupt_unsafe_region region;
    void* p = std::malloc(n == 0 ? 1 : n);
    if (!p)
        throw std::bad_alloc();
    return p;
}

void operator delete(void* p, fast_task::allocator_tag) noexcept {
    fast_task::interrupt_unsafe_region region;
    std::free(p);
}

void* operator new[](std::size_t s, fast_task::allocator_tag) noexcept(false) {
    fast_task::interrupt_unsafe_region region;
    void* p = std::malloc(s == 0 ? 1 : s);
    if (!p)
        throw std::bad_alloc();
    return p;
}

void operator delete[](void* p, fast_task::allocator_tag) noexcept {
    fast_task::interrupt_unsafe_region region;
    std::free(p);
}

void* operator new(std::size_t n, std::align_val_t al, fast_task::allocator_tag) noexcept(false) {
    void* p = fast_task::allocate_aligned(n == 0 ? 1 : n, static_cast<std::size_t>(al));
    if (!p)
        throw std::bad_alloc();
    return p;
}

void operator delete(void* p, std::align_val_t, fast_task::allocator_tag) noexcept {
    fast_task::free_aligned(p);
}

void* operator new[](std::size_t s, std::align_val_t al, fast_task::allocator_tag) noexcept(false) {
    void* p = fast_task::allocate_aligned(s == 0 ? 1 : s, static_cast<std::size_t>(al));
    if (!p)
        throw std::bad_alloc();
    return p;
}

void operator delete[](void* p, std::align_val_t, fast_task::allocator_tag) noexcept {
    fast_task::free_aligned(p);
}