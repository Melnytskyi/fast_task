#include <allocator.hpp>
#include <exception>
#include <malloc.h>
#include <tasks/util/interrupt.hpp>

namespace fast_task {
    void* allocate(size_t bytes) {
        interrupt::interrupt_unsafe_region region;
        void* ptr = malloc(bytes);
        if (ptr == nullptr)
            throw std::bad_alloc();
        return ptr;
    }

    void free(void* p) {
        interrupt::interrupt_unsafe_region region;
        ::free(p);
    }
}

void* operator new(std::size_t n, fast_task::allocator_tag) noexcept(false) {
    fast_task::interrupt::interrupt_unsafe_region region;
    void* ptr = malloc(n);
    if (ptr == nullptr)
        throw std::bad_alloc();
    return ptr;
}

void operator delete(void* p, fast_task::allocator_tag) noexcept {
    fast_task::interrupt::interrupt_unsafe_region region;
    free(p);
}

void* operator new[](std::size_t s, fast_task::allocator_tag) noexcept(false) {
    fast_task::interrupt::interrupt_unsafe_region region;
    void* ptr = malloc(s);
    if (ptr == nullptr)
        throw std::bad_alloc();
    return ptr;
}

void operator delete[](void* p, fast_task::allocator_tag) noexcept {
    fast_task::interrupt::interrupt_unsafe_region region;
    free(p);
}