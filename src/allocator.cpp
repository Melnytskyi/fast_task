#include <allocator.hpp>
#include <exception>
#include <interput.hpp>
#include <malloc.h>
#include <tasks/util/interrupt.hpp>

namespace fast_task {
    void* allocate(std::size_t bytes) {
        interrupt_unsafe_region region;
        return malloc(bytes);
    }

    void free(void* p) {
        interrupt_unsafe_region region;
        ::free(p);
    }
}

void* operator new(std::size_t n, fast_task::allocator_tag) noexcept(false) {
    fast_task::interrupt_unsafe_region region;
    return malloc(n);
}

void operator delete(void* p, fast_task::allocator_tag) noexcept {
    fast_task::interrupt_unsafe_region region;
    free(p);
}

void* operator new[](std::size_t s, fast_task::allocator_tag) noexcept(false) {
    fast_task::interrupt_unsafe_region region;
    return malloc(s);
}

void operator delete[](void* p, fast_task::allocator_tag) noexcept {
    fast_task::interrupt_unsafe_region region;
    free(p);
}