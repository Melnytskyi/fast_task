// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <tasks/util/os_alloc.hpp>
#include <tasks/util/macro.hpp>

#if PLATFORM_LINUX
    #include <sys/mman.h>
    #include <unistd.h>
#elif PLATFORM_WINDOWS
    #define NOMINMAX
    #include <Windows.h>
#endif
namespace fast_task {
    void* os_alloc(std::uintptr_t size) noexcept {
#if PLATFORM_LINUX
        void* ptr = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        return (ptr == MAP_FAILED) ? nullptr : ptr;
#elif PLATFORM_WINDOWS
        return VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
#else
        return nullptr;
#endif
    }

    void os_free(void* ptr, std::uintptr_t size) noexcept {
        if (!ptr)
            return;
#if PLATFORM_LINUX
        munmap(ptr, size);
#elif PLATFORM_WINDOWS
        (void)size;
        VirtualFree(ptr, 0, MEM_RELEASE);
#endif
    }
}