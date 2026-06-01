// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <algorithm>
#include <atomic>
#include <cassert>
#include <concurrentqueue/moodycamel/concurrentqueue.h>
#include <string.h>
#include <vector>

#include <tasks/_internal.hpp>
#include <tasks/util/light_stack.hpp>

namespace fast_task {
    typedef boost::context::stack_context stack_context;

    moodycamel::ConcurrentQueue<light_stack::stack_context> stack_allocations(10000);
    std::atomic_size_t stack_allocations_buffer = 0;
    bool light_stack::flush_used_stacks = 0;
    size_t light_stack::max_buffer_size = 0;
}
#if PLATFORM_WINDOWS
    #define WIN32_LEAN_AND_MEAN
    #define NOMINMAX
    #include <Windows.h>

    #ifndef FT_GUARD_PAGE_COUNT
        #define FT_GUARD_PAGE_COUNT 1
    #endif

size_t page_size = []() {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return si.dwPageSize;
}();

namespace fast_task {
    stack_context create_stack(size_t size) {
        const size_t guard_page_size = page_size * FT_GUARD_PAGE_COUNT;

        void* vp = ::VirtualAlloc(0, size, MEM_RESERVE, PAGE_READWRITE);
        if (!vp)
            throw std::bad_alloc();

        const auto init_commit_size = page_size * 3;
        auto pPtr = static_cast<PBYTE>(vp) + size;
        pPtr -= init_commit_size;
        if (!VirtualAlloc(pPtr, init_commit_size, MEM_COMMIT, PAGE_READWRITE)) {
            VirtualFree(vp, size, MEM_FREE);
            throw std::bad_alloc();
        }

    #if FT_GUARD_PAGE_COUNT > 0
        pPtr -= guard_page_size;
        if (!VirtualAlloc(pPtr, guard_page_size, MEM_COMMIT, PAGE_READWRITE | PAGE_GUARD)) {
            VirtualFree(vp, size, MEM_FREE);
            throw std::bad_alloc();
        }
    #endif

        stack_context sctx;
        sctx.size = size;
        sctx.sp = static_cast<char*>(vp) + sctx.size;
        return sctx;
    }

    light_stack::light_stack(size_t size) BOOST_NOEXCEPT_OR_NOTHROW : size(size) {}

    stack_context light_stack::allocate() {
        const size_t guard_page_size = page_size * FT_GUARD_PAGE_COUNT;
        const size_t size__ = ((size + guard_page_size + page_size - 1) / page_size) * page_size;

        stack_context result;
        if (stack_allocations.try_dequeue(result)) {
            stack_allocations_buffer--;
            if (!flush_used_stacks)
                return result;
            else {
                auto* stack_base = static_cast<char*>(result.sp) - result.size;
                const size_t clear_offset = std::min(guard_page_size, result.size);
                if (clear_offset < result.size)
                    memset(stack_base + clear_offset, 0xCC, result.size - clear_offset);
                return result;
            }
        } else
            return create_stack(size__);
    }

    void unlimited_buffer(stack_context& sctx) {
        if (!stack_allocations.enqueue(sctx))
            ::VirtualFree(static_cast<char*>(sctx.sp) - sctx.size, 0, MEM_RELEASE);
        else
            stack_allocations_buffer++;
    }

    void limited_buffer(stack_context& sctx) {
        if (++stack_allocations_buffer < light_stack::max_buffer_size) {
            if (!stack_allocations.enqueue(sctx)) {
                ::VirtualFree(static_cast<char*>(sctx.sp) - sctx.size, 0, MEM_RELEASE);
                stack_allocations_buffer--;
            }
        } else {
            ::VirtualFree(static_cast<char*>(sctx.sp) - sctx.size, 0, MEM_RELEASE);
            stack_allocations_buffer--;
        }
    }

    void light_stack::deallocate(stack_context& sctx) {
        assert(sctx.sp);
        if (!max_buffer_size)
            unlimited_buffer(sctx);
        else if (max_buffer_size != SIZE_MAX)
            limited_buffer(sctx);
        else
            ::VirtualFree(static_cast<char*>(sctx.sp) - sctx.size, 0, MEM_RELEASE);
    }
}
#elif PLATFORM_LINUX
    #include <sys/mman.h>
    #include <sys/stat.h>
    #include <unistd.h>
    #include <valgrind/memcheck.h>
    #include <valgrind/valgrind.h>

    #ifndef FT_GUARD_PAGE_COUNT
        #define FT_GUARD_PAGE_COUNT 1
    #endif

namespace fast_task {
    static const size_t page_size = boost::context::stack_traits::page_size();
    static const size_t guard_page_size = page_size * FT_GUARD_PAGE_COUNT;

    stack_context create_stack(size_t size) {
        size_t total_size = std::max(size, page_size * 3);
        void* vp = mmap(nullptr, total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (vp == MAP_FAILED)
            throw std::bad_alloc();

    #if FT_GUARD_PAGE_COUNT > 0
        if (mprotect(vp, guard_page_size, PROT_NONE) == -1) {
            munmap(vp, total_size);
            throw std::bad_alloc();
        }
    #endif

        if (RUNNING_ON_VALGRIND) {
            [[maybe_unused]] void* stack_bottom = static_cast<uint8_t*>(vp) + guard_page_size;
            [[maybe_unused]] void* stack_top = static_cast<uint8_t*>(vp) + total_size;
            get_execution_data(get_loc().curr_task).valgrind_stack_id = VALGRIND_STACK_REGISTER(stack_bottom, stack_top);
        }

        stack_context sctx;
        sctx.size = size;
        sctx.sp = static_cast<char*>(vp) + sctx.size;
        return sctx;
    }

    void destroy_stack(stack_context& sctx) {
        if (!sctx.sp)
            return;

        if (RUNNING_ON_VALGRIND)
            VALGRIND_STACK_DEREGISTER(get_execution_data(get_loc().curr_task).valgrind_stack_id);

        munmap(static_cast<char*>(sctx.sp) - sctx.size, sctx.size);
        sctx.sp = nullptr;
        sctx.size = 0;
    }

    light_stack::light_stack(size_t size) BOOST_NOEXCEPT_OR_NOTHROW : size(size) {}

    stack_context light_stack::allocate() {
        const size_t size__ = ((size + guard_page_size + page_size - 1) / page_size) * page_size;

        stack_context result;
        if (stack_allocations.try_dequeue(result)) {
            stack_allocations_buffer--;
            if (!flush_used_stacks)
                return result;
            else {
                auto* stack_base = static_cast<char*>(result.sp) - result.size;
                const size_t clear_offset = std::min(guard_page_size, result.size);
                if (clear_offset < result.size)
                    memset(stack_base + clear_offset, 0xCC, result.size - clear_offset);
                return result;
            }
        } else
            return create_stack(size__);
    }

    void unlimited_buffer(stack_context& sctx) {
        if (!stack_allocations.enqueue(sctx))
            destroy_stack(sctx);
        else
            stack_allocations_buffer++;
    }

    void limited_buffer(stack_context& sctx) {
        if (++stack_allocations_buffer < light_stack::max_buffer_size) {
            if (!stack_allocations.enqueue(sctx)) {
                destroy_stack(sctx);
                stack_allocations_buffer--;
            }
        } else {
            destroy_stack(sctx);
            stack_allocations_buffer--;
        }
    }

    void light_stack::deallocate(stack_context& sctx) {
        assert(sctx.sp);
        if (!max_buffer_size)
            unlimited_buffer(sctx);
        else if (max_buffer_size != SIZE_MAX)
            limited_buffer(sctx);
        else
            destroy_stack(sctx);
    }
}

#else
    #error Unsupported platform
#endif
