// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <atomic>
#include <boost/lockfree/queue.hpp>
#include <cassert>
#include <vector>

#include <tasks/_internal.hpp>
#include <tasks/util/light_stack.hpp>

namespace fast_task {
    typedef boost::context::stack_context stack_context;

    boost::lockfree::queue<light_stack::stack_context> stack_allocations(10000);
    std::atomic_size_t stack_allocations_buffer = 0;
    bool light_stack::flush_used_stacks = 0;
    size_t light_stack::max_buffer_size = 0;
}
#if PLATFORM_WINDOWS
    #include <Windows.h>
size_t page_size = []() {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return si.dwPageSize;
}();

namespace fast_task {
    stack_context create_stack(size_t size) {
        const size_t guard_page_size = page_size;

        void* vp = ::VirtualAlloc(0, size, MEM_RESERVE, PAGE_READWRITE);
        if (!vp)
            throw std::bad_alloc();

        // needs at least 3 pages to fully construct the coroutine and switch to it
        const auto init_commit_size = page_size * 3;
        auto pPtr = static_cast<PBYTE>(vp) + size;
        pPtr -= init_commit_size;
        if (!VirtualAlloc(pPtr, init_commit_size, MEM_COMMIT, PAGE_READWRITE)) {
            VirtualFree(vp, size, MEM_FREE);
            throw std::bad_alloc();
        }

        // create guard page so the OS can catch page faults and grow our stack
        pPtr -= guard_page_size;
        if (!VirtualAlloc(pPtr, guard_page_size, MEM_COMMIT, PAGE_READWRITE | PAGE_GUARD)) {
            VirtualFree(vp, size, MEM_FREE);
            throw std::bad_alloc();
        }
        stack_context sctx;
        sctx.size = size;
        sctx.sp = static_cast<char*>(vp) + sctx.size;
        return sctx;
    }

    light_stack::light_stack(size_t size) BOOST_NOEXCEPT_OR_NOTHROW : size(size) {}

    stack_context light_stack::allocate() {
        const size_t guard_page_size = page_size;
        const size_t pages = (size + guard_page_size + page_size - 1) / page_size;
        // add one page at bottom that will be used as guard-page
        const size_t size__ = (pages + 1) * page_size;

        stack_context result;
        if (stack_allocations.pop(result)) {
            stack_allocations_buffer--;
            if (!flush_used_stacks)
                return result;
            else {
                memset(static_cast<char*>(result.sp) - result.size, 0xCC, result.size);
                return result;
            }
        } else
            return create_stack(size__);
    }

    void unlimited_buffer(stack_context& sctx) {
        if (!stack_allocations.push(sctx))
            ::VirtualFree(static_cast<char*>(sctx.sp) - sctx.size, 0, MEM_RELEASE);
        else
            stack_allocations_buffer++;
    }

    void limited_buffer(stack_context& sctx) {
        if (++stack_allocations_buffer < light_stack::max_buffer_size) {
            if (!stack_allocations.push(sctx)) {
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

namespace fast_task {
    const size_t page_size = boost::context::stack_traits::page_size();
    const size_t guard_page_size = boost::context::stack_traits::page_size();

    stack_context create_stack(size_t size) {
        void* vp = mmap(nullptr, size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (!vp)
            throw std::bad_alloc();

        // needs at least 3 pages to fully construct the coroutine and switch to it
        const auto init_commit_size = page_size * 3;
        auto pPtr = static_cast<uint8_t*>(vp) + size;
        pPtr -= init_commit_size;
        if (mprotect(pPtr, init_commit_size, PROT_READ | PROT_WRITE) == -1) {
            munmap(vp, size);
            throw std::bad_alloc();
        }

        //PROT_NONE already used for guard page
        stack_context sctx;
        sctx.size = size;
        sctx.sp = static_cast<char*>(vp) + sctx.size;
        return sctx;
    }

    light_stack::light_stack(size_t size) BOOST_NOEXCEPT_OR_NOTHROW : size(size) {}

    stack_context light_stack::allocate() {
        const size_t pages = (size + guard_page_size + page_size - 1) / page_size;
        // add one page at bottom that will be used as guard-page
        const size_t size__ = (pages + 1) * page_size;

        stack_context result;
        if (stack_allocations.pop(result)) {
            stack_allocations_buffer--;
            if (!flush_used_stacks)
                return result;
            else {
                memset(static_cast<char*>(result.sp) - result.size, 0xCC, result.size);
                return result;
            }
        } else
            return create_stack(size__);
    }

    void unlimited_buffer(stack_context& sctx) {
        if (!stack_allocations.push(sctx))
            munmap(static_cast<char*>(sctx.sp) - sctx.size, sctx.size);
        else
            stack_allocations_buffer++;
    }

    void limited_buffer(stack_context& sctx) {
        if (++stack_allocations_buffer < light_stack::max_buffer_size) {
            if (!stack_allocations.push(sctx)) {
                munmap(static_cast<char*>(sctx.sp) - sctx.size, sctx.size);
                stack_allocations_buffer--;
            }
        } else {
            munmap(static_cast<char*>(sctx.sp) - sctx.size, sctx.size);
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
            munmap(static_cast<char*>(sctx.sp) - sctx.size, sctx.size);
    }
}

#else
    #error Unsupported platform
#endif