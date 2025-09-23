// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <algorithm>
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
    #include <signal.h>
    #include <sys/mman.h>
    #include <sys/stat.h>
    #include <unistd.h>
    #include <valgrind/memcheck.h>
    #include <valgrind/valgrind.h>

namespace fast_task {
    static const size_t page_size = boost::context::stack_traits::page_size();
    static const size_t guard_page_size = boost::context::stack_traits::page_size();

    //void stack_growth_handler(int sig, siginfo_t* si, void* ucontext);
    //
    //static thread_local struct old___ {
    //    struct sigaction handler;
    //    stack_t stack;
    //    bool is_init = false;
    //
    //    void init() {
    //        if (is_init)
    //            return;
    //        is_init = true;
    //        stack_t ss;
    //        ss.ss_sp = mmap(nullptr, SIGSTKSZ, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    //        ss.ss_size = SIGSTKSZ;
    //        ss.ss_flags = 0;
    //        if (sigaltstack(&ss, &stack) == -1) {
    //            perror("sigaltstack");
    //            exit(EXIT_FAILURE);
    //        }
    //        struct sigaction sa;
    //        sigemptyset(&sa.sa_mask);
    //        sa.sa_sigaction = stack_growth_handler;
    //        sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    //        if (sigaction(SIGSEGV, &sa, &handler) == -1) {
    //            perror("sigaction");
    //            exit(EXIT_FAILURE);
    //        }
    //    }
    //
    //    ~old___() {
    //        if (sigaltstack(&stack, &stack) == -1)
    //            perror("sigaltstack");
    //        if (munmap(static_cast<char*>(stack.ss_sp), SIGSTKSZ) == -1)
    //            perror("munmap");
    //        if (sigaction(SIGSEGV, &handler, NULL) == -1)
    //            perror("sigaction failed in library destructor");
    //    }
    //} old_data;
    //
    //void pass_handler(int sig, siginfo_t* si, void* ucontext) {
    //    if (old_data.handler.sa_flags & SA_SIGINFO)
    //        old_data.handler.sa_sigaction(sig, si, ucontext);
    //    else if (old_data.handler.sa_handler == SIG_DFL) {
    //        signal(sig, SIG_DFL);
    //        raise(sig);
    //    } else if (old_data.handler.sa_handler != SIG_IGN)
    //        old_data.handler.sa_handler(sig);
    //}
    //
    //void stack_growth_handler(int sig, siginfo_t* si, void* ucontext) {
    //    if (!loc.curr_task) { //definitely not ours stack
    //        pass_handler(sig, si, ucontext);
    //        return;
    //    } else if (!get_data(loc.curr_task).data) { //avoid alloc
    //        pass_handler(sig, si, ucontext);
    //        return;
    //    }
    //
    //    void* fault_addr = si->si_addr;
    //    void* stack_start = get_execution_data(loc.curr_task).stack_ptr;
    //    void* stack_end = static_cast<char*>(stack_start) + get_execution_data(loc.curr_task).stack_size;
    //
    //    if (fault_addr >= stack_start && fault_addr < stack_end) {
    //        void* page_start = (void*)((uintptr_t)fault_addr & ~(page_size - 1));
    //        if (mprotect(page_start, page_size, PROT_READ | PROT_WRITE) == -1) {
    //            if (is_debugger_attached()) {
    //                pass_handler(sig, si, ucontext);
    //                return;
    //            }
    //            psignal(sig, "mprotect failed in signal handler");
    //            _exit(EXIT_FAILURE);
    //        }
    //        if (RUNNING_ON_VALGRIND)
    //            VALGRIND_MAKE_MEM_DEFINED(page_start, page_size);
    //        return;
    //    } else
    //        pass_handler(sig, si, ucontext);
    //}

    void __install_signal_handler_mem() {
        //old_data.init();
    }

    //TODO create proper guard page
    stack_context create_stack(size_t size) {
        size_t total_size = std::max(size, page_size * 3);
        void* vp = mmap(nullptr, total_size, /*PROT_NONE*/ PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (!vp)
            throw std::bad_alloc();

        // needs at least 3 pages to fully construct the coroutine and switch to it
        //const auto init_commit_size = page_size * 3;
        //auto commit_start = static_cast<uint8_t*>(vp) + total_size - init_commit_size;
        //if (mprotect(commit_start, init_commit_size, PROT_READ | PROT_WRITE) == -1) {
        //    munmap(vp, total_size);
        //    throw std::bad_alloc();
        //}
        if (RUNNING_ON_VALGRIND) {
            void* stack_bottom = vp;
            void* stack_top = static_cast<uint8_t*>(vp) + total_size;
            get_execution_data(loc.curr_task).valgrind_stack_id = VALGRIND_STACK_REGISTER(stack_bottom, stack_top);
        }

        //PROT_NONE already used for guard page
        stack_context sctx;
        sctx.size = size;
        sctx.sp = static_cast<char*>(vp) + sctx.size;
        return sctx;
    }

    void destroy_stack(stack_context& sctx) {
        if (!sctx.sp)
            return;

        if (RUNNING_ON_VALGRIND)
            VALGRIND_STACK_DEREGISTER(get_execution_data(loc.curr_task).valgrind_stack_id);

        munmap(static_cast<char*>(sctx.sp) - sctx.size, sctx.size);
        sctx.sp = nullptr;
        sctx.size = 0;
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
            destroy_stack(sctx);
        else
            stack_allocations_buffer++;
    }

    void limited_buffer(stack_context& sctx) {
        if (++stack_allocations_buffer < light_stack::max_buffer_size) {
            if (!stack_allocations.push(sctx)) {
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